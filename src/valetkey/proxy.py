# SPDX-License-Identifier: Apache-2.0
"""The allowlisting proxy: the only way out of a browser's network namespace.

The browser reaches this proxy through a bridge to one Unix socket. The proxy speaks the HTTP
forward-proxy protocol and handles two kinds of request:

* ``CONNECT host:443`` (HTTPS and secure WebSockets). It answers ``200 Connection Established``
  and then copies bytes both ways. It never decrypts anything.
* ``GET http://host/path HTTP/1.1`` and the other common methods (plain HTTP on port 80). The
  request line is rewritten to origin form and the request is forwarded, then bytes are copied.
  The ``Host`` header is replaced with the host of the URL, and ``Connection`` and ``Proxy-*``
  headers are dropped in favour of ``Connection: close``, so one connection never carries
  requests for two hosts. Every other header passes through untouched.

Anything else is answered with 400 or 405 and the connection is closed.

Each connection goes through four checks, in this order:

1. The port: 443 for ``CONNECT``, 80 for plain HTTP. Anything else is refused.
2. The host, in :attr:`Mode.ENFORCE`: it must be allowed by the site's
   :class:`~valetkey.sites.Policy`. In :attr:`Mode.RECORD` every host passes this check and is
   noted in :meth:`Proxy.seen_hosts`.
3. The address: the proxy resolves the host itself and connects only to public addresses. A name
   that resolves to loopback, private, link-local or other non-public addresses is refused, which
   stops DNS rebinding from reaching services on the local machine or network. IP literals get
   the same check. Every address the name resolves to must pass, because a rebinding answer
   often mixes public and private ones, and the proxy connects only to an address that passed.
   The one exception is a site's ``private_networks``: a private address inside a range the
   person listed passes, for that site only. Loopback, link-local, multicast, unspecified and
   reserved addresses and the cloud metadata services (``sites.NEVER_ALLOWED_ADDRESSES``) are
   refused whatever is listed.
4. The connection to the upstream server.

Refusals are answered with ``403 Forbidden`` and recorded. What gets recorded is the host, the
port and a short reason, and never a path, a query string, a header or a body, because on a
logged-in site those carry credentials. The proxy writes nothing to stdout.
"""

import asyncio
import contextlib
import ipaddress
import logging
import socket
from collections import deque
from dataclasses import dataclass
from enum import StrEnum
from http import HTTPStatus
from typing import TYPE_CHECKING, NoReturn, cast
from urllib.parse import urlsplit

from valetkey import sites

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Awaitable, Callable, Iterable
    from pathlib import Path
    from typing import Self
    from urllib.parse import SplitResult

logger = logging.getLogger(__name__)

MAX_HEAD_BYTES = 16 * 1024
HEAD_TIMEOUT = 10.0
CONNECT_TIMEOUT = 10.0
MAX_REFUSALS = 1000
MAX_SEEN_HOSTS = 5000
CONNECT_PORT = 443
HTTP_PORT = 80
_CHUNK = 64 * 1024
_PLAIN_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"})
_DROPPED_HEADERS = frozenset({b"host", b"connection", b"proxy-connection", b"keep-alive"})
PRIVATE_ADDRESS = "resolves to a private address"
"""The reason given for an address the proxy will not connect to."""
NOT_ALLOWED = "not in the allow list"
"""The reason a host is refused when the policy does not allow it."""

type Streams = tuple[asyncio.StreamReader, asyncio.StreamWriter]
type Resolver = Callable[[str, int], Awaitable[list[str]]]
type Connector = Callable[[str, int], Awaitable[Streams]]
type AddressCheck = Callable[[str], str | None]


class Mode(StrEnum):
    """How the proxy treats hosts."""

    ENFORCE = "enforce"
    RECORD = "record"


@dataclass(frozen=True, slots=True)
class Refusal:
    """A connection the proxy refused.

    ``seq`` counts refusals from 1 and never repeats. ``host`` is normalized and ``reason`` is a
    short fixed phrase. Nothing else about the request is kept.
    """

    seq: int
    host: str
    port: int
    reason: str


@dataclass(frozen=True, slots=True)
class SeenHost:
    """A host a connection was made to in record mode, and how many connections that took."""

    host: str
    connections: int


@dataclass(frozen=True, slots=True)
class Request:
    """The parts of a proxy request the proxy acts on.

    ``path`` is the origin-form target (``/a?b=1``) for plain HTTP and empty for ``CONNECT``.
    ``headers`` are the raw header lines, without line endings.
    """

    method: str
    host: str
    port: int
    path: str
    headers: tuple[bytes, ...]


class RequestError(Exception):
    """A request the proxy answers with an error status instead of serving."""

    def __init__(self, status: HTTPStatus, message: str) -> None:
        """Keep the status and the short text sent as the response body."""
        super().__init__(message)
        self.status = status
        self.message = message


# -- decisions: small pure functions ---------------------------------------------------------


def parse_request(head: bytes) -> Request:
    """Parse a request head (everything before the blank line) into a :class:`Request`.

    Raises:
        RequestError: with status 400 for anything malformed or not a proxy request (an
            origin-form target, a scheme other than HTTP, credentials in the URL, a bad host),
            and 405 for a method the proxy does not forward.

    """
    try:
        text = head.decode("ascii")
    except UnicodeDecodeError:
        _bad("request is not ASCII")
    request_line, *header_lines = text.split("\r\n")
    parts = request_line.split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):  # noqa: PLR2004 - method target version
        _bad("malformed request line")
    method, target, _version = parts
    if not (method.isalpha() and method.isupper()):
        _bad("malformed method")
    if any(ord(char) < 0x21 or ord(char) == 0x7F or char == "\\" for char in target):  # noqa: PLR2004
        _bad("malformed request target")
    headers = _header_lines(header_lines)
    if method == "CONNECT":
        parsed = _split(f"//{target}")
        host, port = _endpoint(parsed)
        if port is None or parsed.path or parsed.query or parsed.fragment:
            _bad("CONNECT needs host:port")
        return Request(method, host, port, "", headers)
    if method not in _PLAIN_METHODS:
        msg = f"method {method} is not supported"
        raise RequestError(HTTPStatus.METHOD_NOT_ALLOWED, msg)
    if not target.startswith("http://"):
        _bad("a proxy request needs an absolute http:// URL (use CONNECT for https)")
    parsed = _split(target)
    host, port = _endpoint(parsed)
    path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
    return Request(method, host, HTTP_PORT if port is None else port, path, headers)


def _bad(message: str) -> NoReturn:
    raise RequestError(HTTPStatus.BAD_REQUEST, message)


def _split(target: str) -> SplitResult:
    try:
        return urlsplit(target)
    except ValueError:
        _bad("malformed request target")


def _endpoint(parsed: SplitResult) -> tuple[str, int | None]:
    """Return the normalized host and the port (or ``None``) of a parsed target."""
    try:
        host = sites.normalize_host(parsed.hostname or "")
        port = parsed.port
    except ValueError:
        _bad("malformed host or port")
    if "@" in parsed.netloc or "%" in host or not sites.is_plausible_host(host):
        _bad("malformed host")
    return host, port


def _header_lines(lines: list[str]) -> tuple[bytes, ...]:
    for line in lines:
        name, colon, _value = line.partition(":")
        if not colon or not name or name != name.strip() or any(c in line for c in "\0\n\r"):
            _bad("malformed header")
    return tuple(line.encode("ascii") for line in lines)


def upstream_head(request: Request) -> bytes:
    """Build the head sent to the origin server for a plain HTTP request.

    The request line becomes origin form with ``HTTP/1.1``. ``Host`` is set from the URL, and
    ``Connection``, ``Proxy-Connection`` and ``Keep-Alive`` are replaced by ``Connection: close``.
    Other headers are kept as they came, in order.
    """
    host = f"[{request.host}]" if ":" in request.host else request.host
    kept = [
        line for line in request.headers if line.partition(b":")[0].lower() not in _DROPPED_HEADERS
    ]
    kept = [line for line in kept if not line.lower().startswith(b"proxy-")]
    lines = [
        f"{request.method} {request.path} HTTP/1.1".encode("ascii"),
        f"Host: {host}".encode("ascii"),
    ]
    return b"\r\n".join([*lines, *kept, b"Connection: close"]) + b"\r\n\r\n"


def port_refusal(request: Request) -> str | None:
    """Return why the port is refused, or ``None``: 443 for ``CONNECT``, 80 for plain HTTP."""
    allowed = CONNECT_PORT if request.method == "CONNECT" else HTTP_PORT
    if request.port == allowed:
        return None
    return f"port {request.port} is not allowed (only {allowed})"


def policy_refusal(policy: sites.Policy, mode: Mode, host: str) -> str | None:
    """Return why ``host`` is refused, or ``None``. Record mode refuses nothing."""
    if mode is Mode.RECORD or sites.allows(policy, host):
        return None
    return NOT_ALLOWED


def address_refusal(address: str) -> str | None:
    """Return why ``address`` may not be connected to, or ``None`` when it is public.

    Refused: anything that is not an IP address, and loopback, private, link-local, unspecified,
    multicast, reserved and other non-global addresses. An IPv4-mapped IPv6 address is judged by
    the IPv4 address inside it.
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return PRIVATE_ADDRESS
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    blocked = (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_reserved
        or not ip.is_global
    )
    return PRIVATE_ADDRESS if blocked else None


def private_address_allowed(address: str, networks: Iterable[str]) -> bool:
    """Tell whether ``address`` is private but inside one of the site's listed ``networks``.

    Never true for loopback, link-local, multicast, unspecified or reserved addresses, nor for
    ``sites.NEVER_ALLOWED_ADDRESSES``, whatever is listed. An IPv4-mapped IPv6 address is judged
    by the IPv4 address inside it, so a mapped form cannot slip past a range written for IPv4.
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
        or ip in sites.NEVER_ALLOWED_ADDRESSES
    ):
        return False
    return any(
        ip.version == network.version and ip in network
        for network in map(ipaddress.ip_network, networks)
    )


async def system_resolver(host: str, port: int) -> list[str]:
    """Resolve ``host`` with the system resolver and return its addresses, in order, once each."""
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


# -- the proxy -------------------------------------------------------------------------------


class Proxy:
    """An allowlisting HTTP proxy for one site, listening on one Unix socket.

    ``policy`` is the site's policy; replace it later with :meth:`update_policy`. ``mode`` is
    :attr:`Mode.ENFORCE`, which refuses hosts the policy does not allow, or :attr:`Mode.RECORD`,
    which lets every host through and notes it in :meth:`seen_hosts`.

    The keyword arguments tune or replace the parts that touch the network:

    * ``resolver`` turns a host name into addresses (default: the system resolver).
    * ``connector`` opens a connection to ``(address, port)`` (default:
      :func:`asyncio.open_connection`).
    * ``address_check`` returns a reason to refuse an address, or ``None`` (default:
      :func:`address_refusal`). Tests replace the resolver, connector and check together to reach
      a local server; nothing else should.
    * ``head_timeout`` and ``connect_timeout`` are seconds to receive a request head and to
      connect to one upstream address.
    * ``max_refusals`` is how many refusals :meth:`refused_since` can still return. Older ones are
      dropped, and their numbers are not reused.
    * ``max_seen_hosts`` is how many distinct hosts record mode keeps. Further new hosts are
      ignored.
    * ``quiet_hosts`` are hosts the browser contacts on its own, such as its updater. They are
      matched exactly. A refusal for one is answered with 403 as usual but not reported by
      :meth:`refused_since`. They are counted in :attr:`quiet_refusals` and kept in their own
      history, :meth:`quiet_refused_since`, for a caller that wants to say so quietly. In record
      mode they are not noted in :meth:`seen_hosts`.
    """

    def __init__(  # noqa: PLR0913 - every knob is a keyword the tests turn
        self,
        policy: sites.Policy,
        mode: Mode = Mode.ENFORCE,
        *,
        resolver: Resolver = system_resolver,
        connector: Connector = asyncio.open_connection,
        address_check: AddressCheck = address_refusal,
        head_timeout: float = HEAD_TIMEOUT,
        connect_timeout: float = CONNECT_TIMEOUT,
        max_refusals: int = MAX_REFUSALS,
        max_seen_hosts: int = MAX_SEEN_HOSTS,
        quiet_hosts: frozenset[str] = frozenset(),
    ) -> None:
        """Create a proxy. Nothing listens until :meth:`start`."""
        self._policy = policy
        self._mode = mode
        self._resolver = resolver
        self._connector = connector
        self._address_check = address_check
        self._head_timeout = head_timeout
        self._connect_timeout = connect_timeout
        self._max_seen_hosts = max_seen_hosts
        self._quiet = frozenset(sites.normalize_host(host) for host in quiet_hosts)
        self._quiet_refused = 0
        self._quiet_history: deque[Refusal] = deque(maxlen=max_refusals)
        self._refusals: deque[Refusal] = deque(maxlen=max_refusals)
        self._seq = 0
        self._seen: dict[str, int] = {}
        self._listening: tuple[asyncio.Server, Path] | None = None
        self._tasks: set[asyncio.Task[None]] = set()

    @property
    def mode(self) -> Mode:
        """The mode the proxy runs in."""
        return self._mode

    @property
    def policy(self) -> sites.Policy:
        """The policy new connections are checked against."""
        return self._policy

    @property
    def quiet_refusals(self) -> int:
        """How many refusals of ``quiet_hosts`` there have been. They are not in the history."""
        return self._quiet_refused

    def quiet_refused_since(self, cursor: int = 0) -> tuple[list[Refusal], int]:
        """Return the refusals of ``quiet_hosts`` after ``cursor`` and the cursor for next time.

        Works like :meth:`refused_since`, with a numbering of its own. These refusals never
        appear in :meth:`refused_since`.
        """
        return [r for r in self._quiet_history if r.seq > cursor], self._quiet_refused

    def update_policy(self, policy: sites.Policy) -> None:
        """Use ``policy`` for connections that start from now on. Open tunnels are untouched."""
        self._policy = policy

    def refused_since(self, cursor: int = 0) -> tuple[list[Refusal], int]:
        """Return the refusals after ``cursor`` and the cursor to pass next time.

        Start with 0. The new cursor is the number of the latest refusal, so it only grows, and
        asking again with it returns only what is new. Only the last ``max_refusals`` are kept.
        """
        return [refusal for refusal in self._refusals if refusal.seq > cursor], self._seq

    def seen_hosts(self) -> list[SeenHost]:
        """Return the hosts connected to in record mode, in the order first seen."""
        return [SeenHost(host, count) for host, count in self._seen.items()]

    async def start(self, socket_path: Path) -> None:
        """Listen on ``socket_path`` and set the socket file to mode ``0600``.

        The directory holding the socket should already be private (``0700``); creating it is the
        caller's job. A stale socket file at the path is replaced.

        Raises:
            RuntimeError: when the proxy is already started.

        """
        if self._listening is not None:
            msg = "the proxy is already started"
            raise RuntimeError(msg)
        server = await asyncio.start_unix_server(
            self._handle, path=socket_path, limit=MAX_HEAD_BYTES
        )
        self._listening = (server, socket_path)
        await asyncio.to_thread(socket_path.chmod, 0o600)

    async def close(self) -> None:
        """Stop listening, end every open connection and remove the socket file."""
        listening, self._listening = self._listening, None
        if listening is None:
            return
        server, socket_path = listening
        server.close()
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await server.wait_closed()
        await asyncio.to_thread(socket_path.unlink, missing_ok=True)

    @contextlib.asynccontextmanager
    async def serving(self, socket_path: Path) -> AsyncGenerator[Self]:
        """Run the proxy on ``socket_path`` for the length of an ``async with`` block."""
        await self.start(socket_path)
        try:
            yield self
        finally:
            await self.close()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = cast("asyncio.Task[None]", asyncio.current_task())
        self._tasks.add(task)
        try:
            await self._serve(reader, writer)
        except RequestError as error:
            await _respond(writer, error.status, error.message)
        except Exception:
            logger.exception("proxy connection failed")
            await _respond(writer, HTTPStatus.INTERNAL_SERVER_ERROR, "internal error")
        finally:
            self._tasks.discard(task)
            await _close(writer)

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self._head_timeout)
        except TimeoutError:
            msg = "timed out waiting for the request"
            raise RequestError(HTTPStatus.REQUEST_TIMEOUT, msg) from None
        except asyncio.LimitOverrunError:
            msg = "request head is too large"
            raise RequestError(HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE, msg) from None
        except asyncio.IncompleteReadError:
            return
        request = parse_request(head[:-4])
        reason = port_refusal(request) or policy_refusal(self._policy, self._mode, request.host)
        if reason is not None:
            await self._refuse(writer, request, reason)
            return
        addresses = await self._resolve(request)
        networks = self._policy.private_networks
        if any(
            self._address_check(address) is not None
            and not private_address_allowed(address, networks)
            for address in addresses
        ):
            await self._refuse(writer, request, PRIVATE_ADDRESS)
            return
        if self._mode is Mode.RECORD and request.host not in self._quiet:
            self._note_seen(request.host)
        upstream_reader, upstream_writer = await self._connect(addresses, request.port)
        try:
            if request.method == "CONNECT":
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                upstream_writer.write(upstream_head(request))
            await _splice(reader, writer, upstream_reader, upstream_writer)
        finally:
            await _close(upstream_writer)

    async def _resolve(self, request: Request) -> list[str]:
        if sites.is_ip_literal(request.host):
            return [request.host]
        try:
            addresses = await self._resolver(request.host, request.port)
        except OSError:
            addresses = []
        if not addresses:
            msg = f"could not resolve {request.host}"
            raise RequestError(HTTPStatus.BAD_GATEWAY, msg)
        return addresses

    async def _connect(self, addresses: list[str], port: int) -> Streams:
        for address in addresses:
            with contextlib.suppress(OSError):
                return await asyncio.wait_for(self._connector(address, port), self._connect_timeout)
        msg = "could not connect to the host"
        raise RequestError(HTTPStatus.BAD_GATEWAY, msg)

    async def _refuse(self, writer: asyncio.StreamWriter, request: Request, reason: str) -> None:
        if request.host in self._quiet:
            self._quiet_refused += 1
            self._quiet_history.append(
                Refusal(self._quiet_refused, request.host, request.port, reason)
            )
        else:
            self._seq += 1
            self._refusals.append(Refusal(self._seq, request.host, request.port, reason))
        await _respond(writer, HTTPStatus.FORBIDDEN, f"blocked {request.host}: {reason}")

    def _note_seen(self, host: str) -> None:
        if host in self._seen or len(self._seen) < self._max_seen_hosts:
            self._seen[host] = self._seen.get(host, 0) + 1


async def _respond(writer: asyncio.StreamWriter, status: HTTPStatus, message: str) -> None:
    body = f"valetkey: {message}\n".encode("ascii", "replace")
    head = (
        f"HTTP/1.1 {status.value} {status.phrase}\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    )
    with contextlib.suppress(OSError):
        writer.write(head.encode("ascii") + body)
        await writer.drain()


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with contextlib.suppress(OSError):
        await writer.wait_closed()


async def _pump(source: asyncio.StreamReader, sink: asyncio.StreamWriter) -> None:
    with contextlib.suppress(OSError):
        while data := await source.read(_CHUNK):
            sink.write(data)
            await sink.drain()


async def _splice(
    reader_a: asyncio.StreamReader,
    writer_a: asyncio.StreamWriter,
    reader_b: asyncio.StreamReader,
    writer_b: asyncio.StreamWriter,
) -> None:
    """Copy bytes both ways until either side ends, then stop both directions."""
    pumps = [
        asyncio.create_task(_pump(reader_a, writer_b)),
        asyncio.create_task(_pump(reader_b, writer_a)),
    ]
    try:
        await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for pump in pumps:
            pump.cancel()
        await asyncio.gather(*pumps, return_exceptions=True)
