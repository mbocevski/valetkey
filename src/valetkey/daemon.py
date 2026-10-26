# SPDX-License-Identifier: Apache-2.0
"""``valetkeyd``: the one process per user that owns profiles, sessions, proxies and logins.

Every MCP client and the command-line tool talk to it over a Unix socket (see
:mod:`valetkey.client` for the wire format). Sharing one process is what makes "one browser per
profile" enforceable: Chromium's own profile lock is cleared on purpose when a browser starts
in a fresh namespace, so the registry here is the only thing that stops two browsers sharing a
profile.

**Operations.** ``args`` are JSON; every success carries the fields below in ``result``.

* ``sites``: no args. ``{"sites": [{"site", "state", "start", "allow", "learned", "summary"}]}``
  from the policy files and the live state. ``summary`` is what the last login learned, and it
  is delivered once.
* ``open`` ``{site}``: start the site's session, or join the running one (``reused: true``).
* ``snapshot``, ``click`` ``{ref}``, ``type`` ``{ref, text}``, ``navigate`` ``{url}``,
  ``screenshot`` ``{name?}``, ``status``: act on the site's session.
* ``close`` ``{site}``: end the site's session or login. ``{site, closed}``.
* ``reload_policy`` ``{site}``: read the policy file again and give it to the live proxy.
* ``login`` ``{target}``: ``target`` is a known site name or a host or URL. Opens a login
  window and returns at once with ``{site, window: "open"}``. When the window closes the hosts
  it reached are classified and merged into the site's policy.

Every response about a session carries an envelope: ``site``, ``contained: true``, the page's
``url``, and ``refused``, the hosts the proxy refused since this client last asked about the
site. Text that came from a web page is wrapped as ``{"untrusted": true, "text": ...}``, so a
client can tell it from anything the daemon says itself.

**Errors** are ``{code, message}``: ``bad_request``, ``request_too_large``, ``unknown_op``,
``unknown_site``, ``login_in_progress``, ``session_running``, ``no_session``, ``session_ended``,
``session_failed``, ``browser_error``, ``no_display``, ``x11_only``, ``bad_policy`` and
``internal``.

**Registry.** Each site is ``idle``, ``login`` or ``session``, changed only under a per-site
lock. ``open`` is refused while a login runs, ``login`` while a session runs, and a second
``open`` joins the live session. Session operations run in worker threads under a second
per-site lock, so two clients never interleave a click and a snapshot.

**Refusal cursors** are kept per connection and site: each client is told about each refusal
once, and one client asking does not use up what another has yet to see. A client that joins a
live session starts from the refusals made after it joined.

**Threads.** The event loop never blocks. Browser calls run in the default executor's threads.
Starting a session is one such call, and the session keeps its own long-lived thread for the
sandbox's die-with-parent rule (see :mod:`valetkey.sessions`); a login does the same (see
:mod:`valetkey.login`).
"""

import asyncio
import contextlib
import json
import logging
import os
import shutil
import signal
import socket
import struct
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, NoReturn, Protocol, cast

from valetkey import client, learn, login, sandbox, sessions, sites
from valetkey.client import MAX_LINE_BYTES, DaemonError
from valetkey.proxy import Mode, Proxy

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping
    from pathlib import Path

logger = logging.getLogger(__name__)

SD_LISTEN_FDS_START = 3
"""The first file descriptor systemd passes to a socket-activated service."""
STATES = ("idle", "login", "session")
_ACTIVATION_VARIABLES = ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES")
_NEWEST = 2**62
"""A cursor beyond any refusal, to ask the proxy where its history ends."""
_NOT_JSON = "the request is not valid JSON"
_ERROR_CODES: tuple[tuple[type[Exception], str], ...] = (
    (login.X11OnlyError, "x11_only"),
    (login.DisplayError, "no_display"),
    (sessions.AgentBrowserError, "browser_error"),
    (sessions.SessionError, "session_failed"),
    (sites.PolicyError, "bad_policy"),
    (ValueError, "bad_request"),
)
"""How errors from below become codes. The first match wins, so subclasses come first."""


class AlreadyRunningError(RuntimeError):
    """Another daemon already listens on the socket."""


class BrowserSession(Protocol):
    """What the daemon needs of a session. :class:`valetkey.sessions.Session` provides it."""

    first_page: sessions.Page

    def open(self, url: str) -> sessions.Page:
        """Navigate to ``url``."""

    def snapshot(self) -> sessions.Snapshot:
        """Return the page's interactive elements."""

    def click(self, ref: str) -> None:
        """Click ``ref``."""

    def fill(self, ref: str, text: str) -> None:
        """Fill ``ref`` with ``text``."""

    def current_url(self) -> str:
        """Return the page's URL."""

    def screenshot(self, name: str = "screenshot.png") -> Path:
        """Save a screenshot and return its path."""

    def is_alive(self) -> bool:
        """Tell whether the browser still runs."""

    def close(self) -> None:
        """End the session."""


class LoginWindow(Protocol):
    """What the daemon needs of a login. :class:`valetkey.login.LoginHandle` provides it."""

    async def wait(self) -> login.LoginResult:
        """Wait until the window has closed."""

    async def cancel(self) -> login.LoginResult:
        """End the login without classifying anything."""


type SessionFactory = Callable[[sites.Roots, str, str, Path], BrowserSession]
type LoginStarter = Callable[..., Awaitable[LoginWindow]]
type PeerUid = Callable[[socket.socket], int]


# -- the protocol: small pure functions ------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Request:
    """One parsed request line."""

    id: int | str | None
    op: str
    args: dict[str, Any]


def _fail(code: str, message: str) -> NoReturn:
    raise DaemonError(code, message)


def _parse_fail(message: str, request_id: int | str | None = None) -> NoReturn:
    raise _ParseError(message, request_id)


class _ParseError(DaemonError):
    """A request line that cannot be served; ``request_id`` is the id to answer with, if any."""

    def __init__(self, message: str, request_id: int | str | None = None) -> None:
        super().__init__("bad_request", message)
        self.request_id = request_id


def parse_request(line: bytes) -> Request:
    """Parse one request line.

    Raises:
        DaemonError: with code ``bad_request`` for anything that is not a JSON object with a
            string ``op``, an optional object ``args`` and an optional integer or string ``id``.
            Use :func:`request_id_of` on it to get the id to answer with, when one was readable.

    """
    try:
        data = json.loads(line)
    except ValueError:
        _parse_fail(_NOT_JSON)
    if not isinstance(data, dict):
        _parse_fail("the request must be a JSON object")
    identifier = data.get("id")
    if isinstance(identifier, bool) or not isinstance(identifier, int | str | None):
        identifier = None
    if not isinstance(data.get("op"), str) or not data["op"]:
        _parse_fail('the request needs an "op" string', identifier)
    args = data.get("args", {})
    if not isinstance(args, dict):
        _parse_fail('"args" must be an object', identifier)
    return Request(identifier, data["op"], args)


def request_id_of(error: DaemonError) -> int | str | None:
    """Return the request id a parse error carries, or ``None``."""
    return error.request_id if isinstance(error, _ParseError) else None


def encode(message: dict[str, Any]) -> bytes:
    """Return ``message`` as one line of JSON."""
    return json.dumps(message, separators=(",", ":")).encode() + b"\n"


def ok_response(identifier: int | str | None, result: dict[str, Any]) -> bytes:
    """Return the line that answers a request successfully."""
    return encode({"id": identifier, "ok": True, "result": result})


def error_response(identifier: int | str | None, error: DaemonError) -> bytes:
    """Return the line that answers a request with ``error``."""
    return encode({"id": identifier, "ok": False, "error": error.to_json()})


def untrusted(text: str) -> dict[str, Any]:
    """Wrap text that came from a web page, so a client can tell it from the daemon's own."""
    return {"untrusted": True, "text": text}


def map_error(error: Exception) -> DaemonError:
    """Turn an error from a session or the login runner into the error the client sees."""
    if isinstance(error, DaemonError):
        return error
    for kind, code in _ERROR_CODES:
        if isinstance(error, kind):
            return DaemonError(code, str(error))
    return DaemonError("internal", "the daemon hit an unexpected error")


def listen_fds(environ: Mapping[str, str], pid: int) -> int:
    """Return how many sockets systemd passed to process ``pid`` (0 when none).

    systemd sets ``LISTEN_PID`` to the PID it started and ``LISTEN_FDS`` to the count, so a
    value meant for another process, or an unreadable one, counts as none.
    """
    try:
        if int(environ.get("LISTEN_PID", "")) != pid:
            return 0
        return max(int(environ.get("LISTEN_FDS", "")), 0)
    except ValueError:
        return 0


def activated_socket(
    environ: Mapping[str, str], pid: int, first_fd: int = SD_LISTEN_FDS_START
) -> socket.socket | None:
    """Return the listening socket systemd passed in, or ``None`` when it did not pass one.

    Raises:
        ValueError: when the descriptor is not a Unix stream socket.

    """
    if listen_fds(environ, pid) < 1:
        return None
    os.set_inheritable(first_fd, False)  # noqa: FBT003 - os.set_inheritable takes it positionally
    inherited = socket.socket(fileno=first_fd)
    if inherited.family != socket.AF_UNIX or inherited.type != socket.SOCK_STREAM:
        inherited.close()
        message = "the socket systemd passed is not a Unix stream socket"
        raise ValueError(message)
    inherited.setblocking(False)  # noqa: FBT003  # the stdlib takes it positionally only
    return inherited


def peer_uid(connection: socket.socket) -> int:
    """Return the user id of the process at the other end of a Unix socket (``SO_PEERCRED``)."""
    credentials = connection.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
    )
    return struct.unpack("3i", credentials)[1]


def refused_entry(refusal: Any) -> dict[str, Any]:  # noqa: ANN401 - a proxy.Refusal
    """Describe one refusal for a client: the host, the port and the reason, nothing else."""
    return {"host": refusal.host, "port": refusal.port, "reason": refusal.reason}


def make_private_dirs(path: Path) -> None:
    """Create ``path`` and its missing parents with mode ``0700``."""
    missing = [path, *path.parents]
    for directory in reversed([d for d in missing if not d.exists()]):
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)


# -- the registry ----------------------------------------------------------------------------


@dataclass(eq=False)
class _Site:
    """Everything the daemon holds for one site."""

    name: str
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    op_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    kind: str = "idle"
    session: BrowserSession | None = None
    proxy: Proxy | None = None
    window: LoginWindow | None = None
    watcher: asyncio.Task[None] | None = None
    generation: int = 0
    start: str = ""
    summary: str | None = None


@dataclass(eq=False)
class _Connection:
    """One client connection. Refusal cursors are kept here, per site."""

    cursors: dict[str, tuple[int, int]] = field(default_factory=dict)


class Daemon:
    """The daemon's state and operations. :func:`run` serves one over a socket.

    The keyword arguments replace the parts that need a real browser or a real display, for
    tests: ``session_factory`` starts a session for a site,
    ``login_starter`` is :func:`valetkey.login.start_login`, ``proxy_options`` are extra
    keyword arguments for each session's :class:`valetkey.proxy.Proxy`, and ``peer_uid`` reads a
    connection's user id.
    """

    def __init__(  # noqa: PLR0913 - each is a seam the tests replace
        self,
        roots: sites.Roots,
        *,
        session_factory: SessionFactory | None = None,
        login_starter: LoginStarter = login.start_login,
        proxy_options: Mapping[str, Any] | None = None,
        peer_uid: PeerUid = peer_uid,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        """Create a daemon for the directories in ``roots``. Nothing listens until :func:`run`."""
        self.roots = roots
        self._session_factory = session_factory or start_session
        self._login_starter = login_starter
        self._proxy_options = dict(proxy_options or {})
        self._peer_uid = peer_uid
        self._now = now
        self._uid = os.getuid()
        self._sites: dict[str, _Site] = {}
        self._connections: set[asyncio.Task[None]] = set()
        self._server: asyncio.Server | None = None
        self._socket_path: Path | None = None
        self._ops: dict[str, Callable[[_Connection, dict[str, Any]], Awaitable[dict[str, Any]]]] = {
            "sites": self._op_sites,
            "open": self._op_open,
            "snapshot": self._op_snapshot,
            "click": self._op_click,
            "type": self._op_type,
            "navigate": self._op_navigate,
            "screenshot": self._op_screenshot,
            "status": self._op_status,
            "close": self._op_close,
            "reload_policy": self._op_reload_policy,
            "login": self._op_login,
        }

    # -- serving --

    async def start(self, path: Path | None = None) -> None:
        """Listen for clients.

        Under systemd socket activation the passed-in socket is used and its file is left
        alone. Otherwise the socket is bound at ``path`` (default:
        :func:`valetkey.client.socket_path`) with mode ``0600``.

        Raises:
            AlreadyRunningError: when a daemon already answers on that path.

        """
        inherited = activated_socket(os.environ, os.getpid())
        if inherited is not None:
            for name in _ACTIVATION_VARIABLES:
                os.environ.pop(name, None)
            self._server = await asyncio.start_unix_server(
                self._serve_connection, sock=inherited, limit=MAX_LINE_BYTES, cleanup_socket=False
            )
            return
        target = path or client.socket_path(self.roots)
        await asyncio.to_thread(make_private_dirs, target.parent)
        if await client.is_running(target):
            message = f"valetkeyd is already running on {target}"
            raise AlreadyRunningError(message)
        self._server = await asyncio.start_unix_server(
            self._serve_connection, path=target, limit=MAX_LINE_BYTES
        )
        self._socket_path = target
        await asyncio.to_thread(target.chmod, 0o600)

    async def shutdown(self) -> None:
        """Stop serving, end every session and login, and remove the socket file."""
        if self._server is not None:
            self._server.close()
        tasks = list(self._connections)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.gather(*(self._shutdown_site(s) for s in self._sites.values()))
        if self._server is not None:
            await self._server.wait_closed()
            self._server = None
        if self._socket_path is not None:
            await asyncio.to_thread(self._socket_path.unlink, missing_ok=True)

    async def _shutdown_site(self, state: _Site) -> None:
        async with state.lock:
            await self._end(state)

    async def _serve_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        assert task is not None  # noqa: S101 - a handler always runs in a task
        self._connections.add(task)
        try:
            if self._peer_uid(writer.get_extra_info("socket")) == self._uid:
                await self._converse(reader, writer)
        finally:
            self._connections.discard(task)
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    async def _converse(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        connection = _Connection()
        while True:
            try:
                line = await reader.readline()
            except ValueError:  # longer than the limit; the stream cannot be resynchronised
                error = DaemonError(
                    "request_too_large", f"a request may not exceed {MAX_LINE_BYTES} bytes"
                )
                await _send(writer, error_response(None, error))
                return
            if not line.endswith(b"\n"):
                return
            await _send(writer, await self._answer(connection, line))

    async def _answer(self, connection: _Connection, line: bytes) -> bytes:
        """Return the response line for one request line. Never raises."""
        identifier: int | str | None = None
        try:
            request = parse_request(line)
        except DaemonError as error:
            return error_response(request_id_of(error), error)
        identifier = request.id
        handler = self._ops.get(request.op)
        if handler is None:
            return error_response(
                identifier, DaemonError("unknown_op", f"no such operation: {request.op}")
            )
        try:
            return ok_response(identifier, await handler(connection, request.args))
        except Exception as error:
            mapped = map_error(error)
            if mapped.code == "internal":
                logger.exception("request failed: %s", request.op)
            return error_response(identifier, mapped)

    # -- state --

    def _state(self, site: str) -> _Site:
        return self._sites.setdefault(site, _Site(site))

    def _known_sites(self) -> list[str]:
        directory = sites.policy_path(self.roots, "x").parent
        found = {p.stem for p in directory.glob("*.json")} if directory.is_dir() else set()
        valid = {name for name in found if _is_site_name(name)}
        return sorted(valid | {n for n, s in self._sites.items() if s.kind != "idle" or s.summary})

    async def _load_policy(self, site: str) -> sites.Policy:
        try:
            return await asyncio.to_thread(sites.load_policy, self.roots, site)
        except FileNotFoundError:
            known = ", ".join(self._known_sites()) or "none yet"
            _fail("unknown_site", f"no site named {site!r}; known sites: {known}")

    # -- operations: sites and policies --

    async def _op_sites(self, _connection: _Connection, _args: dict[str, Any]) -> dict[str, Any]:
        entries = []
        for name in self._known_sites():
            state = self._state(name)
            try:
                policy: sites.Policy | None = await asyncio.to_thread(
                    sites.load_policy, self.roots, name
                )
            except OSError, sites.PolicyError:
                policy = None
            entries.append(
                {
                    "site": name,
                    "state": state.kind,
                    "start": policy.start if policy else state.start,
                    "allow": list(policy.allow) if policy else [],
                    "learned": policy.learned.strftime("%Y-%m-%dT%H:%M:%SZ")
                    if policy and policy.learned
                    else None,
                    "summary": state.summary,
                }
            )
            state.summary = None
        return {"sites": entries}

    async def _op_reload_policy(
        self, _connection: _Connection, args: dict[str, Any]
    ) -> dict[str, Any]:
        site = _site_arg(args)
        policy = await self._load_policy(site)
        state = self._state(site)
        live = state.proxy is not None
        if state.proxy is not None:
            state.proxy.update_policy(policy)
        return {
            "site": site,
            "allow": list(policy.allow),
            "excluded": list(policy.excluded),
            "live": live,
        }

    # -- operations: login --

    async def _op_login(self, _connection: _Connection, args: dict[str, Any]) -> dict[str, Any]:
        target = _string_arg(args, "target")
        site, start = await self._login_target(target)
        state = self._state(site)
        async with state.lock:
            if state.kind == "session":
                _fail("session_running", f"{site} has a running session; close it first")
            if state.kind == "login":
                _fail("login_in_progress", f"a login window for {site} is already open")
            state.kind = "login"
            state.start = start
            try:
                state.window = await self._login_starter(
                    site, start, self.roots, self._finisher(state, start)
                )
            except BaseException:
                state.kind = "idle"
                raise
            state.watcher = asyncio.ensure_future(self._watch_login(state, state.window))
        return {"site": site, "window": "open"}

    async def _login_target(self, target: str) -> tuple[str, str]:
        """Return the site name and start URL for a known site name, a host or a URL."""
        if _is_site_name(target) and "." not in target:
            policy = await self._load_policy(target)
            return target, policy.start
        start = login.normalize_start_url(target)
        return await asyncio.to_thread(sites.choose_site_name, self.roots, start), start

    def _finisher(self, state: _Site, start: str) -> Callable[[list[Any], Path], Awaitable[None]]:
        async def finish(seen: list[Any], profile: Path) -> None:
            try:
                navigated = await asyncio.to_thread(
                    learn.navigation_hosts, profile / "Default" / "History"
                )
                classification = learn.classify(start, [h.host for h in seen], navigated)
                try:
                    existing: sites.Policy | None = await asyncio.to_thread(
                        sites.load_policy, self.roots, state.name
                    )
                except FileNotFoundError:
                    existing = None
                policy = learn.merge(existing, classification, start, self._now(), state.name)
                await asyncio.to_thread(sites.save_policy, self.roots, policy)
            except Exception as error:
                logger.exception("could not save the login for %s", state.name)
                state.summary = f"The {state.name} login could not be saved: {error}"
                return
            state.summary = learn.summary(policy, classification)

        return finish

    async def _watch_login(self, state: _Site, window: LoginWindow) -> None:
        try:
            await window.wait()
        except Exception:
            logger.exception("login for %s failed", state.name)
        finally:
            state.window = None
            state.kind = "idle"

    # -- operations: sessions --

    async def _op_open(self, connection: _Connection, args: dict[str, Any]) -> dict[str, Any]:
        site = _site_arg(args)
        state = self._state(site)
        async with state.lock:
            if state.kind == "login":
                _fail("login_in_progress", f"a login window for {site} is open; close it first")
            if state.kind == "session" and not (state.session and state.session.is_alive()):
                await self._end(state)
            reused = state.kind == "session"
            if not reused:
                await self._begin_session(state)
            session = cast("BrowserSession", state.session)
            if not reused:
                connection.cursors[site] = (state.generation, 0)  # the opener sees startup refusals
                url, title = session.first_page.url, session.first_page.title
            else:
                url, title = await asyncio.to_thread(session.current_url), ""
            result = self._envelope(connection, state, url)
        result["reused"] = reused
        result["page"] = {"title": untrusted(title)}
        return result

    async def _begin_session(self, state: _Site) -> None:
        policy = await self._load_policy(state.name)
        paths = sessions.session_paths(self.roots, state.name)
        await asyncio.to_thread(make_private_dirs, paths.proxy_socket.parent)
        proxy = Proxy(
            policy, Mode.ENFORCE, quiet_hosts=sandbox.BACKGROUND_HOSTS, **self._proxy_options
        )
        await proxy.start(paths.proxy_socket)
        try:
            session = await asyncio.to_thread(
                self._session_factory, self.roots, state.name, policy.start, paths.proxy_socket
            )
        except BaseException:
            await proxy.close()
            await asyncio.to_thread(shutil.rmtree, paths.directory, ignore_errors=True)
            raise
        state.session, state.proxy, state.kind = session, proxy, "session"
        state.start = policy.start
        state.generation += 1

    async def _end(self, state: _Site) -> None:
        """Stop whatever the site is doing and make it idle. The caller holds ``state.lock``."""
        window, watcher = state.window, state.watcher
        if window is not None:
            await window.cancel()
        if watcher is not None:
            await asyncio.gather(watcher, return_exceptions=True)
        async with state.op_lock:
            session, proxy = state.session, state.proxy
            state.session = state.proxy = None
            state.kind = "idle"
            if session is not None:
                try:
                    await asyncio.to_thread(session.close)
                except Exception:
                    logger.exception("closing the %s session failed", state.name)
            if proxy is not None:
                await proxy.close()
            if session is not None or proxy is not None:
                directory = sessions.session_paths(self.roots, state.name).directory
                await asyncio.to_thread(shutil.rmtree, directory, ignore_errors=True)

    async def _op_close(self, _connection: _Connection, args: dict[str, Any]) -> dict[str, Any]:
        site = _site_arg(args)
        state = self._state(site)
        async with state.lock:
            was = state.kind != "idle"
            await self._end(state)
        return {"site": site, "closed": was}

    async def _op_status(self, connection: _Connection, args: dict[str, Any]) -> dict[str, Any]:
        site = _site_arg(args)
        state = self._state(site)
        if state.kind != "session":
            if state.kind == "idle":
                await self._load_policy(site)
            return {"site": site, "state": state.kind, "contained": True}
        result = await self._session_op(connection, state, BrowserSession.is_alive)
        result.pop("_value")
        result["state"] = "session"
        return result

    async def _op_snapshot(self, connection: _Connection, args: dict[str, Any]) -> dict[str, Any]:
        state = self._state(_site_arg(args))
        result = await self._session_op(connection, state, lambda session: session.snapshot())
        snap: sessions.Snapshot = result.pop("_value")
        result["url"] = snap.url
        result["snapshot"] = untrusted(snap.tree)
        result["refs"] = {ref: element.role for ref, element in snap.refs.items()}
        return result

    async def _op_click(self, connection: _Connection, args: dict[str, Any]) -> dict[str, Any]:
        state = self._state(_site_arg(args))
        ref = _string_arg(args, "ref")
        result = await self._session_op(connection, state, lambda session: session.click(ref))
        result.pop("_value")
        result["done"] = True
        return result

    async def _op_type(self, connection: _Connection, args: dict[str, Any]) -> dict[str, Any]:
        state = self._state(_site_arg(args))
        ref, text = _string_arg(args, "ref"), _string_arg(args, "text")
        result = await self._session_op(connection, state, lambda session: session.fill(ref, text))
        result.pop("_value")
        result["done"] = True
        return result

    async def _op_navigate(self, connection: _Connection, args: dict[str, Any]) -> dict[str, Any]:
        state = self._state(_site_arg(args))
        url = _string_arg(args, "url")
        result = await self._session_op(connection, state, lambda session: session.open(url))
        page: sessions.Page = result.pop("_value")
        result["url"] = page.url
        result["page"] = {"title": untrusted(page.title)}
        return result

    async def _op_screenshot(self, connection: _Connection, args: dict[str, Any]) -> dict[str, Any]:
        state = self._state(_site_arg(args))
        name = args.get("name", "screenshot.png")
        if not isinstance(name, str):
            _fail("bad_request", '"name" must be a string')
        result = await self._session_op(connection, state, lambda session: session.screenshot(name))
        result["path"] = str(result.pop("_value"))
        return result

    async def _session_op(
        self, connection: _Connection, state: _Site, call: Callable[[BrowserSession], Any]
    ) -> dict[str, Any]:
        """Run ``call`` on the site's session in a worker thread and wrap the answer.

        The returned dictionary holds the envelope and, under ``_value``, what ``call``
        returned, for the caller to shape and remove.
        """
        dead: BrowserSession | None = None
        async with state.op_lock:
            if state.kind != "session":
                _fail("no_session", f"{state.name} has no running session; open it first")
            session = cast("BrowserSession", state.session)
            if not session.is_alive():
                dead = session
            else:
                try:
                    value = await asyncio.to_thread(call, session)
                    url = await asyncio.to_thread(session.current_url)
                except Exception as error:
                    mapped = map_error(error)
                    mapped.details = self._envelope(connection, state, None) | {"url": None}
                    raise mapped from error
                envelope = self._envelope(connection, state, url)
                envelope["_value"] = value
                return envelope
        async with state.lock:
            if state.session is dead:
                await self._end(state)
        _fail("session_ended", f"the {state.name} browser has exited; open the site again")

    def _envelope(self, connection: _Connection, state: _Site, url: str | None) -> dict[str, Any]:
        """Build the fields every session answer carries; this client's refusals are consumed.

        A connection that has not asked about the live session before starts from the refusals
        made from now on, not from the history of other clients' pages.
        """
        proxy = cast("Proxy", state.proxy)
        known = connection.cursors.get(state.name)
        if known is None or known[0] != state.generation:
            known = (state.generation, proxy.refused_since(_NEWEST)[1])
        entries, cursor = proxy.refused_since(known[1])
        connection.cursors[state.name] = (state.generation, cursor)
        refused = [refused_entry(entry) for entry in entries]
        return {"site": state.name, "contained": True, "url": url, "refused": refused}


def start_session(
    roots: sites.Roots, site: str, start_url: str, proxy_socket: Path
) -> BrowserSession:
    """Start the real session: a contained agent-browser behind the site's proxy."""
    return sessions.Session.start(roots, site, start_url, proxy_socket=proxy_socket)


def _is_site_name(name: str) -> bool:
    try:
        sites.validate_site_name(name)
    except ValueError:
        return False
    return True


def _site_arg(args: dict[str, Any]) -> str:
    site = _string_arg(args, "site")
    try:
        return sites.validate_site_name(site)
    except ValueError as error:
        _fail("bad_request", str(error))


def _string_arg(args: dict[str, Any], name: str) -> str:
    value = args.get(name)
    if not isinstance(value, str) or not value:
        _fail("bad_request", f'"{name}" must be a non-empty string')
    return value


async def _send(writer: asyncio.StreamWriter, line: bytes) -> None:
    with contextlib.suppress(OSError):
        writer.write(line)
        await writer.drain()


# -- running ---------------------------------------------------------------------------------


async def run(
    daemon: Daemon,
    socket_path: Path | None = None,
    *,
    ready: asyncio.Event | None = None,
) -> int:
    """Serve until SIGTERM or SIGINT, then shut down cleanly and return the exit status (0).

    ``ready`` is set once the daemon is listening and the signal handlers are in place.
    """
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for name in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(name, stop.set)
    try:
        await daemon.start(socket_path)
        if ready is not None:
            ready.set()
        await stop.wait()
    finally:
        for name in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(name)
        await daemon.shutdown()
    return 0
