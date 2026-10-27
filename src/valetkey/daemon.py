# SPDX-License-Identifier: Apache-2.0
"""``valetkeyd``: the one process per user that owns profiles, sessions, proxies and logins.

Every MCP client and the command-line tool talk to it over a Unix socket (see
:mod:`valetkey.client` for the wire format). Sharing one process is what makes "one browser per
profile" enforceable: Chromium's own profile lock is cleared on purpose when a browser starts
in a fresh namespace, so the registry here is the only thing that stops two browsers sharing a
profile.

**Operations.** ``args`` are JSON; every success carries the fields below in ``result``.

* ``sites`` ``{site?}``: ``{"sites": [{"site", "account", "state", "start", "allow", "excluded",
  "denied", "learned", "summary"}]}`` from the policy files and the live state, one entry per
  account, or only the entry of ``site`` when that is given. ``summary`` is what the last login
  learned, and it is delivered once.
* ``open`` ``{site}``: start the site's session, or join the running one (``reused: true``).
* ``snapshot`` ``{images?}``, ``type`` ``{ref, text, submit?}``, ``navigate`` ``{url}``,
  ``screenshot`` ``{name?}``, ``status`` ``{site}``: act on the site's session. ``submit``
  presses Enter after the text is typed. With ``images: true`` a ``snapshot`` answer also has
  ``images``, the biggest pictures and videos on the page, each ``{kind, alt, url, width,
  height}`` with ``alt`` and ``url`` untrusted.
* ``save`` ``{ref | url}``: save what an address serves into the site's downloads directory,
  by the contained browser and its proxy, so only hosts the site may reach work. ``ref`` is an
  element of the last snapshot (a link's target, a picture's or video's source or poster); ``url``
  is an HTTP or HTTPS address. The browser opens it in a tab of its own and the daemon takes the
  body from the browser's record of the exchange, so nothing runs in the page of that address, and
  writes it into the folder like any download. The answer is as for ``navigate``: the envelope,
  the address that was fetched (``source``, untrusted) and ``downloads`` with the file that
  arrived, never its bytes.
* ``click`` ``{ref | text, role?, expect?}``: a verified click (see :mod:`valetkey.clicks`).
  A ``ref`` means the element it was in this client's last snapshot, which is looked up again
  at click time; ``text`` is visible text, optionally with a ``role``. ``expect`` is one of
  ``{"text_appears": s}``, ``{"text_gone": s}`` or ``{"url_changes": true}``. The answer adds
  ``clicked`` (``role`` and the page's ``name``, untrusted), ``attempts``, ``expect`` and
  ``outcome`` (``met``, ``not_met``, ``already_true`` or ``unchecked``).
* ``downloads`` ``{site}``: the files in the site's downloads directory (``files``, each with a
  ``path`` that is untrusted because the page chose the name, a ``size``, a ``mime`` guessed from
  the content, and ``new`` if this client has not been told of it) and those still being
  downloaded (``in_progress``). A ``click`` or ``navigate`` answer carries the same under
  ``downloads``: the files that arrived since this client last looked.
* ``status`` with no ``site``: what is running now. ``{"sessions": [{"site", "since",
  "contained", "host", "idle_seconds", "closes_at"}], "logins": [{"site", "since"}],
  "bridges": [{"bridge", "since"}]}``, the
  first two sorted by site. ``since`` is a UTC time, ``host`` is the host of the page the
  browser was last reported at (never the whole URL, which may carry a token). ``idle_seconds``
  is how long nothing has used the session and ``closes_at`` a UTC time: see **Idle sessions**.
  It is read from
  the processes the daemon owns. With ``links: true`` a login shown in a web browser also has
  ``remote`` (``url``, ``port``, ``ssh``): the link is a credential, so ``watch`` never carries
  it and nothing that reaches a model asks for it.
* ``watch``: the connection stays open. The first answer is ``{"event": "snapshot", "at",
  "sessions", "logins"}`` as for ``status``; then one answer per change, each
  ``{"event": "session_started" | "session_ended" | "login_opened" | "login_closed",
  "site", "at"}`` (a ``session_ended`` caused by lack of use also has ``"reason": "idle"``), or
  ``{"event": "bridge_connected" | "bridge_disconnected", "bridge", "at"}``,
  all with the request's ``id``. Nothing can hide a session from it.
* ``bridge_register`` ``{rand}``: record the bridge ``bridge-<rand>``, whose socket the ssh
  connection forwards to ``<runtime>/valetkey/bridge-<rand>.sock``. The socket must already be
  there, a real socket of this user (``no_socket``), and the name must be free
  (``bridge_exists``). The caller keeps the connection open: the bridge is forgotten when it
  closes. Asking again on the same connection is harmless and answers ``registered: false``.
  See :mod:`valetkey.bridge`.
* ``close`` ``{site}``: end the site's session or login. ``{site, closed}``.
* ``reload_policy`` ``{site}``: read the policy file again and give it to the live proxy.
* ``login`` ``{target, account?}``: ``target`` is a known site name or a host or URL, and
  ``account`` names another account of the site (``sitex:work``). Opens a login
  window and returns at once with ``{site, window: "open"}``. The window is on this machine's
  screen. With none to use it is on a laptop through a connected bridge when the config turns on
  ``remote_logins.waypipe`` (the answer then has ``route: "bridge"``), and otherwise in a web
  browser when it turns on ``novnc``. When the window closes the hosts it reached are
  classified and merged into the site's policy.

**Accounts.** A site can have several, named ``site:account`` and each with its own policy,
profile and downloads. A bare ``site`` is the account of a site that has only one, and is refused
with ``ambiguous_account`` when it has several.

Every response about a session carries an envelope: ``site``, ``contained: true``, the page's
``url``, ``refused``, the hosts the proxy refused since this client last asked about the
site, and ``background_refused``, ``[{host, count}]`` for the refusals of hosts the browser
contacts on its own (see :data:`valetkey.sandbox.BACKGROUND_HOSTS`) since then. Those are kept
apart so that they never read as a host the page needs. Today that is only the browser's
updater, which asks for something in the first moments of every session, so refusals made in
the first :data:`STARTUP_GRACE` seconds are left out.

Text that came from a web page is wrapped as ``{"untrusted": true, "text": ...}``, so a client
can tell it from anything the daemon says itself.

**Errors** are ``{code, message}``: ``bad_request``, ``request_too_large``, ``unknown_op``,
``unknown_site``, ``ambiguous_account``, ``unknown_ref``, ``target_not_found``,
``target_ambiguous``, ``login_in_progress``, ``private_address``, ``bridge_exists``, ``no_socket``,
``no_session``, ``session_idle``, ``session_ended``, ``session_failed``,
``browser_error``, ``no_display``, ``x11_only``, ``bad_policy``, ``setup_error`` (the public
suffix list is missing) and ``internal``.

**Liveness.** A task polls every session twice a second. A session whose browser has been
killed (the holder or Chrome itself) is ended and reported within about a second, instead of the
next time a client asks. When a session starts, ``notify-send`` is run, if it exists, with the
site name; it is never waited for.

**Registry.** Each site is ``idle``, ``login`` or ``session``, changed only under a per-site
lock. ``open`` is refused while a login runs, ``login`` while a session runs, and a second
``open`` joins the live session. Session operations run in worker threads under a second
per-site lock, so two clients never interleave a click and a snapshot.

**Idle sessions.** A session that nothing uses for ``session_idle_minutes`` (config file, 1 to
1440, 15 unless set) is ended like ``close`` does it: the profile, cookies and downloads stay,
``session_ended`` carries ``"reason": "idle"`` and one line is logged. Using it means a request
that names the site, a call still running, a question waiting for the person, or a download
still being written. The next call that needs the session fails with ``session_idle`` and a
message that says so, until the site is opened or closed.

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
import fcntl
import functools
import logging
import os
import re
import signal
import socket
import sqlite3
import stat
import struct
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from valetkey import (
    approvals,
    client,
    cookies,
    display,
    downloads,
    learn,
    login,
    sites,
)
from valetkey.approval_ops import Approvals, Notifier
from valetkey.client import MAX_LINE_BYTES, DaemonError
from valetkey.download_ops import Downloads
from valetkey.protocol import (
    BrowserSession,
    LoginWindow,
    Request,
    error_response,
    fail,
    map_error,
    ok_response,
    parse_request,
    request_id_of,
    send,
    string_arg,
)
from valetkey.proxy import (
    address_refusal,
    private_address_allowed,
    system_resolver,
)
from valetkey.registry import (
    TIME_FORMAT,
    Connection,
    Registry,
    Site,
    Watcher,
)
from valetkey.session_ops import (
    POLL_INTERVAL,
    STARTUP_GRACE,
    Announcer,
    SessionFactory,
    Sessions,
    make_private_dirs,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping, Sequence

logger = logging.getLogger(__name__)

_BRIDGE_RAND = re.compile(r"[A-Za-z0-9]{8,64}")
RESOLVE_SECONDS = 10.0
"""The longest to wait for the start host of a login to resolve."""
_MAX_NAMED_HOSTS = 5
SD_LISTEN_FDS_START = 3
"""The first file descriptor systemd passes to a socket-activated service."""
STATES = ("idle", "login", "session")
_ACTIVATION_VARIABLES = ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES")


class AlreadyRunningError(RuntimeError):
    """Another daemon already listens on the socket."""


type LoginStarter = Callable[..., Awaitable[LoginWindow]]
type DisplayStarter = Callable[..., Awaitable[display.Display]]
type PeerUid = Callable[[socket.socket], int]


# -- the protocol: small pure functions ------------------------------------------------------


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


def _take_lock(socket_path: Path) -> int:
    """Lock ``<socket>.lock`` for this process and return its descriptor.

    Raises:
        AlreadyRunningError: when another process holds the lock.

    """
    descriptor = os.open(client.lock_path(socket_path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(descriptor)
        message = f"valetkeyd is already running on {socket_path}"
        raise AlreadyRunningError(message) from None
    return descriptor


def peer_uid(connection: socket.socket) -> int:
    """Return the user id of the process at the other end of a Unix socket (``SO_PEERCRED``)."""
    credentials = connection.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
    )
    return struct.unpack("3i", credentials)[1]


def _private_note(summary: str | None, site: str, hosts: tuple[str, ...]) -> str:
    """Add to a login's summary the hosts refused for their private address, and what to do."""
    shown = ", ".join(hosts[:_MAX_NAMED_HOSTS])
    more = len(hosts) - _MAX_NAMED_HOSTS
    named = f"{shown} and {more} more" if more > 0 else shown
    note = (
        f"Refused because they are on a private network: {named}. Only the person can allow "
        f"that, with `valetkey allow {site} --private-network RANGE` (the narrowest range that "
        "holds the address); then log in again."
    )
    return f"{summary} {note}" if summary else note


def _closed_for_login(error: Exception) -> DaemonError:
    """Return ``error`` as the daemon would answer it, saying the running session was closed."""
    mapped = map_error(error)
    mapped.details = mapped.details | {"closed_session": True}
    return mapped


@dataclass(frozen=True, slots=True)
class _RegisteredBridge:
    """A laptop's waypipe bridge, reachable on a socket in the runtime directory."""

    name: str
    path: Path
    since: datetime


class Daemon:
    """The daemon's state and operations. :func:`run` serves one over a socket.

    The keyword arguments replace the parts that need a real browser or a real display, for
    tests: ``session_factory`` starts a session for a site,
    ``login_starter`` is :func:`valetkey.login.start_login`, ``proxy_options`` are extra
    keyword arguments for each session's :class:`valetkey.proxy.Proxy`, ``startup_grace`` is
    :data:`STARTUP_GRACE`, and ``peer_uid`` reads a connection's user id. ``download_settle`` is
    how long to look for a download that a click has only just started, and ``download_wait`` is
    the longest to wait for downloads that are running. ``announcer`` (default
    :func:`announce_session`) tells the person that a session started, and ``poll_interval`` is
    how often each session's browser is checked. ``display_starter`` makes the private display of
    a login shown in a web browser (:func:`valetkey.display.start_display`). ``idle_limit`` is
    how many seconds a session may go unused, instead of the config file's
    ``session_idle_minutes``, and ``idle_clock`` tells the time for it. ``screen_finder`` looks
    for the person's screen (:func:`valetkey.login.find_wayland_socket`), to know whether a login
    window could open before a running session is closed for it.
    """

    def __init__(  # noqa: PLR0913 - each is a seam the tests replace
        self,
        roots: sites.Roots,
        *,
        session_factory: SessionFactory | None = None,
        login_starter: LoginStarter = login.start_login,
        proxy_options: Mapping[str, Any] | None = None,
        startup_grace: float = STARTUP_GRACE,
        peer_uid: PeerUid = peer_uid,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        download_settle: float = downloads.SETTLE_SECONDS,
        download_wait: float = downloads.FINISH_SECONDS,
        announcer: Announcer | None = None,
        notifier: Notifier | None = None,
        poll_interval: float = POLL_INTERVAL,
        approve_timeout: float = approvals.COMMAND_TIMEOUT,
        user_environment: Callable[[], Mapping[str, str]] = login.systemd_user_environment,
        display_starter: DisplayStarter = display.start_display,
        idle_limit: float | None = None,
        idle_clock: Callable[[], float] = time.monotonic,
        screen_finder: Callable[[], Path] = login.find_wayland_socket,
    ) -> None:
        """Create a daemon for the directories in ``roots``. Nothing listens until :func:`run`."""
        self.roots = roots
        self._login_starter = login_starter
        self._display_starter = display_starter
        self._proxy_options = dict(proxy_options or {})
        self._peer_uid = peer_uid
        self._now = now
        self.registry = Registry(roots, now=now, idle_clock=idle_clock)
        self.downloads = Downloads(self.registry, settle=download_settle, wait=download_wait)
        self.approvals = Approvals(
            self.registry,
            approve_timeout=approve_timeout,
            user_environment=user_environment,
            notifier=notifier,
        )
        self.sessions = Sessions(
            self.registry,
            self.downloads,
            session_factory=session_factory,
            proxy_options=self._proxy_options,
            startup_grace=startup_grace,
            announcer=announcer,
            now=now,
            poll_interval=poll_interval,
            idle_limit=idle_limit,
            idle_clock=idle_clock,
        )
        self._screen_finder = screen_finder
        self._bridges: dict[str, _RegisteredBridge] = {}
        self._uid = os.getuid()
        self._connections: set[asyncio.Task[None]] = set()
        self._server: asyncio.Server | None = None
        self._socket_path: Path | None = None
        self._lock_fd: int | None = None
        self._ops: dict[str, Callable[[Connection, dict[str, Any]], Awaitable[dict[str, Any]]]] = {
            "sites": self._op_sites,
            "open": self.sessions.op_open,
            "snapshot": self.sessions.op_snapshot,
            "click": self.sessions.op_click,
            "type": self.sessions.op_type,
            "navigate": self.sessions.op_navigate,
            "save": self.sessions.op_save,
            "screenshot": self.sessions.op_screenshot,
            "status": self._op_status,
            "close": self.sessions.op_close,
            "reload_policy": self._op_reload_policy,
            "login": self._op_login,
            "downloads": self.downloads.op_downloads,
            "allow_check": self.approvals.op_allow_check,
            "allow_apply": self.approvals.op_allow_apply,
            "allow_ask": self.approvals.op_allow_ask,
            "deny_check": self.approvals.op_deny_check,
            "deny_apply": self.approvals.op_deny_apply,
            "deny_ask": self.approvals.op_deny_ask,
            "bridge_register": self._op_bridge_register,
        }

    # -- serving --

    async def start(self, path: Path | None = None) -> None:
        """Listen for clients.

        Under systemd socket activation the passed-in socket is used and its file is left
        alone. Otherwise the socket is bound at ``path`` (default:
        :func:`valetkey.client.socket_path`) with mode ``0600``.

        Only one daemon may own a socket path. A lock file next to the socket decides which of
        several that start at once wins, so a loser fails at once instead of replacing the
        winner's socket. A daemon started by systemd takes the same lock, named after the socket
        it was passed, so a client can tell that one runs without connecting to a socket that
        would start it. A daemon that binds its own socket also checks that nothing answers
        on the path, in case a systemd socket is there.

        Raises:
            AlreadyRunningError: when another daemon holds that path or listens on it.

        """
        await self.sessions.read_idle_limit()
        inherited = activated_socket(os.environ, os.getpid())
        if inherited is not None:
            for name in _ACTIVATION_VARIABLES:
                os.environ.pop(name, None)
            await self._start_activated(inherited, path)
            return
        target = path or client.socket_path(self.roots)
        await asyncio.to_thread(make_private_dirs, target.parent)
        self._lock_fd = await asyncio.to_thread(_take_lock, target)
        if await client.is_running(target):
            self._release_lock()
            message = f"valetkeyd is already running on {target}"
            raise AlreadyRunningError(message)
        try:
            self._server = await asyncio.start_unix_server(
                self._serve_connection, path=target, limit=MAX_LINE_BYTES
            )
            self._socket_path = target
            await asyncio.to_thread(target.chmod, 0o600)
        except BaseException:
            self._release_lock()
            raise
        self.sessions.start_monitor()

    async def _start_activated(self, inherited: socket.socket, path: Path | None) -> None:
        """Serve on the socket systemd passed in, holding the lock that sits next to it.

        The lock is what lets a command that must never start a daemon (see
        :func:`valetkey.client.daemon_holds_lock`) tell that this one is running. It is named
        after the inherited socket's own path, falling back to ``path`` and then the default.
        A daemon that finds the lock held leaves with an error, so ``Restart=on-failure`` and the
        start limit stop a loop instead of running two daemons.

        Raises:
            AlreadyRunningError: when another process holds the lock.

        """
        name = inherited.getsockname()
        target = Path(name) if isinstance(name, str) and name else path
        try:
            self._lock_fd = await asyncio.to_thread(
                _take_lock, target or client.socket_path(self.roots)
            )
        except BaseException:
            inherited.close()
            raise
        try:
            self._server = await asyncio.start_unix_server(
                self._serve_connection, sock=inherited, limit=MAX_LINE_BYTES, cleanup_socket=False
            )
            self.sessions.start_monitor()
        except BaseException:
            inherited.close()
            self._release_lock()
            raise

    def _release_lock(self) -> None:
        if self._lock_fd is not None:
            os.close(self._lock_fd)
            self._lock_fd = None

    async def shutdown(self) -> None:
        """Stop serving, end every session and login, and remove the socket file."""
        if self._server is not None:
            self._server.close()
        await self.sessions.stop_background()
        tasks = list(self._connections)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.gather(
            *(self.sessions.shutdown_site(s) for s in self.registry.sites.values())
        )
        if self._server is not None:
            await self._server.wait_closed()
            self._server = None
        if self._socket_path is not None:
            await asyncio.to_thread(self._socket_path.unlink, missing_ok=True)
        self._release_lock()  # after the socket file is gone

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
        connection = Connection()
        try:
            await self._exchange(connection, reader, writer)
        finally:
            for name in connection.bridges:
                self._unregister_bridge(name)

    async def _exchange(
        self, connection: Connection, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        while True:
            try:
                line = await reader.readline()
            except ValueError:  # longer than the limit; the stream cannot be resynchronised
                error = DaemonError(
                    "request_too_large", f"a request may not exceed {MAX_LINE_BYTES} bytes"
                )
                await send(writer, error_response(None, error))
                return
            if not line.endswith(b"\n"):
                return
            try:
                request = parse_request(line)
            except DaemonError as error:
                await send(writer, error_response(request_id_of(error), error))
                continue
            if request.op == "watch":
                await self._stream(reader, writer, request.id)
                return
            await send(writer, await self._dispatch(connection, request))

    async def _dispatch(self, connection: Connection, request: Request) -> bytes:
        """Return the response line for one request. Never raises."""
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

    async def _stream(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        identifier: int | str | None,
    ) -> None:
        """Answer ``watch``: a snapshot, then one answer per event, until the client goes away.

        The watcher is added before the snapshot is read, and neither step awaits, so no change
        falls between the two. A client that stops reading and falls
        :data:`valetkey.registry.WATCH_QUEUE` events behind is disconnected rather than allowed to
        hold memory.
        """
        watcher = Watcher()
        self.registry.watchers.add(watcher)
        gone = asyncio.ensure_future(reader.read())  # finishes at end-of-file: the client left
        try:
            await send(writer, ok_response(identifier, self._activity("snapshot")))
            while True:
                event = asyncio.ensure_future(watcher.queue.get())
                await asyncio.wait({event, gone}, return_when=asyncio.FIRST_COMPLETED)
                if not event.done():
                    event.cancel()
                    return
                item = event.result()
                if item is None:
                    return
                await send(writer, ok_response(identifier, item))
        finally:
            gone.cancel()
            self.registry.watchers.discard(watcher)

    def _activity(self, event: str | None = None, *, links: bool = False) -> dict[str, Any]:
        """Describe what runs now, from the registry the daemon's own processes keep.

        ``links`` adds the link of a login shown in a web browser. It is a credential, so only
        ``status`` with ``links: true`` ever asks for it.
        """
        sessions_now = []
        logins_now = []
        for name in sorted(self.registry.sites):
            state = self.registry.sites[name]
            since = state.since.strftime(TIME_FORMAT) if state.since else None
            if state.kind == "session":
                sessions_now.append(
                    {"site": name, "since": since, "contained": True, "host": state.host}
                    | self.sessions.idle_fields(state)
                )
            elif state.kind == "login":
                entry: dict[str, Any] = {"site": name, "since": since}
                if links and state.shown is not None:
                    entry["remote"] = display.describe(state.shown)
                logins_now.append(entry)
        bridges_now = [
            {"bridge": bridge.name, "since": bridge.since.strftime(TIME_FORMAT)}
            for bridge in self._bridges.values()
        ]
        result: dict[str, Any] = {
            "sessions": sessions_now,
            "logins": logins_now,
            "bridges": bridges_now,
        }
        if event is not None:
            result = {"event": event, "at": self._now().strftime(TIME_FORMAT)} | result
        return result

    # -- state --

    # -- operations: sites and policies --

    async def _op_sites(self, _connection: Connection, args: dict[str, Any]) -> dict[str, Any]:
        entries = []
        found = self.registry.known_sites()
        only: str | None = None
        if args.get("site") is not None:
            only = self.registry.site_of(args)
            if only not in found:
                await self.registry.load_policy(only)  # says that the site is not known
        for name in found:
            if only is not None and name != only:
                continue
            state = self.registry.state(name)
            try:
                policy: sites.Policy | None = await asyncio.to_thread(
                    sites.load_policy, self.roots, name
                )
            except OSError, sites.PolicyError:
                policy = None
            shown = self.registry.shown(name, found)
            entries.append(
                {
                    "site": shown,
                    "account": shown.partition(sites.ACCOUNT_SEPARATOR)[2] or None,
                    "state": state.kind,
                    "start": policy.start if policy else state.start,
                    "allow": list(policy.allow) if policy else [],
                    "excluded": list(policy.excluded) if policy else [],
                    "denied": list(policy.denied) if policy else [],
                    "learned": policy.learned.strftime("%Y-%m-%dT%H:%M:%SZ")
                    if policy and policy.learned
                    else None,
                    "summary": state.summary,
                }
            )
            state.summary = None
        return {"sites": entries}

    async def _op_reload_policy(
        self, _connection: Connection, args: dict[str, Any]
    ) -> dict[str, Any]:
        site = self.registry.site_of(args)
        policy = await self.registry.load_policy(site)
        state = self.registry.state(site)
        live = state.proxy is not None
        # The ranges may have changed: only refusals from now on say anything about them.
        state.address_hosts.clear()
        if state.proxy is not None:
            state.address_floor = state.proxy.refused_since(0)[1]
            state.proxy.update_policy(policy)
        return {
            "site": site,
            "allow": list(policy.allow),
            "excluded": list(policy.excluded),
            "denied": list(policy.denied),
            "live": live,
        }

    # -- operations: asking the person to widen a site's key --
    #
    # These are the only operations that add a host to a policy (a finished login, run by the
    # person at a window, is the other way). See the module `approvals` for the trust boundary.

    # -- operations: bridges --

    async def _op_bridge_register(
        self, connection: Connection, args: dict[str, Any]
    ) -> dict[str, Any]:
        """Record a bridge and tie it to this connection, which the caller then keeps open.

        ``rand`` names the bridge ``bridge-<rand>`` and its socket
        ``<runtime>/valetkey/bridge-<rand>.sock``. The daemon builds the path itself, and the
        socket must already be there: a real socket the user owns. Registering a name this
        connection already holds changes nothing, so the caller can repeat it. Another
        connection's name is refused. The bridge is forgotten when the connection closes.
        """
        rand = string_arg(args, "rand")
        if not _BRIDGE_RAND.fullmatch(rand):
            fail("bad_request", "rand must be 8 to 64 letters and digits")
        name = f"bridge-{rand}"
        if name in connection.bridges:
            return {"bridge": name, "registered": False}
        if name in self._bridges:
            fail("bridge_exists", f"{name} is already registered")
        path = sites.runtime_path(self.roots) / f"{name}.sock"
        try:
            found = await asyncio.to_thread(path.lstat)
        except OSError:
            found = None
        if found is None or not stat.S_ISSOCK(found.st_mode) or found.st_uid != self._uid:
            fail("no_socket", f"{path} is not a socket of this user; is the ssh forward up?")
        self._bridges[name] = _RegisteredBridge(name, path, self._now())
        connection.bridges.add(name)
        self.registry.emit("bridge_connected", bridge=name)
        return {"bridge": name, "registered": True}

    def _unregister_bridge(self, name: str) -> None:
        del self._bridges[name]
        self.registry.emit("bridge_disconnected", bridge=name)

    def bridge_sockets(self) -> list[Path]:
        """Return the sockets of the registered bridges, the newest last."""
        return [bridge.path for bridge in self._bridges.values()]

    # -- operations: login --

    async def _op_login(self, _connection: Connection, args: dict[str, Any]) -> dict[str, Any]:
        target = string_arg(args, "target")
        account = args.get("account")
        if account is not None and not isinstance(account, str):
            fail("bad_request", '"account" must be a string')
        await asyncio.to_thread(sites.system_suffixes)  # no list, no login: see SuffixListError
        site, start = await self._login_target(target, account)
        existing = await self._existing_policy(site)
        await self._refuse_private_start(site, start, existing)
        state = self.registry.state(site)
        async with state.lock:
            closed = state.kind == "session"
            if closed:
                # A login is usually wanted because the saved one expired, with the session
                # still open. Close it the way ``close`` does, but only if a window can open:
                # with no screen to use, the session is left running.
                await self._require_screen()
                await self.sessions.end(state)
            if state.kind == "login":
                fail("login_in_progress", f"a login window for {site} is already open")
            state.kind = "login"
            state.start = start
            state.began = self._now()
            try:
                state.window, state.shown = await self._open_window(
                    state, site, start, existing.private_networks if existing else ()
                )
            except Exception as error:
                state.kind = "idle"
                if closed:
                    raise _closed_for_login(error) from error
                raise
            except BaseException:
                state.kind = "idle"
                raise
            state.since = self._now()
            state.watcher = asyncio.ensure_future(self._watch_login(state, state.window))
            self.registry.emit("login_opened", site)
        result: dict[str, Any] = {"site": self.registry.shown(site), "window": "open"}
        if closed:
            result["closed_session"] = True
        if state.route == "bridge":
            result["route"] = "bridge"
        if state.shown is not None:
            result["remote"] = display.describe(state.shown)
        return result

    async def _require_screen(self) -> None:
        """Raise the login's own refusal unless some route to a login window is there.

        The routes are the person's screen, a connected bridge when the config allows one, and a
        web browser when the config allows that (see :meth:`_open_window`).

        Raises:
            login.DisplayError: when there is none, as opening the window would.

        """
        try:
            await asyncio.to_thread(self._screen_finder)
        except login.DisplayError:
            if await self._bridge_for_login() is None and not await self._novnc_enabled():
                raise

    async def _open_window(
        self, state: Site, site: str, start: str, networks: Sequence[str]
    ) -> tuple[LoginWindow, display.Display | None]:
        """Open the login window on the person's screen, or else somewhere they can reach.

        The order is this machine's own screen, then the laptop at the other end of a connected
        bridge (the ``remote_logins.waypipe`` switch in the config), then a private display that
        a web browser can view (the noVNC switch, see :mod:`valetkey.display`). With none of
        them the login's own refusal is raised. A display is returned with the window, and it
        ends with it; ``state.route`` says which of the three was used.
        """
        options: dict[str, Any] = {
            "proxy_options": self._proxy_options,
            "private_networks": networks,
        }
        finisher = self._finisher(state, start)
        state.route = "local"
        try:
            return await self._login_starter(site, start, self.roots, finisher, **options), None
        except login.DisplayError:
            bridge = await self._bridge_for_login()
            if bridge is not None:
                window = await self._login_starter(
                    site, start, self.roots, finisher, bridge=bridge, **options
                )
                state.route = "bridge"
                return window, None
            if not await self._novnc_enabled():
                raise
        shown = await self._display_starter(self.roots, site)
        try:
            window = await self._login_starter(
                site, start, self.roots, finisher, wayland_socket=shown.wayland_socket, **options
            )
        except BaseException:
            await shown.close()
            raise
        state.route = "novnc"
        return window, shown

    async def _bridge_for_login(self) -> Path | None:
        """Return the socket of the newest connected bridge, if the config allows using one."""
        try:
            enabled = (await asyncio.to_thread(approvals.load_config, self.roots)).waypipe
        except approvals.ConfigError:
            logger.warning("the config is not usable, so a login is not offered on a laptop")
            return None
        sockets = self.bridge_sockets() if enabled else []
        return sockets[-1] if sockets else None

    async def _novnc_enabled(self) -> bool:
        """Tell whether the config lets a login with no screen be shown in a web browser."""
        try:
            return (await asyncio.to_thread(approvals.load_config, self.roots)).novnc
        except approvals.ConfigError:
            logger.warning("the config is not usable, so a login is not offered in a browser")
            return False

    async def _existing_policy(self, site: str) -> sites.Policy | None:
        """Return ``site``'s policy, or ``None`` when it has none yet."""
        try:
            return await asyncio.to_thread(sites.load_policy, self.roots, site)
        except FileNotFoundError:
            return None

    async def _refuse_private_start(
        self, site: str, start: str, existing: sites.Policy | None
    ) -> None:
        """Fail early when ``start`` resolves to a private address the site may not reach.

        The login proxy would refuse it anyway, and the person would be left with a window that
        shows an error. Only the person can list a range, so the error says which command to
        run. A name that does not resolve is left to the browser to report.
        """
        host = sites.host_of(start)
        resolver = self._proxy_options.get("resolver", system_resolver)
        check = self._proxy_options.get("address_check", address_refusal)
        try:
            async with asyncio.timeout(RESOLVE_SECONDS):
                addresses = await resolver(host, 443)
        except OSError, TimeoutError:
            return
        networks = existing.private_networks if existing else ()
        if not any(
            check(address) is not None and not private_address_allowed(address, networks)
            for address in addresses
        ):
            return
        command = (
            f"valetkey allow {site} --private-network RANGE"
            if existing
            else f"valetkey add {site} {start} --private-network RANGE"
        )
        fail(
            "private_address",
            f"{host} resolves to a private address that {site} may not reach. Only the person "
            f"can allow that, for this site only: ask them to run `{command}`, with the "
            "narrowest range that holds its address (one address such as 10.20.0.7/32, or a /24), "
            "and then log in again.",
        )

    async def _login_target(self, target: str, account: str | None) -> tuple[str, str]:
        """Return the account name and start URL for a known site name, a host or a URL.

        ``account`` names another account of the site (``sitex`` and ``work`` give ``sitex:work``).
        Without it, a site with one account is that account, and a site with several must be
        named in full. A new account starts at the start URL of one the site already has.
        """
        if "." not in target and self._names_a_site(target):
            return await self._login_known(target, account)
        start = login.normalize_start_url(target)
        base = await asyncio.to_thread(sites.choose_site_name, self.roots, start)
        if account is None:
            return sites.resolve_account(self.roots, base), start
        return sites.account_name(base, account), start

    @staticmethod
    def _names_a_site(target: str) -> bool:
        """Say whether ``target`` is a site, not a host with a port such as ``intranet:8080``."""
        site, _, account = target.partition(sites.ACCOUNT_SEPARATOR)
        if account == sites.FIRST_ACCOUNT:
            return _is_site_name(site)
        return _is_site_name(target)

    async def _login_known(self, target: str, account: str | None) -> tuple[str, str]:
        if account is None:
            name = sites.resolve_account(self.roots, target)
            return name, (await self.registry.load_policy(name)).start
        site, current = sites.split_site_name(target)
        if current is not None:
            fail("bad_request", f"name the account once: {target!r} already has one")
        try:
            name = sites.account_name(site, account)
        except ValueError as error:
            fail("bad_request", str(error))
        try:
            return name, (await asyncio.to_thread(sites.load_policy, self.roots, name)).start
        except FileNotFoundError:
            pass
        accounts = [n for n in sites.known_sites(self.roots) if sites.split_site_name(n)[0] == site]
        if not accounts:
            await self.registry.load_policy(target)  # says that the site is not known
        return name, (await self.registry.load_policy(accounts[0])).start

    def _finisher(self, state: Site, start: str) -> Callable[[list[Any], Path], Awaitable[None]]:
        async def finish(seen: list[Any], profile: Path) -> None:
            try:
                if state.began is None:
                    message = "the time the login began was not recorded"
                    raise RuntimeError(message)  # noqa: TRY301 - handled below, as any failure is
                history = profile / "Default" / "History"
                navigated = await asyncio.to_thread(
                    functools.partial(learn.navigation, history, since=state.began)
                )
                classification = learn.classify(
                    start, [h.host for h in seen], navigated.shown, navigated.passed
                )
                pages: tuple[str, ...] = ()
                with contextlib.suppress(sqlite3.DatabaseError):  # the extra is optional
                    pages = await asyncio.to_thread(
                        functools.partial(learn.login_pages, history, start, since=state.began)
                    )
                try:
                    existing: sites.Policy | None = await asyncio.to_thread(
                        sites.load_policy, self.roots, state.name
                    )
                except FileNotFoundError:
                    existing = None
                own = [sites.registrable_domain(sites.host_of(start)), *classification.owned]
                signed_in = await asyncio.to_thread(
                    functools.partial(
                        cookies.recorded,
                        profile,
                        history,
                        since=state.began,
                        now=self._now(),
                        own=lambda host: sites.host_matches(host, own),
                    )
                )
                policy = learn.merge(
                    existing,
                    classification,
                    start,
                    self._now(),
                    site=state.name,
                    pages=pages,
                    login_cookies=signed_in,
                )
                await asyncio.to_thread(sites.save_policy, self.roots, policy)
            except learn.HistoryError as error:
                # The message is a fixed phrase. What the history said is in the log, never here:
                # the login browser wrote it, so it may be text meant for the agent.
                logger.warning("could not save the login for %s: %s", state.name, error)
                state.summary = f"The {state.name} login could not be saved: {error}."
                return
            except Exception:
                logger.exception("could not save the login for %s", state.name)
                state.summary = (
                    f"The {state.name} login could not be saved. The daemon's log says why."
                )
                return
            state.summary = learn.summary(policy, classification)

        return finish

    async def _watch_login(self, state: Site, window: LoginWindow) -> None:
        try:
            result = await window.wait()
            if result.private_refused:
                state.summary = _private_note(state.summary, state.name, result.private_refused)
        except Exception:
            logger.exception("login for %s failed", state.name)
        finally:
            shown, state.shown = state.shown, None
            if shown is not None:
                await shown.close()
            state.window = None
            state.kind = "idle"
            self.registry.emit("login_closed", state.name)

    # -- operations: sessions --

    async def _op_status(self, connection: Connection, args: dict[str, Any]) -> dict[str, Any]:
        if "site" not in args:
            links = args.get("links", False)
            if not isinstance(links, bool):
                fail("bad_request", '"links" must be true or false')
            return self._activity(links=links)
        site = self.registry.site_of(args)
        state = self.registry.state(site)
        if state.kind != "session":
            if state.kind == "idle":
                await self.registry.load_policy(site)
            return {"site": site, "state": state.kind, "contained": True}
        result = await self.sessions.session_op(connection, state, BrowserSession.is_alive)
        result.pop("_value")
        result["state"] = "session"
        return result


def _is_site_name(name: str) -> bool:
    try:
        sites.validate_site_name(name)
    except ValueError:
        return False
    return True


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
