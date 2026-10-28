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
* ``snapshot`` ``{images?, interactive?, selector?}``, ``type`` ``{ref, text, submit?}``,
  ``navigate`` ``{url}``,
  ``screenshot`` ``{name?}``, ``status`` ``{site}``: act on the site's session. ``submit``
  presses Enter after the text is typed. With ``images: true`` a ``snapshot`` answer also has
  ``images``, the biggest pictures and videos on the page, each ``{kind, alt, url, width,
  height}`` with ``alt`` and ``url`` untrusted. With ``selector``, a CSS selector, the tree is
  only the part of the page under the first element it matches, the answer has ``scope`` (the
  selector), ``matches`` (how many elements it matches, when more than one: only the first is
  shown) and its references are added to the client's table for the page; a selector that
  matches nothing is a ``browser_error``.
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
  "contained", "host", "microphone", "idle_seconds", "closes_at"}], "logins": [{"site", "since"}],
  "bridges": [{"bridge", "since"}]}``, the
  first two sorted by site. ``since`` is a UTC time, ``host`` is the host of the page the
  browser was last reported at (never the whole URL, which may carry a token). ``idle_seconds``
  is how long nothing has used the session and ``closes_at`` a UTC time: see **Idle sessions**.
  ``microphone`` is whether the session has one (see **The microphone**), and then ``capture``
  says where its capture stream is. It is read from
  the processes the daemon owns. With ``links: true`` a login shown in a web browser also has
  ``remote`` (``url``, ``port``, ``ssh``): the link is a credential, so ``watch`` never carries
  it and nothing that reaches a model asks for it.
* ``watch``: the connection stays open. The first answer is ``{"event": "snapshot", "at",
  "sessions", "logins"}`` as for ``status``; then one answer per change, each
  ``{"event": "session_started" | "session_ended" | "login_opened" | "login_closed",
  "site", "at"}`` (a ``session_ended`` caused by lack of use also has ``"reason": "idle"``, and a
  ``session_started`` has ``"microphone"``, and a ``login_closed`` lists what the window's proxy
  refused, as ``"refused"`` (at most 20 of ``{host, port, reason}``) and ``"refused_more"``), or
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

**The microphone.** A site's policy has ``microphone``, off unless the person turned it on. A
session of a site that has it on is started with a private audio graph (see
:mod:`valetkey.audio`), and ``status`` reports ``"microphone": true`` and ``capture``:
``{"socket", "directory", "node"}``, the graph's PulseAudio socket, the directory with its
PipeWire socket, and the number of the node the browser records with (``null`` while nothing
does). ``sites`` entries have ``microphone`` too. ``microphone_check`` ``{site}`` answers
``{site, enabled, can_ask}``. ``microphone_ask`` ``{site, reason}`` asks through the approval
command or a notification and answers ``{site, result, message}`` with ``allowed``, ``denied``,
``expired`` or ``could_not_ask``; a no is not remembered. ``microphone_apply`` ``{site, channel}``
turns it on because the MCP client's interface returned a yes, for the ``"elicitation"`` channel
only. A running session is not changed: the setting applies from the next one.

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
still being written, and a browser that records through the microphone (checked every poll, so
``idle_seconds`` is 0 and ``closes_at`` null meanwhile, and the limit counts from the end of the
recording). The next call that needs the session fails with ``session_idle`` and a
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
import logging
import os
import signal
import socket
import struct
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from valetkey import (
    approvals,
    client,
    display,
    downloads,
    login,
    sites,
)
from valetkey.approval_ops import Approvals, Notifier
from valetkey.client import MAX_LINE_BYTES, DaemonError
from valetkey.download_ops import Downloads
from valetkey.login_ops import DisplayStarter, Logins, LoginStarter
from valetkey.protocol import (
    BrowserSession,
    Request,
    error_response,
    fail,
    map_error,
    ok_response,
    parse_request,
    request_id_of,
    send,
)
from valetkey.registry import (
    TIME_FORMAT,
    Connection,
    Registry,
    Watcher,
)
from valetkey.scope import Scope
from valetkey.session_ops import (
    POLL_INTERVAL,
    STARTUP_GRACE,
    Announcer,
    SessionFactory,
    Sessions,
    make_private_dirs,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping

logger = logging.getLogger(__name__)

SD_LISTEN_FDS_START = 3
"""The first file descriptor systemd passes to a socket-activated service."""
STATES = ("idle", "login", "session")
_ACTIVATION_VARIABLES = ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES")
_SITE_OPS = frozenset(
    {
        "open",
        "snapshot",
        "click",
        "type",
        "navigate",
        "save",
        "screenshot",
        "console",
        "close",
        "reload_policy",
        "downloads",
        "allow_check",
        "allow_apply",
        "allow_ask",
        "deny_check",
        "deny_apply",
        "deny_ask",
        "microphone_check",
        "microphone_apply",
        "microphone_ask",
    }
)
"""The operations that name one site in ``site``, and that a scope checks before they run."""
_LISTING_OPS = frozenset({"sites", "status"})
"""The operations that list every site, or tell about one named in ``site``: a scope cuts the
list to its sites, and checks the name when there is one."""


class AlreadyRunningError(RuntimeError):
    """Another daemon already listens on the socket."""


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
        self.logins = Logins(
            self.registry,
            self.sessions,
            login_starter=login_starter,
            display_starter=display_starter,
            proxy_options=self._proxy_options,
            screen_finder=screen_finder,
            now=now,
        )
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
            "console": self.sessions.op_console,
            "status": self._op_status,
            "close": self.sessions.op_close,
            "reload_policy": self._op_reload_policy,
            "login": self.logins.op_login,
            "downloads": self.downloads.op_downloads,
            "allow_check": self.approvals.op_allow_check,
            "allow_apply": self.approvals.op_allow_apply,
            "allow_ask": self.approvals.op_allow_ask,
            "deny_check": self.approvals.op_deny_check,
            "deny_apply": self.approvals.op_deny_apply,
            "deny_ask": self.approvals.op_deny_ask,
            "microphone_check": self.approvals.op_microphone_check,
            "microphone_apply": self.approvals.op_microphone_apply,
            "microphone_ask": self.approvals.op_microphone_ask,
            "bridge_register": self.logins.op_bridge_register,
            "scope": self._op_scope,
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
                self.logins.unregister_bridge(name)

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
                await self._stream(connection, reader, writer, request.id)
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
            self._enforce_scope(connection, request)
            return ok_response(identifier, await handler(connection, request.args))
        except Exception as error:
            mapped = map_error(error)
            if mapped.code == "internal":
                logger.exception("request failed: %s", request.op)
            if mapped.code == "unknown_site" and connection.scope is not None:
                # The message lists every known site, and a scoped client may not learn them.
                allowed = connection.scope.allowed()
                mapped = DaemonError(
                    "unknown_site", f"no such site in this server's scope (allowed: {allowed})"
                )
            return error_response(identifier, mapped)

    def _enforce_scope(self, connection: Connection, request: Request) -> None:
        """Refuse a request that a connection with a scope may not make.

        Only the operations that name their site, ``sites`` and ``status`` (which list, and cut
        their answer to the scope), ``login`` (which checks the account it would use) and ``scope``
        itself pass. Anything else, such as a bridge, is refused, so an operation added later is
        closed to a scope until it is listed.
        """
        scope = connection.scope
        if scope is None or request.op in {"login", "scope"}:
            return
        if request.op not in _SITE_OPS | _LISTING_OPS:
            raise scope.refuse_operation(request.op)
        if request.op in _LISTING_OPS and request.args.get("site") is None:
            return  # a list of every site: the answer is cut to the scope
        self._require_in_scope(connection, request.args.get("site"))

    def _require_in_scope(self, connection: Connection, requested: object) -> None:
        """Raise unless the site that ``requested`` names is in the connection's scope."""
        scope = connection.scope
        assert scope is not None  # noqa: S101 - callers check
        if not isinstance(requested, str):
            return  # the operation says what is wrong with it
        try:
            name = sites.resolve_account(self.roots, requested)
        except sites.AmbiguousAccountError:
            raise scope.refusal(requested) from None
        except ValueError:
            return  # not a site name; the operation says so
        if not scope.covers(name):
            raise scope.refusal(requested)

    async def _op_scope(self, connection: Connection, args: dict[str, Any]) -> dict[str, Any]:
        """Answer ``scope``: limit this connection to ``sites``, once.

        The list holds ``site`` and ``site:account`` names. A connection that has a scope cannot
        be given another, so no request can widen it. One that has made other requests first may
        still declare one, which only narrows what it can do.
        """
        if connection.scope is not None:
            fail("scope_set", "this connection's scope is already set and cannot be changed")
        listed = args.get("sites")
        if not isinstance(listed, list):
            fail("bad_request", '"sites" must be a list of site names')
        try:
            connection.scope = Scope.parse(listed)
        except ValueError as error:
            fail("bad_request", str(error))
        return {"allowed": connection.scope.allowed()}

    async def _stream(
        self,
        connection: Connection,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        identifier: int | str | None,
    ) -> None:
        """Answer ``watch``: a snapshot, then one answer per event, until the client goes away.

        The watcher is added before the snapshot is read, and neither step awaits, so no change
        falls between the two. A client that stops reading and falls
        :data:`valetkey.registry.WATCH_QUEUE` events behind is disconnected rather than allowed to
        hold memory. A connection with a scope is sent only the sites in it.
        """
        scope = connection.scope
        watcher = Watcher()
        self.registry.watchers.add(watcher)
        gone = asyncio.ensure_future(reader.read())  # finishes at end-of-file: the client left
        try:
            first = self._activity("snapshot")
            await send(
                writer,
                ok_response(identifier, first if scope is None else scope.filter_activity(first)),
            )
            while True:
                event = asyncio.ensure_future(watcher.queue.get())
                await asyncio.wait({event, gone}, return_when=asyncio.FIRST_COMPLETED)
                if not event.done():
                    event.cancel()
                    return
                item = event.result()
                if item is None:
                    return
                if scope is None or scope.allows_event(item):
                    await send(writer, ok_response(identifier, item))
        finally:
            gone.cancel()
            self.registry.watchers.discard(watcher)

    async def _captures(self) -> dict[str, dict[str, object]]:
        """Ask each running session with the microphone where its capture stream is."""
        found: dict[str, dict[str, object]] = {}
        for name, state in list(self.registry.sites.items()):
            session = state.session
            if state.kind == "session" and state.microphone and session is not None:
                capture = await asyncio.to_thread(session.capture_stream)
                if capture is not None:
                    found[name] = capture
        return found

    def _activity(
        self,
        event: str | None = None,
        *,
        links: bool = False,
        captures: Mapping[str, dict[str, object]] | None = None,
    ) -> dict[str, Any]:
        """Describe what runs now, from the registry the daemon's own processes keep.

        ``links`` adds the link of a login shown in a web browser. It is a credential, so only
        ``status`` with ``links: true`` ever asks for it. ``captures`` are the capture streams of
        the sessions with the microphone (see :meth:`_captures`), which ``status`` adds.
        """
        sessions_now = []
        logins_now = []
        for name in sorted(self.registry.sites):
            state = self.registry.sites[name]
            since = state.since.strftime(TIME_FORMAT) if state.since else None
            if state.kind == "session":
                entry_now: dict[str, Any] = {
                    "site": name,
                    "since": since,
                    "contained": True,
                    "host": state.host,
                    "microphone": state.microphone,
                    "source": state.microphone_source,
                }
                if captures is not None and name in captures:
                    entry_now["capture"] = captures[name]
                sessions_now.append(entry_now | self.sessions.idle_fields(state))
            elif state.kind == "login":
                entry: dict[str, Any] = {"site": name, "since": since}
                if links and state.shown is not None:
                    entry["remote"] = display.describe(state.shown)
                logins_now.append(entry)
        bridges_now = [
            {"bridge": bridge.name, "since": bridge.since.strftime(TIME_FORMAT)}
            for bridge in self.logins.bridges.values()
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

    async def _op_sites(self, connection: Connection, args: dict[str, Any]) -> dict[str, Any]:
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
            if connection.scope is not None and not connection.scope.covers(name):
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
                    "microphone": policy.microphone if policy else False,
                    "microphone_source": policy.microphone_source if policy else None,
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

    # -- operations: login --

    # -- operations: sessions --

    async def _op_status(self, connection: Connection, args: dict[str, Any]) -> dict[str, Any]:
        if "site" not in args:
            links = args.get("links", False)
            if not isinstance(links, bool):
                fail("bad_request", '"links" must be true or false')
            activity = self._activity(links=links, captures=await self._captures())
            scope = connection.scope
            return activity if scope is None else scope.filter_activity(activity)
        site = self.registry.site_of(args)
        state = self.registry.state(site)
        if state.kind != "session":
            if state.kind == "idle":
                await self.registry.load_policy(site)
            return {"site": site, "state": state.kind, "contained": True}
        result = await self.sessions.session_op(connection, state, BrowserSession.is_alive)
        result.pop("_value")
        result["state"] = "session"
        result["microphone"] = state.microphone
        result["source"] = state.microphone_source
        if state.microphone and (capture := (await self._captures()).get(site)) is not None:
            result["capture"] = capture
        return result


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
