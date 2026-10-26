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
* ``snapshot``, ``type`` ``{ref, text, submit?}``, ``navigate`` ``{url}``,
  ``screenshot`` ``{name?}``, ``status`` ``{site}``: act on the site's session. ``submit``
  presses Enter after the text is typed.
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
  "contained", "host"}], "logins": [{"site", "since"}], "bridges": [{"bridge", "since"}]}``, the
  first two sorted by site. ``since`` is a UTC time, ``host`` is the host of the page the
  browser was last reported at (never the whole URL, which may carry a token). It is read from
  the processes the daemon owns.
* ``watch``: the connection stays open. The first answer is ``{"event": "snapshot", "at",
  "sessions", "logins"}`` as for ``status``; then one answer per change, each
  ``{"event": "session_started" | "session_ended" | "login_opened" | "login_closed",
  "site", "at"}``, or ``{"event": "bridge_connected" | "bridge_disconnected", "bridge", "at"}``,
  all with the request's ``id``. Nothing can hide a session from it.
* ``bridge_register`` ``{rand}``: record the bridge ``bridge-<rand>``, whose socket the ssh
  connection forwards to ``<runtime>/valetkey/bridge-<rand>.sock``. The socket must already be
  there, a real socket of this user (``no_socket``), and the name must be free
  (``bridge_exists``). The caller keeps the connection open: the bridge is forgotten when it
  closes. Asking again on the same connection is harmless and answers ``registered: false``.
  See :mod:`valetkey.bridge`.
* ``close`` ``{site}``: end the site's session or login. ``{site, closed}``.
* ``reload_policy`` ``{site}``: read the policy file again and give it to the live proxy.
* ``login`` ``{target}``: ``target`` is a known site name or a host or URL. Opens a login
  window and returns at once with ``{site, window: "open"}``. When the window closes the hosts
  it reached are classified and merged into the site's policy.

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
``unknown_site``, ``unknown_ref``, ``target_not_found``, ``target_ambiguous``,
``login_in_progress``, ``private_address``, ``bridge_exists``, ``no_socket``,
``session_running``, ``no_session``, ``session_ended``, ``session_failed``,
``browser_error``, ``no_display``, ``x11_only``, ``bad_policy`` and ``internal``.

**Liveness.** A task polls every session twice a second. A session whose browser has been
killed (the holder or Chrome itself) is ended and reported within about a second, instead of the
next time a client asks. When a session starts, ``notify-send`` is run, if it exists, with the
site name; it is never waited for.

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
import fcntl
import json
import logging
import os
import re
import shutil
import signal
import socket
import sqlite3
import stat
import struct
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn, Protocol, cast
from urllib.parse import urlsplit

from valetkey import (
    approvals,
    clicks,
    client,
    downloads,
    expiry,
    learn,
    login,
    sandbox,
    sessions,
    sites,
)
from valetkey.client import MAX_LINE_BYTES, DaemonError
from valetkey.proxy import (
    NOT_ALLOWED,
    PRIVATE_ADDRESS,
    Mode,
    Proxy,
    address_refusal,
    private_address_allowed,
    system_resolver,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping

logger = logging.getLogger(__name__)

_BRIDGE_RAND = re.compile(r"[A-Za-z0-9]{8,64}")
RESOLVE_SECONDS = 10.0
"""The longest to wait for the start host of a login to resolve."""
_MAX_NAMED_HOSTS = 5
MAX_REFUSED_HOSTS = 2000
"""How many refused hosts are remembered per site."""
SD_LISTEN_FDS_START = 3
"""The first file descriptor systemd passes to a socket-activated service."""
STATES = ("idle", "login", "session")
WATCH_QUEUE = 1000
"""Events a `watch` client may fall behind by. A client further behind is disconnected."""
POLL_INTERVAL = 0.5
"""Seconds between checks that each session's browser still runs."""
NOTIFY_TIMEOUT = 5.0
"""Seconds `notify-send` gets before it is killed."""
_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_ACTIVATION_VARIABLES = ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES")
_NEWEST = 2**62
STARTUP_GRACE = 3.0
"""Seconds after a session starts during which its background refusals are not reported."""
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

    def outline(self) -> str:
        """Return the whole accessibility tree as text."""

    def click(self, ref: str) -> None:
        """Click ``ref``."""

    def password_fields(self) -> int:
        """Count the password fields on the page."""

    def clear_requests(self) -> None:
        """Forget the logged network requests."""

    def attachments(self) -> int:
        """Count the logged responses that the browser turns into downloads."""

    def press_enter(self) -> None:
        """Press Enter in the focused element."""

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
type Announcer = Callable[[str], Awaitable[None]]


async def announce_session(
    site: str,
    *,
    which: Callable[[str], str | None] = shutil.which,
    spawn: Callable[..., Awaitable[asyncio.subprocess.Process]] = asyncio.create_subprocess_exec,
) -> None:
    """Tell the person, with ``notify-send``, that a session for ``site`` started.

    Nothing happens when ``notify-send`` is not installed. Only the site name, which valetkey
    validated, goes into the message; nothing from a page does. A notification that does not
    finish in :data:`NOTIFY_TIMEOUT` seconds is killed. A failure never reaches the session; it is
    logged as one line at the information level, so a broken notification does not hide.
    """
    program = which("notify-send")
    if program is None:
        return
    message = f"valetkey: a browser session for {site} started"
    try:
        process = await spawn(
            program,
            "--app-name=valetkey",
            "--",
            message,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except OSError as error:
        logger.info("notify-send could not start: %s", error)
        return
    try:
        status = await asyncio.wait_for(process.wait(), NOTIFY_TIMEOUT)
    except TimeoutError:
        process.kill()
        await process.wait()
        logger.info("notify-send did not finish in %g seconds and was stopped", NOTIFY_TIMEOUT)
        return
    if status != 0:
        logger.info("notify-send exited with status %s, so no notification was shown", status)


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
    if isinstance(error, clicks.ClickError):
        return DaemonError(error.code, str(error), error.details)
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


def refused_entry(refusal: Any) -> dict[str, Any]:  # noqa: ANN401 - a proxy.Refusal
    """Describe one refusal for a client: the host, the port and the reason, nothing else."""
    return {"host": refusal.host, "port": refusal.port, "reason": refusal.reason}


def _watching(call: Callable[[BrowserSession], Any]) -> Callable[[BrowserSession], Any]:
    """Wrap ``call`` so the network log starts empty, to count the attachments it causes."""

    def run(session: BrowserSession) -> Any:  # noqa: ANN401 - whatever the call returns
        session.clear_requests()
        return call(session)

    return run


_ASK_OUTCOMES = {
    "no": ("denied", "The person said no."),
    "timeout": ("expired", "Nobody answered in time. You may ask again."),
    "none": ("could_not_ask", "Nobody could be asked from here. Run: {manual}"),
    "broken": ("could_not_ask", "The approval command could not run. Run: {manual}"),
}
"""How each way the approval command can end, other than yes, is reported."""


def _answer(site: str, host: str, result: str, message: str) -> dict[str, Any]:
    return {"site": site, "host": host, "result": result, "message": message}


def _allow_answer(site: str, host: str, found: approvals.Eligibility) -> dict[str, Any]:
    """Answer for a host that is not to be asked about: allowed already, or not eligible."""
    result = "allowed" if found.status == "already_allowed" else "not_eligible"
    return _answer(site, host, result, found.message)


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


def _remember_refusals(state: _Site, proxy: Proxy) -> None:
    """Note the hosts ``proxy`` refused for the policy, so they can be asked about later."""
    for refusal in proxy.refused_since(0)[0]:
        if refusal.reason == NOT_ALLOWED and len(state.refused_hosts) < MAX_REFUSED_HOSTS:
            state.refused_hosts[refusal.host] = None
        if (
            refusal.reason == PRIVATE_ADDRESS
            and refusal.seq > state.address_floor
            and len(state.address_hosts) < MAX_REFUSED_HOSTS
        ):
            state.address_hosts[refusal.host] = None


def _download_entry(item: downloads.Download) -> dict[str, Any]:
    """Describe a download for a client. The page chose the name in the path, so it is untrusted."""
    return {"path": untrusted(str(item.path)), "size": item.size, "mime": item.mime}


def make_private_dirs(path: Path) -> None:
    """Create ``path`` and its missing parents with mode ``0700``."""
    missing = [path, *path.parents]
    for directory in reversed([d for d in missing if not d.exists()]):
        directory.mkdir(mode=0o700, exist_ok=True)
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
    quiet_floor: int | None = None
    """Newest background refusal of the start-up burst; ``None`` while the burst is going on."""
    start: str = ""
    summary: str | None = None
    since: datetime | None = None
    host: str | None = None
    refused_hosts: dict[str, None] = field(default_factory=dict)
    """Hosts the proxy refused for this site because the policy did not allow them, in any
    session since the daemon started. Only these can be asked about."""
    address_hosts: dict[str, None] = field(default_factory=dict)
    """Hosts the proxy refused for the private address they resolve to, since the policy was
    last loaded. Only the person can do something about those."""
    address_floor: int = 0
    """Refusals up to this number of the live proxy predate the last reload of the policy."""
    denied_hosts: set[str] = field(default_factory=set)
    """Hosts the approval command said no to, so the agent is not allowed to ask again."""
    ask_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    """One question at a time per site."""


@dataclass(eq=False)
class _Watcher:
    """One `watch` connection: the events it has not been sent yet."""

    queue: asyncio.Queue[dict[str, Any] | None] = field(
        default_factory=lambda: asyncio.Queue(maxsize=WATCH_QUEUE)
    )


@dataclass(eq=False)
class _Connection:
    """One client connection. Refusal cursors and the last snapshot are kept here, per site."""

    cursors: dict[str, tuple[int, int, int]] = field(default_factory=dict)
    refs: dict[str, tuple[int, dict[str, tuple[str, str]]]] = field(default_factory=dict)
    """For each site, the session generation and the ``{ref: (role, name)}`` of the snapshot
    this client last received. A click by reference means the element it was in that snapshot."""
    seen_downloads: dict[str, dict[str, downloads.Signature]] = field(default_factory=dict)
    """For each site, the finished downloads this client has already been told about."""
    bridges: set[str] = field(default_factory=set)
    """The bridges this connection registered. They end with the connection."""


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
    how often each session's browser is checked.
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
        poll_interval: float = POLL_INTERVAL,
        approve_timeout: float = approvals.COMMAND_TIMEOUT,
        user_environment: Callable[[], Mapping[str, str]] = login.systemd_user_environment,
    ) -> None:
        """Create a daemon for the directories in ``roots``. Nothing listens until :func:`run`."""
        self.roots = roots
        self._approve_timeout = approve_timeout
        self._user_environment = user_environment
        self._session_factory = session_factory or start_session
        self._login_starter = login_starter
        self._proxy_options = dict(proxy_options or {})
        self._startup_grace = startup_grace
        self._peer_uid = peer_uid
        self._now = now
        self._download_settle = download_settle
        self._download_wait = download_wait
        self._announcer = announcer or announce_session
        self._poll_interval = poll_interval
        self._watchers: set[_Watcher] = set()
        self._bridges: dict[str, _RegisteredBridge] = {}
        self._monitor: asyncio.Task[None] | None = None
        self._background: set[asyncio.Task[None]] = set()
        self._uid = os.getuid()
        self._sites: dict[str, _Site] = {}
        self._connections: set[asyncio.Task[None]] = set()
        self._server: asyncio.Server | None = None
        self._socket_path: Path | None = None
        self._lock_fd: int | None = None
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
            "downloads": self._op_downloads,
            "allow_check": self._op_allow_check,
            "allow_apply": self._op_allow_apply,
            "allow_ask": self._op_allow_ask,
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
        self._monitor = asyncio.ensure_future(self._monitor_sessions())

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
            self._monitor = asyncio.ensure_future(self._monitor_sessions())
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
        for task in (self._monitor, *self._background):
            if task is not None:
                task.cancel()
        await asyncio.gather(
            *(t for t in (self._monitor, *self._background) if t is not None),
            return_exceptions=True,
        )
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
        self._release_lock()  # after the socket file is gone

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
        try:
            await self._exchange(connection, reader, writer)
        finally:
            for name in connection.bridges:
                self._unregister_bridge(name)

    async def _exchange(
        self, connection: _Connection, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
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
            try:
                request = parse_request(line)
            except DaemonError as error:
                await _send(writer, error_response(request_id_of(error), error))
                continue
            if request.op == "watch":
                await self._stream(reader, writer, request.id)
                return
            await _send(writer, await self._dispatch(connection, request))

    async def _dispatch(self, connection: _Connection, request: Request) -> bytes:
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
        falls between the two. A client that stops reading and falls :data:`WATCH_QUEUE` events
        behind is disconnected rather than allowed to hold memory.
        """
        watcher = _Watcher()
        self._watchers.add(watcher)
        gone = asyncio.ensure_future(reader.read())  # finishes at end-of-file: the client left
        try:
            await _send(writer, ok_response(identifier, self._activity("snapshot")))
            while True:
                event = asyncio.ensure_future(watcher.queue.get())
                await asyncio.wait({event, gone}, return_when=asyncio.FIRST_COMPLETED)
                if not event.done():
                    event.cancel()
                    return
                item = event.result()
                if item is None:
                    return
                await _send(writer, ok_response(identifier, item))
        finally:
            gone.cancel()
            self._watchers.discard(watcher)

    def _emit(self, event: str, site: str | None = None, *, bridge: str | None = None) -> None:
        """Tell every `watch` client that ``event`` happened to ``site`` or to ``bridge``."""
        message: dict[str, Any] = {"event": event}
        if site is not None:
            message["site"] = site
        if bridge is not None:
            message["bridge"] = bridge
        message["at"] = self._now().strftime(_TIME_FORMAT)
        for watcher in list(self._watchers):
            try:
                watcher.queue.put_nowait(message)
            except asyncio.QueueFull:
                self._watchers.discard(watcher)
                watcher.queue.get_nowait()
                watcher.queue.put_nowait(None)  # ends that client's stream

    def _activity(self, event: str | None = None) -> dict[str, Any]:
        """Describe what runs now, from the registry the daemon's own processes keep."""
        sessions_now = []
        logins_now = []
        for name in sorted(self._sites):
            state = self._sites[name]
            since = state.since.strftime(_TIME_FORMAT) if state.since else None
            if state.kind == "session":
                sessions_now.append(
                    {"site": name, "since": since, "contained": True, "host": state.host}
                )
            elif state.kind == "login":
                logins_now.append({"site": name, "since": since})
        bridges_now = [
            {"bridge": bridge.name, "since": bridge.since.strftime(_TIME_FORMAT)}
            for bridge in self._bridges.values()
        ]
        result: dict[str, Any] = {
            "sessions": sessions_now,
            "logins": logins_now,
            "bridges": bridges_now,
        }
        if event is not None:
            result = {"event": event, "at": self._now().strftime(_TIME_FORMAT)} | result
        return result

    async def _announce(self, site: str) -> None:
        """Run the announcer; a failure to tell the person never reaches the session."""
        try:
            await self._announcer(site)
        except Exception:
            logger.exception("announcing the %s session failed", site)

    async def _monitor_sessions(self) -> None:
        """End every session whose browser has died, so the registry matches the processes."""
        while True:
            await asyncio.sleep(self._poll_interval)
            for state in list(self._sites.values()):
                session = state.session
                if state.kind != "session" or session is None:
                    continue
                try:
                    if await asyncio.to_thread(session.is_alive):
                        continue
                    await self._end_if_current(state, session)
                except Exception:
                    logger.exception("checking the %s session failed", state.name)

    async def _end_if_current(self, state: _Site, session: BrowserSession) -> None:
        """End the site's session if it is still ``session``, not one opened in the meantime."""
        async with state.lock:
            if state.session is session:
                await self._end(state)

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
                    "excluded": list(policy.excluded) if policy else [],
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
        # The ranges may have changed: only refusals from now on say anything about them.
        state.address_hosts.clear()
        if state.proxy is not None:
            state.address_floor = state.proxy.refused_since(0)[1]
            state.proxy.update_policy(policy)
        return {
            "site": site,
            "allow": list(policy.allow),
            "excluded": list(policy.excluded),
            "live": live,
        }

    # -- operations: asking the person to widen a site's key --
    #
    # These are the only operations that add a host to a policy (a finished login, run by the
    # person at a window, is the other way). See the module `approvals` for the trust boundary.

    async def _eligibility(
        self, site: str, host: object
    ) -> tuple[sites.Policy, str, approvals.Eligibility]:
        try:
            name = approvals.validate_host(host)
        except ValueError as error:
            _fail("bad_request", str(error))
        policy = await self._load_policy(site)
        state = self._state(site)
        if state.proxy is not None:
            _remember_refusals(state, state.proxy)
        return (
            policy,
            name,
            approvals.eligibility(policy, name, state.refused_hosts, state.address_hosts),
        )

    async def _op_allow_check(
        self, _connection: _Connection, args: dict[str, Any]
    ) -> dict[str, Any]:
        """Say whether ``host`` may be asked about for a site, and whether the daemon can ask."""
        site = _site_arg(args)
        _policy, host, found = await self._eligibility(site, args.get("host"))
        state = self._state(site)
        return {
            "site": site,
            "host": host,
            "status": found.status,
            "message": found.message,
            "seen_during_login": found.seen_during_login,
            "denied": host in state.denied_hosts,
            "can_ask": await self._approve_command() is not None,
        }

    async def _approve_command(self) -> tuple[str, ...] | None:
        """Return the configured approval command; an unusable config counts as none."""
        try:
            return (await asyncio.to_thread(approvals.load_config, self.roots)).approve_command
        except approvals.ConfigError:
            logger.exception("config.json cannot be used")
            return None

    async def _op_allow_apply(
        self, _connection: _Connection, args: dict[str, Any]
    ) -> dict[str, Any]:
        """Grant ``host`` because the MCP client's interface returned a yes.

        The daemon takes the word of the MCP server process for it (see :mod:`approvals`). The
        host must still be eligible: refused, or excluded.
        """
        site = _site_arg(args)
        if args.get("channel") != "elicitation":
            _fail("bad_request", 'this operation is for the "elicitation" channel')
        policy, host, found = await self._eligibility(site, args.get("host"))
        if found.status != "eligible":
            return _allow_answer(site, host, found)
        return await self._grant(site, host, policy)

    async def _op_allow_ask(self, _connection: _Connection, args: dict[str, Any]) -> dict[str, Any]:
        """Ask through the approval command, and grant if it exits with status 0."""
        site = _site_arg(args)
        reason = approvals.sanitize_reason(args.get("reason"))
        state = self._state(site)
        async with state.ask_lock:
            policy, host, found = await self._eligibility(site, args.get("host"))
            if found.status != "eligible":
                return _allow_answer(site, host, found)
            if host in state.denied_hosts:
                return _answer(site, host, "denied", "The person already said no.")
            outcome = await self._consult(site, host, found.seen_during_login, reason)
            if outcome == "yes":
                return await self._grant(site, host, policy)
            if outcome == "no":
                state.denied_hosts.add(host)
            result, message = _ASK_OUTCOMES[outcome]
            return _answer(
                site, host, result, message.format(manual=approvals.manual_command(site, host))
            )

    async def _consult(self, site: str, host: str, seen: bool, reason: str) -> str:  # noqa: FBT001
        """Run the approval command and return ``yes``, ``no``, ``timeout``, ``none`` or ``broken``.

        ``none`` means no command is configured (or its config is unusable), ``broken`` that it
        could not be started.
        """
        command = await self._approve_command()
        if command is None:
            return "none"
        request = {"site": site, "host": host, "seen_during_login": seen, "reason": reason}
        env = await asyncio.to_thread(
            approvals.command_environment, os.environ, self._user_environment
        )
        try:
            return await approvals.run_command(command, request, env, self._approve_timeout)
        except OSError as error:
            logger.warning("the approval command could not run: %s", error)
            return "broken"

    async def _grant(self, site: str, host: str, policy: sites.Policy) -> dict[str, Any]:
        """Add ``host`` to the site's policy, save it, and give it to the live proxy."""
        changed, _added, _removed = sites.allow_host(policy, host)
        await asyncio.to_thread(sites.save_policy, self.roots, changed)
        state = self._state(site)
        if state.proxy is not None:
            state.proxy.update_policy(changed)
        logger.info("allowed %s for %s", host, site)
        return _answer(site, host, "allowed", f"{host} is now allowed for {site}.")

    # -- operations: bridges --

    async def _op_bridge_register(
        self, connection: _Connection, args: dict[str, Any]
    ) -> dict[str, Any]:
        """Record a bridge and tie it to this connection, which the caller then keeps open.

        ``rand`` names the bridge ``bridge-<rand>`` and its socket
        ``<runtime>/valetkey/bridge-<rand>.sock``. The daemon builds the path itself, and the
        socket must already be there: a real socket the user owns. Registering a name this
        connection already holds changes nothing, so the caller can repeat it. Another
        connection's name is refused. The bridge is forgotten when the connection closes.
        """
        rand = _string_arg(args, "rand")
        if not _BRIDGE_RAND.fullmatch(rand):
            _fail("bad_request", "rand must be 8 to 64 letters and digits")
        name = f"bridge-{rand}"
        if name in connection.bridges:
            return {"bridge": name, "registered": False}
        if name in self._bridges:
            _fail("bridge_exists", f"{name} is already registered")
        path = sites.runtime_path(self.roots) / f"{name}.sock"
        try:
            found = await asyncio.to_thread(path.lstat)
        except OSError:
            found = None
        if found is None or not stat.S_ISSOCK(found.st_mode) or found.st_uid != self._uid:
            _fail("no_socket", f"{path} is not a socket of this user; is the ssh forward up?")
        self._bridges[name] = _RegisteredBridge(name, path, self._now())
        connection.bridges.add(name)
        self._emit("bridge_connected", bridge=name)
        return {"bridge": name, "registered": True}

    def _unregister_bridge(self, name: str) -> None:
        del self._bridges[name]
        self._emit("bridge_disconnected", bridge=name)

    def bridge_sockets(self) -> list[Path]:
        """Return the sockets of the registered bridges, the newest last."""
        return [bridge.path for bridge in self._bridges.values()]

    # -- operations: login --

    async def _op_login(self, _connection: _Connection, args: dict[str, Any]) -> dict[str, Any]:
        target = _string_arg(args, "target")
        site, start = await self._login_target(target)
        existing = await self._existing_policy(site)
        await self._refuse_private_start(site, start, existing)
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
                    site,
                    start,
                    self.roots,
                    self._finisher(state, start),
                    proxy_options=self._proxy_options,
                    private_networks=existing.private_networks if existing else (),
                )
            except BaseException:
                state.kind = "idle"
                raise
            state.since = self._now()
            state.watcher = asyncio.ensure_future(self._watch_login(state, state.window))
            self._emit("login_opened", site)
        return {"site": site, "window": "open"}

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
        _fail(
            "private_address",
            f"{host} resolves to a private address that {site} may not reach. Only the person "
            f"can allow that, for this site only: ask them to run `{command}`, with the "
            "narrowest range that holds its address (one address such as 10.20.0.7/32, or a /24), "
            "and then log in again.",
        )

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
                pages: tuple[str, ...] = ()
                with contextlib.suppress(sqlite3.DatabaseError):  # the extra is optional
                    pages = await asyncio.to_thread(
                        learn.login_pages, profile / "Default" / "History", start
                    )
                try:
                    existing: sites.Policy | None = await asyncio.to_thread(
                        sites.load_policy, self.roots, state.name
                    )
                except FileNotFoundError:
                    existing = None
                policy = learn.merge(
                    existing, classification, start, self._now(), site=state.name, pages=pages
                )
                await asyncio.to_thread(sites.save_policy, self.roots, policy)
            except Exception as error:
                logger.exception("could not save the login for %s", state.name)
                state.summary = f"The {state.name} login could not be saved: {error}"
                return
            state.summary = learn.summary(policy, classification)

        return finish

    async def _watch_login(self, state: _Site, window: LoginWindow) -> None:
        try:
            result = await window.wait()
            if result.private_refused:
                state.summary = _private_note(state.summary, state.name, result.private_refused)
        except Exception:
            logger.exception("login for %s failed", state.name)
        finally:
            state.window = None
            state.kind = "idle"
            self._emit("login_closed", state.name)

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
            policy = None if reused else await self._begin_session(state)
            session = cast("BrowserSession", state.session)
            if policy is not None:
                # The opener sees the start-up refusals, but not the background ones.
                connection.cursors[site] = (state.generation, 0, 0)
                url, title = session.first_page.url, session.first_page.title
            else:
                url, title = await asyncio.to_thread(session.current_url), ""
            result = self._envelope(connection, state, url)
            if policy is not None:
                reason = await asyncio.to_thread(
                    expiry.login_expired, policy, url, session.password_fields
                )
                if reason is not None:
                    # A session on a sign-in page is no use, and would block logging in again.
                    await self._end(state)
                    result["login_expired"] = True
                    result["message"] = (
                        f"The saved login for {site} has expired: {reason}. Log in to {site} "
                        "again, then open it again."
                    )
        result["reused"] = reused
        result["page"] = {"title": untrusted(title)}
        return result

    async def _begin_session(self, state: _Site) -> sites.Policy:
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
        state.since = self._now()
        state.host = _host_of(policy.start)
        self._emit("session_started", state.name)
        task = asyncio.ensure_future(self._announce(state.name))
        self._background.add(task)
        task.add_done_callback(self._background.discard)
        self._end_startup_burst(state, proxy)
        return policy

    def _end_startup_burst(self, state: _Site, proxy: Proxy) -> None:
        """Mark the background refusals made so far as start-up noise, after the grace period."""
        generation = state.generation
        state.quiet_floor = None

        def mark() -> None:
            if state.proxy is proxy and state.generation == generation:
                state.quiet_floor = proxy.quiet_refused_since(_NEWEST)[1]

        if self._startup_grace > 0:
            asyncio.get_running_loop().call_later(self._startup_grace, mark)
        else:
            mark()

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
                paths = sessions.session_paths(self.roots, state.name)
                # The browser is gone, so what is left in its folder is finished: keep it.
                await asyncio.to_thread(downloads.sweep, paths.incoming_dir, paths.downloads_dir)
            if proxy is not None:
                _remember_refusals(state, proxy)
                state.address_floor = 0  # the next proxy numbers its refusals from 1
                await proxy.close()
            if session is not None or proxy is not None:
                directory = sessions.session_paths(self.roots, state.name).directory
                await asyncio.to_thread(shutil.rmtree, directory, ignore_errors=True)
            if session is not None:
                self._emit("session_ended", state.name)

    async def _op_close(self, _connection: _Connection, args: dict[str, Any]) -> dict[str, Any]:
        site = _site_arg(args)
        state = self._state(site)
        async with state.lock:
            was = state.kind != "idle"
            await self._end(state)
        return {"site": site, "closed": was}

    async def _op_status(self, connection: _Connection, args: dict[str, Any]) -> dict[str, Any]:
        if "site" not in args:
            return self._activity()
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
        connection.refs[state.name] = (
            state.generation,
            {ref: (element.role, element.name) for ref, element in snap.refs.items()},
        )
        return result

    async def _op_click(self, connection: _Connection, args: dict[str, Any]) -> dict[str, Any]:
        state = self._state(_site_arg(args))
        generation, known = connection.refs.get(state.name, (-1, {}))
        target = clicks.build_target(args, known if generation == state.generation else {})
        expect = clicks.parse_expectation(args.get("expect"))
        seen = await self._seen_downloads(connection, state.name)
        result = await self._session_op(
            connection,
            state,
            _watching(lambda session: clicks.verified_click(session, target, expect)),
        )
        done: clicks.ClickResult = result.pop("_value")
        result["clicked"] = {"role": done.role, "name": untrusted(done.name)}
        result["attempts"] = done.attempts
        result["expect"] = done.expect.to_json() if done.expect else None
        result["outcome"] = done.outcome
        result["downloads"] = await self._new_downloads(connection, state, seen)
        return result

    async def _op_type(self, connection: _Connection, args: dict[str, Any]) -> dict[str, Any]:
        state = self._state(_site_arg(args))
        ref, text = _string_arg(args, "ref"), _string_arg(args, "text")
        submit = args.get("submit", False)
        if not isinstance(submit, bool):
            _fail("bad_request", '"submit" must be true or false')

        def fill(session: BrowserSession) -> None:
            session.fill(ref, text)
            if submit:
                session.press_enter()

        result = await self._session_op(connection, state, fill)
        result.pop("_value")
        result["done"] = True
        result["submitted"] = submit
        return result

    async def _op_navigate(self, connection: _Connection, args: dict[str, Any]) -> dict[str, Any]:
        state = self._state(_site_arg(args))
        url = _string_arg(args, "url")
        seen = await self._seen_downloads(connection, state.name)
        try:
            result = await self._session_op(
                connection, state, _watching(lambda session: session.open(url))
            )
        except DaemonError as error:
            return await self._navigation_that_downloaded(connection, state, seen, error)
        page: sessions.Page = result.pop("_value")
        result["url"] = page.url
        result["page"] = {"title": untrusted(page.title)}
        result["downloads"] = await self._new_downloads(connection, state, seen)
        return result

    async def _navigation_that_downloaded(
        self,
        connection: _Connection,
        state: _Site,
        seen: dict[str, downloads.Signature],
        error: DaemonError,
    ) -> dict[str, Any]:
        """Turn the failure of a navigation that became a download into an answer.

        A URL that answers with an attachment is not a page: the browser aborts the navigation
        and starts a download. If a download did start, say so instead of reporting a failure;
        otherwise the failure stands.
        """
        if error.code != "browser_error" or "ERR_ABORTED" not in error.message:
            raise error
        found = await self._new_downloads(connection, state, seen, self._download_settle * 4)
        if not (found["new"] or found["in_progress"] or found["unsaved"]):
            raise error
        envelope = {k: error.details[k] for k in ("site", "contained", "url", "refused")}
        return envelope | {
            "page": {"title": untrusted("")},
            "downloads": found,
            "download_only": True,
        }

    async def _seen_downloads(
        self, connection: _Connection, site: str
    ) -> dict[str, downloads.Signature]:
        """Return the downloads this client already knows of, starting from what is there now."""
        directory = sites.downloads_path(self.roots, site)
        if site not in connection.seen_downloads:
            connection.seen_downloads[site] = await asyncio.to_thread(downloads.snapshot, directory)
        return connection.seen_downloads[site]

    async def _new_downloads(
        self,
        connection: _Connection,
        state: _Site,
        seen: dict[str, downloads.Signature],
        settle: float | None = None,
    ) -> dict[str, Any]:
        """Report the files that arrived since ``seen``, waiting a little for running ones.

        Responses logged since the call began that said ``attachment`` are the downloads the
        browser started. Any beyond the files that arrived and the ones still running are
        counted as ``unsaved``: the browser started a download and nothing was written, as it
        does when the file name is too long.
        """
        site = state.name
        paths = sessions.session_paths(self.roots, site)
        found = await asyncio.to_thread(
            downloads.collect,
            paths.downloads_dir,
            seen,
            incoming=paths.incoming_dir,
            settle=self._download_settle if settle is None else settle,
            finish=self._download_wait,
        )
        connection.seen_downloads[site] = found.seen
        started = await self._attachments(state)
        return {
            "new": [_download_entry(item) for item in found.new],
            "in_progress": [_download_entry(item) for item in found.in_progress],
            "unsaved": max(0, started - len(found.new) - len(found.in_progress)),
        }

    async def _attachments(self, state: _Site) -> int:
        """Count the responses logged since the call began that the browser turns into downloads."""
        session = state.session
        if session is None:
            return 0
        with contextlib.suppress(sessions.AgentBrowserError, sessions.SessionError):
            return await asyncio.to_thread(session.attachments)
        return 0

    async def _op_downloads(self, connection: _Connection, args: dict[str, Any]) -> dict[str, Any]:
        site = _site_arg(args)
        seen = await self._seen_downloads(connection, site)
        paths = sessions.session_paths(self.roots, site)
        found = await asyncio.to_thread(
            downloads.collect,
            paths.downloads_dir,
            seen,
            incoming=paths.incoming_dir,
            finish=self._download_wait,
        )
        connection.seen_downloads[site] = found.seen
        fresh = {item.name for item in found.new}
        files = [_download_entry(item) | {"new": item.name in fresh} for item in found.everything]
        return {
            "site": site,
            "files": files,
            "in_progress": [_download_entry(item) for item in found.in_progress],
        }

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
                    mapped.details = mapped.details | self._envelope(connection, state, None)
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
        if url is not None:
            state.host = _host_of(url) or state.host
        known = connection.cursors.get(state.name)
        if known is None or known[0] != state.generation:
            known = (
                state.generation,
                proxy.refused_since(_NEWEST)[1],
                proxy.quiet_refused_since(_NEWEST)[1],
            )
        entries, cursor = proxy.refused_since(known[1])
        quiet, quiet_cursor = proxy.quiet_refused_since(known[2])
        connection.cursors[state.name] = (state.generation, cursor, quiet_cursor)
        refused = [refused_entry(entry) for entry in entries]
        floor = state.quiet_floor
        # Until the start-up burst is over nothing is reported, and what it held never is.
        background = [] if floor is None else [r.host for r in quiet if r.seq > floor]
        counts = Counter(background)
        return {
            "site": state.name,
            "contained": True,
            "url": url,
            "refused": refused,
            "background_refused": [{"host": h, "count": n} for h, n in counts.items()],
        }


def start_session(
    roots: sites.Roots, site: str, start_url: str, proxy_socket: Path
) -> BrowserSession:
    """Start the real session: a contained agent-browser behind the site's proxy."""
    return sessions.Session.start(
        roots, site, start_url, proxy_socket=proxy_socket, watch_browser=True
    )


def _host_of(url: str) -> str | None:
    """Return the host of ``url``, or ``None`` for one that has none (``about:blank``)."""
    if urlsplit(url).scheme not in {"http", "https"}:
        return None
    try:
        return sites.host_of(url)
    except ValueError:
        return None


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
