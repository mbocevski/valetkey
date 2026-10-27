# SPDX-License-Identifier: Apache-2.0
"""The operations on a site's browser session: open, read, act, save, close, and keep it alive.

:class:`Sessions` starts a session behind a proxy of its own, runs a client's calls on it in worker
threads under the site's lock, ends it on ``close``, on the browser dying and on lack of use, and
tells the person when one starts. A login, which cannot run beside a session, ends the session
first (:meth:`Sessions.end`).
"""

import asyncio
import functools
import itertools
import logging
import shutil
from datetime import timedelta
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urljoin, urlsplit

from valetkey import (
    approvals,
    clicks,
    cookies,
    deltas,
    downloads,
    expiry,
    procs,
    sandbox,
    sessions,
    sites,
    treetrim,
)
from valetkey.client import DaemonError
from valetkey.protocol import BrowserSession, fail, map_error, refused_entry, string_arg, untrusted
from valetkey.proxy import Mode, Proxy
from valetkey.registry import NEWEST, TIME_FORMAT, Connection, Site, host_of, remember_refusals

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping, Sequence
    from datetime import datetime
    from pathlib import Path

    from valetkey.download_ops import Downloads
    from valetkey.registry import Registry

logger = logging.getLogger("valetkey.daemon")  # the daemon's one log


STARTUP_GRACE = 3.0
"""Seconds after a session starts during which its background refusals are not reported."""


POLL_INTERVAL = 0.5
"""Seconds between checks that each session's browser still runs."""


NOTIFY_TIMEOUT = 5.0
"""Seconds `notify-send` gets before it is killed."""


SNAPSHOT_LIMIT = 40_000
"""The most characters of a page's tree a snapshot answer holds; more is cut at a node."""


DELTA_LIMIT = 4_000
"""The most characters of changed lines (removed and added) a click or typing step reports.
Past it the answer says the page changed a lot, and the agent takes a snapshot."""


type SessionFactory = Callable[[sites.Roots, str, str, Path], BrowserSession]


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


def start_session(
    roots: sites.Roots, site: str, start_url: str, proxy_socket: Path
) -> BrowserSession:
    """Start the real session: a contained agent-browser behind the site's proxy."""
    return sessions.Session.start(
        roots, site, start_url, proxy_socket=proxy_socket, watch_browser=True
    )


def _watching(call: Callable[[BrowserSession], Any]) -> Callable[[BrowserSession], Any]:
    """Wrap ``call`` so the network log starts empty, to count the attachments it causes."""

    def run(session: BrowserSession) -> Any:  # noqa: ANN401 - whatever the call returns
        session.clear_requests()
        return call(session)

    return run


class _StartRefused(Exception):  # noqa: N818 - not an error to report: it becomes an answer
    """The browser could not load a start page because the proxy refused its host."""

    def __init__(self, answer: dict[str, Any]) -> None:
        super().__init__("the start page host is refused")
        self.answer = answer


def _refused_target(message: str, url: str | None, refused: Sequence[dict[str, Any]]) -> str | None:
    """Return the host of ``url`` when a failed navigation was the proxy refusing that host.

    The browser reports a refused HTTPS host as a failed tunnel (``ERR_TUNNEL_CONNECTION_FAILED``),
    which says nothing of the host. It was the host's refusal when the proxy refused exactly that
    host. Any other failure, or a refusal of some other host, is not this.
    """
    host = host_of(url) if url else None
    if host is None or "ERR_TUNNEL_CONNECTION_FAILED" not in message:
        return None
    return host if any(entry["host"] == host for entry in refused) else None


def cut_tree(tree: str, limit: int = SNAPSHOT_LIMIT) -> tuple[str, tuple[int, int] | None]:
    """Cut a snapshot's text to ``limit`` characters at the end of a node, one to a line.

    Returns the text that is kept and, when something was left out, how many lines and
    characters. A first line that is longer than ``limit`` is cut where it is, as the one case
    with no boundary to cut at.
    """
    if len(tree) <= limit:
        return tree, None
    lines = tree.split("\n")
    sizes = itertools.accumulate(len(line) + 1 for line in lines)  # up to each newline
    # The tree is longer than the limit, so some line is the first that does not fit.
    kept = next(n for n, size in enumerate(sizes) if size - 1 > limit)
    text = "\n".join(lines[:kept]) if kept else tree[:limit]
    return text, (len(lines) - max(kept, 1), len(tree) - len(text))


MAX_SELECTOR = 500
"""The longest CSS selector a snapshot takes, in characters."""


def _selector_arg(args: dict[str, Any]) -> str | None:
    """Return the ``selector`` argument of a snapshot, or ``None`` when there is none.

    agent-browser would read a selector that starts with a dash as one of its own options.
    """
    selector = args.get("selector")
    if selector is None:
        return None
    if (
        not isinstance(selector, str)
        or not 1 <= len(selector) <= MAX_SELECTOR
        or "\n" in selector
        or selector.startswith("-")
    ):
        fail(
            "bad_request",
            f'"selector" must be a CSS selector of 1 to {MAX_SELECTOR} characters, with no '
            'newline, that does not start with "-"',
        )
    return selector


def _add_part_of_tree(result: dict[str, Any], tree: str, start_line: int) -> None:
    """Put in ``result`` the trimmed ``tree`` from ``start_line`` on, cut to the size limit.

    ``start_line`` counts lines of the trimmed tree, which is what the agent reads. When the cut
    leaves lines out, ``cut`` says how many and which line to read on from.

    Raises:
        DaemonError: ``bad_request`` when the tree has fewer lines than ``start_line``.

    """
    lines = treetrim.trim_tree(tree).split("\n")
    if start_line > len(lines):
        message = f"The tree has {len(lines)} lines; start_line must be {len(lines)} or less."
        envelope = {k: result[k] for k in ("site", "contained", "url", "refused")}
        code = "bad_request"
        raise DaemonError(code, message, envelope)
    kept, left_out = cut_tree("\n".join(lines[start_line - 1 :]))
    result["snapshot"] = untrusted(kept)
    if left_out is not None:
        shown = len(lines) - (start_line - 1) - left_out[0]
        result["cut"] = {
            "lines": left_out[0],
            "characters": left_out[1],
            "next_line": start_line + shown,
        }


def _count_matches(session: BrowserSession, selector: str) -> int | None:
    """Count the elements ``selector`` matches, or ``None`` when that cannot be told.

    A snapshot of a selector shows the first element it matches, so the agent is told when there
    are more. The count is no reason to refuse the snapshot: a selector that is not valid fails
    in the snapshot itself, with its own message.
    """
    try:
        return session.match_count(selector)
    except sessions.AgentBrowserError, sessions.SessionError, OSError:
        logger.warning("counting the matches of a selector failed", exc_info=True)
        return None


def _start_line_arg(args: dict[str, Any]) -> int:
    """Return the ``start_line`` argument of a snapshot: the first line to read, 1 by default."""
    start = args.get("start_line", 1)
    if isinstance(start, bool) or not isinstance(start, int) or start < 1:
        fail("bad_request", '"start_line" must be a whole number, 1 or more')
    return start


def _idle_message(site: str, minutes: int) -> str:
    noun = "minute" if minutes == 1 else "minutes"
    return (
        f"The {site} session was closed after {minutes} {noun} without use. "
        "Call browser_open to start it again."
    )


def make_private_dirs(path: Path) -> None:
    """Create ``path`` and its missing parents with mode ``0700``."""
    missing = [path, *path.parents]
    for directory in reversed([d for d in missing if not d.exists()]):
        directory.mkdir(mode=0o700, exist_ok=True)
        directory.chmod(0o700)


class Sessions:
    """The session operations of the daemon, and the upkeep of the sessions they start.

    ``session_factory`` starts a session for a site, ``proxy_options`` are extra keyword
    arguments for each session's :class:`valetkey.proxy.Proxy`, ``startup_grace`` is
    :data:`STARTUP_GRACE`, ``announcer`` tells the person that a session started, and
    ``poll_interval`` is how often each session's browser is checked. ``idle_limit`` is how many
    seconds a session may go unused, instead of the config file's ``session_idle_minutes``, and
    ``idle_clock`` tells the time for it.
    """

    def __init__(  # noqa: PLR0913 - each is a seam the tests replace
        self,
        registry: Registry,
        downloads_ops: Downloads,
        *,
        session_factory: SessionFactory | None,
        proxy_options: Mapping[str, Any],
        startup_grace: float,
        announcer: Announcer | None,
        now: Callable[[], datetime],
        poll_interval: float,
        idle_limit: float | None,
        idle_clock: Callable[[], float],
    ) -> None:
        """Create the operations for the sites of ``registry``."""
        self.registry = registry
        self.downloads = downloads_ops
        self.roots = registry.roots
        self._session_factory = session_factory or start_session
        self._proxy_options = proxy_options
        self._startup_grace = startup_grace
        self._announcer = announcer or announce_session
        self._now = now
        self._poll_interval = poll_interval
        self.idle_limit = (
            approvals.DEFAULT_IDLE_MINUTES * 60.0 if idle_limit is None else idle_limit
        )
        self._idle_given = idle_limit is not None
        self._idle_clock = idle_clock
        self.monitor: asyncio.Task[None] | None = None
        self.background: set[asyncio.Task[None]] = set()

    def start_monitor(self) -> None:
        """Start the task that ends the sessions whose browser has died or that are unused."""
        self.monitor = asyncio.ensure_future(self._monitor_sessions())

    async def stop_background(self) -> None:
        """Stop the monitor and the announcements still running, and wait for them."""
        tasks = [t for t in (self.monitor, *self.background) if t is not None]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    async def shutdown_site(self, state: Site) -> None:
        """End whatever ``state`` is doing, when the daemon stops."""
        async with state.lock:
            await self.end(state)

    async def op_open(self, connection: Connection, args: dict[str, Any]) -> dict[str, Any]:
        """Answer ``open``: start the site's session, or join the one that runs."""
        site = self.registry.site_of(args)
        state = self.registry.state(site)
        async with state.lock:
            if state.kind == "login":
                fail("login_in_progress", f"a login window for {site} is open; close it first")
            if state.kind == "session" and not (state.session and state.session.is_alive()):
                await self.end(state)
            reused = state.kind == "session"
            if not reused and (gone := await self._login_cookies_gone(state)):
                return gone
            try:
                policy = None if reused else await self._begin_session(state)
            except _StartRefused as refusal:
                # No session runs: the start page's host is refused, so say so as an answer.
                return refusal.answer | {"reused": False, "page": {"title": untrusted("")}}
            session = cast("BrowserSession", state.session)
            if policy is not None:
                # The opener sees the start-up refusals, but not the background ones.
                connection.cursors[site] = (state.generation, 0, 0)
                url, title = session.first_page.url, session.first_page.title
            else:
                url, title = await asyncio.to_thread(session.current_url), ""
            result = self.registry.envelope(connection, state, url)
            if policy is not None:
                reason = await asyncio.to_thread(
                    expiry.login_expired, policy, url, session.password_fields
                )
                if reason is not None:
                    # A session on a sign-in page is no use, and would block logging in again.
                    await self.end(state)
                    result["login_expired"] = True
                    result["message"] = (
                        f"The saved login for {site} has expired: {reason}. Log in to {site} "
                        "again, then open it again."
                    )
        result["reused"] = reused
        result["page"] = {"title": untrusted(title)}
        return result

    async def _login_cookies_gone(self, state: Site) -> dict[str, Any] | None:
        """Answer an open with ``login_expired`` when the cookies of the login are gone.

        This looks at the profile before any browser starts on it (see :mod:`valetkey.cookies`),
        so nothing has yet given the site a chance to set a cookie of the same name. No browser
        is started for such a site: it would only show it logged out. ``None`` means nothing
        says the login is gone, and the open goes on.
        """
        site = state.name
        policy = await self.registry.load_policy(site)
        profile = sites.profile_path(self.roots, site)
        if not await asyncio.to_thread(
            cookies.gone, profile, policy.login_cookies, now=self._now()
        ):
            return None
        return {
            "site": self.registry.shown(site),
            "contained": True,
            "url": None,
            "refused": [],
            "background_refused": [],
            "reused": False,
            "page": {"title": untrusted("")},
            "login_expired": True,
            "message": (
                f"The saved login for {site} has expired: the cookies it set are gone. Log in "
                f"to {site} again, then open it again."
            ),
        }

    async def _begin_session(self, state: Site) -> sites.Policy:
        policy = await self.registry.load_policy(state.name)
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
        except BaseException as error:
            refused = [refused_entry(entry) for entry in proxy.refused_since(0)[0]]
            remember_refusals(state, proxy)  # so the host can be asked about, as any other
            await proxy.close()
            await asyncio.to_thread(shutil.rmtree, paths.directory, ignore_errors=True)
            host = _refused_target(str(error), policy.start, refused)
            if isinstance(error, sessions.AgentBrowserError) and host is not None:
                answer = {
                    "site": self.registry.shown(state.name),
                    "contained": True,
                    "url": policy.start,
                    "refused": refused,
                    "background_refused": [],
                    "not_loaded": host,
                }
                raise _StartRefused(answer) from error
            raise
        state.session, state.proxy, state.kind = session, proxy, "session"
        state.start = policy.start
        state.generation += 1
        state.since = self._now()
        state.idle_closed = None
        state.last_used = self._idle_clock()
        state.host = host_of(policy.start)
        self.registry.emit("session_started", state.name)
        task = asyncio.ensure_future(self._announce(state.name))
        self.background.add(task)
        task.add_done_callback(self.background.discard)
        self._end_startup_burst(state, proxy)
        return policy

    def _end_startup_burst(self, state: Site, proxy: Proxy) -> None:
        """Mark the background refusals made so far as start-up noise, after the grace period."""
        generation = state.generation
        state.quiet_floor = None

        def mark() -> None:
            if state.proxy is proxy and state.generation == generation:
                state.quiet_floor = proxy.quiet_refused_since(NEWEST)[1]

        if self._startup_grace > 0:
            asyncio.get_running_loop().call_later(self._startup_grace, mark)
        else:
            mark()

    async def end(self, state: Site, *, idle_minutes: int | None = None) -> None:
        """Stop whatever the site is doing and make it idle. The caller holds ``state.lock``.

        ``idle_minutes`` says the end is for lack of use: it is the reason in the
        ``session_ended`` event, and the next call on the site is told so. That is recorded
        before anything is closed, so a call that arrives while the session is going away, or
        just after, is told the same.
        """
        state.idle_closed = idle_minutes
        reason = "idle" if idle_minutes is not None else None
        window, watcher = state.window, state.watcher
        if window is not None:
            await window.cancel()
        if watcher is not None:
            await asyncio.gather(watcher, return_exceptions=True)
        # Once the state is cleared the session and proxy are only in the hands of this call, so
        # a cancellation (the daemon shutting down while a dead session is being ended, or a
        # client that went away) must not stop it half way and leave the proxy's socket open.
        # The shield lets it finish; a later ``_end`` waits for it on ``op_lock``.
        await asyncio.shield(self._release(state, reason))

    async def _release(self, state: Site, reason: str | None) -> None:
        """Close the site's session and proxy and forget them. See :meth:`_end`."""
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
                remember_refusals(state, proxy)
                state.address_floor = 0  # the next proxy numbers its refusals from 1
                await proxy.close()
            if session is not None or proxy is not None:
                directory = sessions.session_paths(self.roots, state.name).directory
                await asyncio.to_thread(shutil.rmtree, directory, ignore_errors=True)
            if session is not None:
                self.registry.emit("session_ended", state.name, reason=reason)

    async def op_close(self, _connection: Connection, args: dict[str, Any]) -> dict[str, Any]:
        """Answer ``close``: end the site's session or login."""
        site = self.registry.site_of(args)
        state = self.registry.state(site)
        async with state.lock:
            was = state.kind != "idle"
            await self.end(state)
        return {"site": self.registry.shown(site), "closed": was}

    async def op_snapshot(self, connection: Connection, args: dict[str, Any]) -> dict[str, Any]:
        """Answer ``snapshot``: the page as text, with a reference for each element to act on."""
        state = self.registry.state(self.registry.site_of(args))
        pictures = args.get("images", False)
        if not isinstance(pictures, bool):
            fail("bad_request", '"images" must be true or false')

        interactive = args.get("interactive", False)
        if not isinstance(interactive, bool):
            fail("bad_request", '"interactive" must be true or false')

        selector = _selector_arg(args)
        start_line = _start_line_arg(args)

        def look(
            session: BrowserSession,
        ) -> tuple[sessions.SnapshotDelta | sessions.Snapshot, list[dict[str, Any]], int | None]:
            pictures_found = session.images() if pictures else []
            if selector is not None:
                # One part of the page is not the tree later deltas change, so it leaves the
                # baseline alone.
                matches = _count_matches(session, selector)
                shown = session.snapshot(interactive=interactive, selector=selector)
                return shown, pictures_found, matches
            # In full, so that it is the whole tree and the baseline later deltas change.
            return session.snapshot_delta(interactive=interactive, full=True), pictures_found, None

        result = await self.session_op(connection, state, look)
        answer, found, matches = result.pop("_value")
        if selector is None:
            snap = cast("sessions.Snapshot", answer.snapshot)
            connection.views[state.name] = deltas.start(state.generation, interactive, answer)
        else:
            snap = cast("sessions.Snapshot", answer)
        if pictures:
            result["images"] = [
                item | {"alt": untrusted(item["alt"]), "url": untrusted(item["url"])}
                for item in found
            ]
        result["url"] = snap.url
        result["refs"] = {ref: element.role for ref, element in snap.refs.items()}
        table = {ref: (element.role, element.name) for ref, element in snap.refs.items()}
        known = connection.refs.get(state.name)
        if selector is not None:
            result["scope"] = selector
            if matches is not None and matches > 1:
                result["matches"] = matches  # a snapshot shows only the first of them
            if known is not None and known[0] == state.generation and known[2] == snap.url:
                table = known[1] | table  # the earlier refs of this page stay usable
        # The table holds the refs of the whole tree, not only of the lines shown below.
        connection.refs[state.name] = (state.generation, table, snap.url)
        _add_part_of_tree(result, snap.tree, start_line)
        return result

    async def op_click(self, connection: Connection, args: dict[str, Any]) -> dict[str, Any]:
        """Answer ``click``: a verified click, with the downloads it started."""
        state = self.registry.state(self.registry.site_of(args))
        generation, known, _url = connection.refs.get(state.name, (-1, {}, ""))
        target = clicks.build_target(args, known if generation == state.generation else {})
        expect = clicks.parse_expectation(args.get("expect"))
        seen = await self.downloads.seen_downloads(connection, state.name)
        result = await self.session_op(
            connection,
            state,
            _watching(lambda session: clicks.verified_click(session, target, expect)),
        )
        done: clicks.ClickResult = result.pop("_value")
        result["clicked"] = {"role": done.role, "name": untrusted(done.name)}
        result["attempts"] = done.attempts
        result["expect"] = done.expect.to_json() if done.expect else None
        result["outcome"] = done.outcome
        result["downloads"] = await self.downloads.new_downloads(connection, state, seen)
        await self.add_page_change(connection, state, result)
        return result

    async def add_page_change(
        self, connection: Connection, state: Site, result: dict[str, Any]
    ) -> None:
        """Put in ``result`` what the page did since this client last read it, if it can be told.

        That takes a snapshot this client has read of the live session (see
        :func:`valetkey.deltas.follow`). It asks for the same kind of tree as that snapshot did,
        so it is a delta. A failure here is no failure of the click: the answer goes without it.
        """
        view = connection.views.get(state.name)
        if view is None or view.generation != state.generation:
            return
        try:
            async with state.op_lock:
                session = state.session
                if (
                    state.kind != "session"
                    or session is None
                    or state.generation != view.generation
                ):
                    return
                answer = await asyncio.to_thread(
                    functools.partial(session.snapshot_delta, interactive=view.interactive)
                )
                title = await asyncio.to_thread(session.title) if answer.kind == "full" else ""
        except sessions.AgentBrowserError, sessions.SessionError, OSError:
            logger.warning("reading what changed on the %s page failed", state.name, exc_info=True)
            return
        known = connection.refs.get(state.name, (state.generation, {}, ""))
        table = known[1]
        change = deltas.follow(view, answer, table, DELTA_LIMIT)
        # The address stays that of the snapshot the table came from, not of where the page went.
        connection.refs[state.name] = (state.generation, table, known[2])
        if change["kind"] == "delta":
            change["removed"] = untrusted("\n".join(change["removed"]))
            change["added"] = untrusted("\n".join(change["added"]))
        if change["kind"] == "full":
            change["title"] = untrusted(title)
        result["change"] = change

    async def op_save(self, connection: Connection, args: dict[str, Any]) -> dict[str, Any]:
        """Answer ``save``: save what an address serves into the site's downloads directory."""
        state = self.registry.state(self.registry.site_of(args))
        ref, url = args.get("ref"), args.get("url")
        if (ref is None) == (url is None):
            fail("bad_request", 'give either "ref" or "url", not both and not neither')
        wanted = string_arg(args, "ref" if ref is not None else "url")
        seen = await self.downloads.seen_downloads(connection, state.name)

        folder = sites.downloads_path(self.roots, state.name)

        def fetch(session: BrowserSession) -> str:
            source = wanted if url is not None else session.resource_url(wanted)
            target = urljoin(session.current_url(), source)
            scheme = urlsplit(target).scheme
            if scheme in {"data", "blob"}:
                code = "bad_request"
                message = (
                    f"the address is a {scheme}: URL, which is the file itself held inside the "
                    "page, so there is nothing to fetch from a server"
                )
                raise DaemonError(code, message)
            if scheme not in {"http", "https"}:
                code = "bad_request"
                message = "only http and https addresses can be saved"
                raise DaemonError(code, message)
            body = session.fetch(target)
            if body is not None:
                downloads.put(folder, downloads.file_name(body.url, body.mime), body.data)
            return target

        result = await self.session_op(connection, state, _watching(fetch))
        result["source"] = untrusted(result.pop("_value"))
        found = await self.downloads.new_downloads(connection, state, seen)
        result["downloads"] = found
        if not (found["new"] or found["in_progress"] or found["unsaved"]):
            code = "not_saved"
            message = "nothing was saved: the browser did not write a file"
            envelope = {k: result[k] for k in ("site", "contained", "url", "refused")}
            raise DaemonError(code, message, envelope)
        return result

    async def op_type(self, connection: Connection, args: dict[str, Any]) -> dict[str, Any]:
        """Answer ``type``: fill a field, and press Enter if asked."""
        state = self.registry.state(self.registry.site_of(args))
        ref, text = string_arg(args, "ref"), string_arg(args, "text")
        submit = args.get("submit", False)
        if not isinstance(submit, bool):
            fail("bad_request", '"submit" must be true or false')

        def fill(session: BrowserSession) -> None:
            session.fill(ref, text)
            if submit:
                session.press_enter()

        result = await self.session_op(connection, state, fill)
        result.pop("_value")
        result["done"] = True
        result["submitted"] = submit
        await self.add_page_change(connection, state, result)
        return result

    async def op_navigate(self, connection: Connection, args: dict[str, Any]) -> dict[str, Any]:
        """Answer ``navigate``: load an address, or say that it was a download or was refused."""
        state = self.registry.state(self.registry.site_of(args))
        url = string_arg(args, "url")
        seen = await self.downloads.seen_downloads(connection, state.name)
        self.registry.skip_refusals_so_far(connection, state)
        try:
            result = await self.session_op(
                connection, state, _watching(lambda session: session.open(url))
            )
        except DaemonError as error:
            host = _refused_target(error.message, url, error.details.get("refused", []))
            if error.code == "browser_error" and host is not None:
                return error.details | {
                    "url": url,
                    "page": {"title": untrusted("")},
                    "not_loaded": host,
                }
            return await self.downloads.navigation_that_downloaded(connection, state, seen, error)
        page: sessions.Page = result.pop("_value")
        result["url"] = page.url
        result["page"] = {"title": untrusted(page.title)}
        result["downloads"] = await self.downloads.new_downloads(
            connection, state, seen, unprompted=True
        )
        return result

    async def op_screenshot(self, connection: Connection, args: dict[str, Any]) -> dict[str, Any]:
        """Answer ``screenshot``: save a picture of the page."""
        state = self.registry.state(self.registry.site_of(args))
        name = args.get("name", "screenshot.png")
        if not isinstance(name, str):
            fail("bad_request", '"name" must be a string')
        result = await self.session_op(connection, state, lambda session: session.screenshot(name))
        result["path"] = str(result.pop("_value"))
        return result

    async def session_op(
        self, connection: Connection, state: Site, call: Callable[[BrowserSession], Any]
    ) -> dict[str, Any]:
        """Run ``call`` on the site's session in a worker thread and wrap the answer.

        The returned dictionary holds the envelope and, under ``_value``, what ``call``
        returned, for the caller to shape and remove. The site counts as used until it ends.
        """
        try:
            return await self._run_session_op(connection, state, call)
        finally:
            self.registry.touch(state.name)

    async def _run_session_op(
        self, connection: Connection, state: Site, call: Callable[[BrowserSession], Any]
    ) -> dict[str, Any]:
        dead: BrowserSession | None = None
        async with state.op_lock:
            if state.kind != "session":
                if state.idle_closed is not None:
                    fail("session_idle", _idle_message(state.name, state.idle_closed))
                fail("no_session", f"{state.name} has no running session; open it first")
            session = cast("BrowserSession", state.session)
            if not session.is_alive():
                dead = session
            else:
                try:
                    value = await asyncio.to_thread(call, session)
                    url = await asyncio.to_thread(session.current_url)
                except Exception as error:
                    mapped = map_error(error)
                    mapped.details = mapped.details | self.registry.envelope(
                        connection, state, None
                    )
                    raise mapped from error
                envelope = self.registry.envelope(connection, state, url)
                envelope["_value"] = value
                return envelope
        async with state.lock:
            if state.session is dead:
                await self.end(state)
        code = "session_ended"
        message = f"the {state.name} browser has exited; open the site again"
        raise DaemonError(code, message)

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
            await self.check_sessions()

    async def check_sessions(self) -> None:
        """End the sessions whose browser has died or that nobody has used for too long.

        The host's process table is read once per check, and only when some session looks for
        its browser there, however many sessions are open.
        """
        checked = [
            (state, session)
            for state in list(self.registry.sites.values())
            if state.kind == "session" and (session := state.session) is not None
        ]
        lines = None
        if any(session.watches_browser for _, session in checked):
            try:
                lines = await asyncio.to_thread(procs.command_lines)
            except OSError:
                logger.exception("reading the process table failed")
        for state, session in checked:
            try:
                if await asyncio.to_thread(session.is_alive, lines):
                    await self._close_if_idle(state, session)
                    continue
                await self.end_if_current(state, session)
            except Exception:
                logger.exception("checking the %s session failed", state.name)

    async def _in_use(self, state: Site) -> bool:
        """Say whether something is happening on the site that keeps its session open.

        A call that is running, a question waiting for the person, or a download that is not
        finished. A login window is no session, so it never reaches here.
        """
        if state.op_lock.locked() or state.ask_lock.locked():
            return True
        paths = sessions.session_paths(self.roots, state.name)
        return await asyncio.to_thread(downloads.running, paths.incoming_dir)

    async def _close_if_idle(self, state: Site, session: BrowserSession) -> None:
        """End the session if nobody has used it for the idle limit, as ``browser_close`` would."""
        limit = self.idle_limit
        if self._idle_clock() - state.last_used < limit:
            return
        if await self._in_use(state):
            self.registry.touch(state.name)
            return
        async with state.lock:
            if state.session is not session or self._idle_clock() - state.last_used < limit:
                return
            minutes = max(1, round(limit / 60))
            logger.info("closing the %s session: unused for %d minutes", state.name, minutes)
            await self.end(state, idle_minutes=minutes)

    async def end_if_current(self, state: Site, session: BrowserSession) -> None:
        """End the site's session if it is still ``session``, not one opened in the meantime."""
        async with state.lock:
            if state.session is session:
                await self.end(state)

    def idle_fields(self, state: Site) -> dict[str, Any]:
        """Say how long the session has been unused and when that will close it."""
        limit = self.idle_limit
        idle = max(0.0, self._idle_clock() - state.last_used)
        closes = self._now() + timedelta(seconds=max(0.0, limit - idle))
        return {"idle_seconds": int(idle), "closes_at": closes.strftime(TIME_FORMAT)}

    async def read_idle_limit(self) -> None:
        """Take the idle limit from the config file, unless one was given.

        Raises:
            approvals.ConfigError: when the file is not valid, so a wrong value stops the daemon
                at start-up instead of being ignored.

        """
        if not self._idle_given:
            config = await asyncio.to_thread(approvals.load_config, self.roots)
            self.idle_limit = config.session_idle_minutes * 60.0
