# SPDX-License-Identifier: Apache-2.0
"""The daemon's registry: the state of every site, and the cursors that say what a client was told.

See :class:`Registry`. The other parts of the daemon (approvals, downloads, sessions and logins)
share one registry, and change a site only under its lock.
"""

import asyncio
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlsplit

from valetkey import deltas, display, downloads, sites
from valetkey.protocol import fail, refused_entry, string_arg
from valetkey.proxy import NOT_ALLOWED, PRIVATE_ADDRESS, Proxy

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime

    from valetkey.protocol import BrowserSession, LoginWindow

MAX_REFUSED_HOSTS = 2000
"""How many refused hosts are remembered per site."""
WATCH_QUEUE = 1000
"""Events a `watch` client may fall behind by. A client further behind is disconnected."""
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
NEWEST = 2**62
"""A cursor beyond any refusal, to ask the proxy where its history ends."""


@dataclass(eq=False)
class Site:
    """Everything the daemon holds for one site."""

    name: str
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    op_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    kind: str = "idle"
    microphone: bool = False
    """Whether the running session has the microphone: what the policy said when it started."""
    session: BrowserSession | None = None
    proxy: Proxy | None = None
    window: LoginWindow | None = None
    shown: display.Display | None = None
    route: str = "local"
    """Where the login window opened: ``local``, ``bridge`` or ``novnc``."""
    watcher: asyncio.Task[None] | None = None
    generation: int = 0
    quiet_floor: int | None = None
    """Newest background refusal of the start-up burst; ``None`` while the burst is going on."""
    start: str = ""
    summary: str | None = None
    since: datetime | None = None
    began: datetime | None = None
    """When the login window was asked for, before the browser started. What the login's history
    holds from then on is what this login did."""
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
    """Hosts the person was asked to allow and said no to, until the daemon restarts. The agent is
    not allowed to ask again."""
    kept_hosts: set[str] = field(default_factory=set)
    """Hosts the person was asked to deny and said no to, until the daemon restarts."""
    ask_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    """One question at a time per site."""
    last_used: float = 0.0
    """When a client last used the site, on the daemon's idle clock."""
    idle_closed: int | None = None
    """How many minutes unused ended the last session, until the site is opened or closed."""


@dataclass(eq=False)
class Watcher:
    """One `watch` connection: the events it has not been sent yet."""

    queue: asyncio.Queue[dict[str, Any] | None] = field(
        default_factory=lambda: asyncio.Queue(maxsize=WATCH_QUEUE)
    )


@dataclass(eq=False)
class Connection:
    """One client connection. Refusal cursors and the last snapshot are kept here, per site."""

    cursors: dict[str, tuple[int, int, int]] = field(default_factory=dict)
    refs: dict[str, tuple[int, dict[str, tuple[str, str]], str]] = field(default_factory=dict)
    """For each site, the session generation, the ``{ref: (role, name)}`` of the snapshots this
    client received of the page at ``url``, and that ``url``. A click by reference means the
    element it was in those snapshots. A snapshot of one part of the page adds to the table when
    the page is the same, and a snapshot of the whole page or of another page replaces it."""
    snapshot_kinds: dict[str, bool] = field(default_factory=dict)
    """For each site, whether this client's last snapshot asked for the interactive tree."""
    views: dict[str, deltas.View] = field(default_factory=dict)
    """For each site, the tree this client last read in a snapshot, which a delta changes."""
    seen_downloads: dict[str, dict[str, downloads.Signature]] = field(default_factory=dict)
    """For each site, the finished downloads this client has already been told about."""
    bridges: set[str] = field(default_factory=set)
    """The bridges this connection registered. They end with the connection."""


def host_of(url: str) -> str | None:
    """Return the host of ``url``, or ``None`` for one that has none (``about:blank``)."""
    if urlsplit(url).scheme not in {"http", "https"}:
        return None
    try:
        return sites.host_of(url)
    except ValueError:
        return None


def remember_refusals(state: Site, proxy: Proxy) -> None:
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


class Registry:
    """The sites the daemon knows, their locks and state, and what each client has been told.

    Every site is a :class:`Site`, created on first use. Its ``kind`` changes only under its
    ``lock``. The registry also announces changes to the ``watch`` clients (:meth:`emit`) and
    notes that a client used a site (:meth:`touch`), which keeps its session open.

    **Refusal cursors.** The proxy numbers the hosts it refuses, and keeps them. Each client
    connection holds, per site, a cursor into those numbers (:attr:`Connection.cursors`): the
    session generation it belongs to, how far it has been told of refused hosts, and how far of
    refused background hosts. :meth:`envelope` reports what is past the cursors and moves them, so
    each client is told about each refusal once, and one client asking uses up nothing that
    another has yet to see. A connection with no cursor, or one for an earlier session, starts at
    the end: it hears of what is refused from then on. :meth:`skip_refusals_so_far` moves the
    cursors to the end without reporting, for an answer that should name only what comes next.
    """

    def __init__(
        self,
        roots: sites.Roots,
        *,
        now: Callable[[], datetime],
        idle_clock: Callable[[], float],
    ) -> None:
        """Create an empty registry for the directories in ``roots``."""
        self.roots = roots
        self._now = now
        self._idle_clock = idle_clock
        self.sites: dict[str, Site] = {}
        self.watchers: set[Watcher] = set()

    def state(self, site: str) -> Site:
        """Return what the daemon holds for ``site``, creating it as idle on first use."""
        return self.sites.setdefault(site, Site(site))

    def site_of(self, args: dict[str, Any]) -> str:
        """Return the account the ``site`` argument names; a bare name must be unambiguous."""
        name = sites.resolve_account(self.roots, string_arg(args, "site"))
        self.touch(name)
        return name

    def shown(self, name: str, known: list[str] | None = None) -> str:
        """Return ``name`` as a client has to write it (see :func:`valetkey.sites.listed_name`)."""
        return sites.listed_name(name, self.known_sites() if known is None else known)

    def known_sites(self) -> list[str]:
        """Return the sites with a policy file and those the daemon is doing something with."""
        found = set(sites.known_sites(self.roots))
        return sorted(found | {n for n, s in self.sites.items() if s.kind != "idle" or s.summary})

    async def load_policy(self, site: str) -> sites.Policy:
        """Read the policy of ``site``; an unknown site fails with ``unknown_site`` and the list."""
        try:
            return await asyncio.to_thread(sites.load_policy, self.roots, site)
        except FileNotFoundError:
            found = self.known_sites()
            known = ", ".join(self.shown(n, found) for n in found) or "none yet"
            fail("unknown_site", f"no site named {site!r}; known sites: {known}")

    def touch(self, name: str) -> None:
        """Note that a client used the site, so its idle time starts again."""
        if (state := self.sites.get(name)) is not None:
            state.last_used = self._idle_clock()

    def emit(
        self,
        event: str,
        site: str | None = None,
        *,
        bridge: str | None = None,
        reason: str | None = None,
        microphone: bool | None = None,
    ) -> None:
        """Tell every `watch` client that ``event`` happened to ``site`` or to ``bridge``.

        A session that started says whether it has the microphone.
        """
        message: dict[str, Any] = {"event": event}
        if site is not None:
            message["site"] = site
        if microphone is not None:
            message["microphone"] = microphone
        if reason is not None:
            message["reason"] = reason
        if bridge is not None:
            message["bridge"] = bridge
        message["at"] = self._now().strftime(TIME_FORMAT)
        for watcher in list(self.watchers):
            try:
                watcher.queue.put_nowait(message)
            except asyncio.QueueFull:
                self.watchers.discard(watcher)
                watcher.queue.get_nowait()
                watcher.queue.put_nowait(None)  # ends that client's stream

    def envelope(self, connection: Connection, state: Site, url: str | None) -> dict[str, Any]:
        """Build the fields every session answer carries; this client's refusals are consumed.

        A connection that has not asked about the live session before starts from the refusals
        made from now on, not from the history of other clients' pages.
        """
        proxy = cast("Proxy", state.proxy)
        if url is not None:
            state.host = host_of(url) or state.host
        known = connection.cursors.get(state.name)
        if known is None or known[0] != state.generation:
            known = (
                state.generation,
                proxy.refused_since(NEWEST)[1],
                proxy.quiet_refused_since(NEWEST)[1],
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
            "site": self.shown(state.name),
            "contained": True,
            "url": url,
            "refused": refused,
            "background_refused": [{"host": h, "count": n} for h, n in counts.items()],
        }

    def skip_refusals_so_far(self, connection: Connection, state: Site) -> None:
        """Leave out of this client's next answer the refusals made until now.

        A navigation's answer should name what the new page asked for. What the old page asked
        for as it went away, such as the beacons it fires as it unloads, was refused before the
        navigation began, and is not the new page's. (Those refusals are still remembered, so the
        hosts can be asked about.)
        """
        proxy = state.proxy
        if state.kind != "session" or proxy is None:
            return
        connection.cursors[state.name] = (
            state.generation,
            proxy.refused_since(NEWEST)[1],
            proxy.quiet_refused_since(NEWEST)[1],
        )
