# SPDX-License-Identifier: Apache-2.0
"""Turn what a login touched into the hosts a site may reach.

After a person logs in, two lists say what the login reached:

* the hosts the recording proxy saw, for any reason, and
* the hosts of the pages the browser navigated to, read from the login profile's history.

:func:`classify` splits them. The site's own domain is allowed. So is every other host the login
reached, as itself, whether the proxy saw it, it showed a page or it only redirected: a site's CDN,
its sign-in provider and the provider's own hosts are all part of what the login used, and a
session that lost one would lose its sign-in. The exceptions are the hosts that look like ads or
tracking (:mod:`valetkey.trackers`), which are left out and counted. Only this login counts: the
history is read from the visits made since the login began, so an older visit cannot add a host.
:func:`merge` folds the result into the site's existing policy without dropping hosts the person
approved earlier and without allowing one they denied, and :func:`summary` describes it, naming the
hosts it allowed in groups and counting the ads and tracking it left out.

Chromium facts this module relies on, checked against Chromium 156.0.8078.47 by logging in
headless to a local page that redirects with HTTP 302 and reading ``<profile>/Default/History``:

* ``urls(id, url, ...)`` and ``visits(id, url, visit_time, from_visit, transition, ...)`` exist,
  and ``visits.url`` is ``urls.id``.
* ``transition`` holds a core type in the low byte (0 link, 1 typed, 2 auto bookmark, 3 auto
  subframe, 4 manual subframe, 5 generated, 6 auto top level, 7 form submit, 8 reload, 9 keyword,
  10 keyword generated) and qualifier flags above it. The typed visit was ``0x18000001`` (chain
  start) and the page it redirected to was ``0xA8000001`` (chain end, server redirect), with the
  same core type 1. SQLite returns the second one as a negative number, so the core type is read
  with ``transition & 255``, which is the same on a negative value.
* Every hop of a redirect chain has its own visit, so a host reached only through a redirect
  still shows up.
* That headless run recorded no visit for a frame inside the page. Subframe visits are the core
  types 3 and 4 in Chromium's page transition list, so they are skipped by type.
* The qualifiers say how a visit was reached: ``SERVER_REDIRECT`` (``0x80000000``) and
  ``CLIENT_REDIRECT`` (``0x40000000``) by a redirect, ``CHAIN_START`` (``0x10000000``) first in a
  chain, ``CHAIN_END`` (``0x20000000``) last. A hop that only redirects is in the middle of its
  chain, so it has no ``CHAIN_END``, and its ``visits.visit_duration`` (microseconds the page was
  open) is 0. A sign-in page the person used was a ``CHAIN_END`` with a duration of seconds.
  Measured over a sign-in provider's form (reached by redirect and by link, with the form posted
  back to the site by redirect and by an auto-submitting page), a chooser page that moved on by
  script after 0.3 s, an already signed-in provider that only redirected, a tracker bounce by
  server redirect and by meta refresh, and a host that a page's script or a server redirect sent
  the browser through.
* How a person's own navigation is recorded, measured in a login window with keys sent to it: a
  link click is ``LINK`` with ``from_visit`` set to the page; a URL typed in the address bar is
  ``TYPED`` with ``from_visit`` 0 and the ``FROM_ADDRESS_BAR`` flag (``0x02000000``); a GET form
  is ``FORM_SUBMIT`` with ``from_visit`` set. A form posted to a redirect is ``FORM_SUBMIT`` in some
  flows and ``TYPED`` in others, but always with ``from_visit`` set to the page, which a typed
  address never has. So a visit of either type that came from a page left that page by a form
  or a script, not by a link. Pages a script moves on from at once are open for 13 to 26 ms; a
  chooser page was open 300 ms; the pages a person used, seconds.
* Nothing in the history says whether the person acted on a page. A form posted to a redirect
  often leaves no form-submit visit, and the same script navigation is recorded as typed in one
  flow and as a link in another. A page that is shown for a few seconds before it moves on looks
  like a sign-in page, so this rule keeps out what redirects at once and cannot keep out a page
  made to look used. The summary names the third parties for that reason.

**The history is hostile.** The login window is a browser a website controls, and it writes the
``History`` database this module reads. A page can leave a file that is not a database at all, a
symlink or a sparse file as big as the disk, a view that never ends in place of a table, a
trigger, a schema whose names are text written to steer an agent, or millions of rows. So the
file is opened without following links, must be a regular file under :data:`MAX_BYTES`, and is
copied within that cap. The copy is opened read-only with a defensive configuration and an
authorizer that allows nothing but reading the ``urls`` and ``visits`` tables, which must be plain
tables: any view, trigger or virtual table makes the file unreadable. A time budget ends a query
that runs too long, and every query has a row limit. Whatever goes wrong becomes a
:class:`HistoryError` with a fixed message. The details, which may hold text the page chose, go to
the log and nowhere else.
"""

import contextlib
import logging
import os
import sqlite3
import stat
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from valetkey import sites, trackers

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

logger = logging.getLogger(__name__)

_SIDE_FILES = ("-wal", "-journal")
MAX_BYTES = 64 * 1024 * 1024
"""The most a history file (or one of its side files) may hold: 64 MiB. Chromium's grows with
use, but a login's profile is new and small."""
QUERY_SECONDS = 2.0
"""The time all the queries of one read share, before they are stopped."""
MAX_ROWS = 100_000
"""The most rows one query returns. A history that has more is read as far as this. The queries
below spell the number out, and a test keeps the two equal."""
MAX_URL = 4096
"""Longer addresses are cut. They are still read for their host, which comes first."""
_COPY_CHUNK = 1 << 20
_PROGRESS_STEP = 10_000
_TABLES = frozenset({"urls", "visits"})
SHOWN_MS = 2000
"""A page counts as shown when it ended its redirect chain and was open at least this long."""
LOGIN_PAGE_MS = 100
"""A page can be a sign-in page when it ended its chain and was open at least this long. Pages a
script moves on from at once are open for 26 ms or less. The query spells the number out in
microseconds, and a test keeps the two equal."""
_CHAIN_END = 0x20000000
_FLAGS = 0xFFFFFFFF
_MAX_NAMED_THIRD_PARTIES = 20

_CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def chrome_time(moment: datetime) -> int:
    """Return ``moment`` as Chromium writes a visit time: microseconds since 1601-01-01 UTC."""
    delta = moment.astimezone(UTC) - _CHROME_EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


# Core types 3 and 4 are the subframe loads. Every query takes the time the login began, as the
# integer :func:`chrome_time` gives: a profile outlives its logins, and what it recorded before
# is not what this login did.
_NAVIGATION = (
    "SELECT u.url, v.transition, v.visit_duration FROM visits AS v JOIN urls AS u ON u.id = v.url "
    "WHERE (v.transition & 255) NOT IN (3, 4) AND v.visit_time >= ? LIMIT 100000"
)

# A sign-in page is a page the person could use (it ended its chain, ``CHAIN_END``, 0x20000000 =
# 536870912) and stayed on for at least ``LOGIN_PAGE_MS`` (100000 microseconds), and that was left
# by a visit that came from it and was not a link: a form submission (core type 7) or a typed
# visit that has a ``from_visit`` (a form posted to a redirect; a typed address has none).
_FORM_ORIGINS = (
    "SELECT p.url FROM visits AS v JOIN visits AS f ON f.id = v.from_visit "
    "JOIN urls AS p ON p.id = f.url "
    "WHERE (v.transition & 255) IN (1, 7) AND (f.transition & 255) NOT IN (3, 4) "
    "AND (f.transition & 536870912) != 0 AND f.visit_duration >= 100000 "
    "AND v.visit_time >= ? AND f.visit_time >= ? LIMIT 100000"
)
_LAST_PAGE = (
    "SELECT u.url FROM visits AS v JOIN urls AS u ON u.id = v.url "
    "WHERE (v.transition & 255) NOT IN (3, 4) AND v.visit_time >= ? "
    "ORDER BY v.visit_time DESC, v.id DESC LIMIT 1"
)

_FIRST_SUBMIT = (
    "SELECT v.visit_time FROM visits AS v JOIN visits AS f ON f.id = v.from_visit "
    "WHERE (v.transition & 255) IN (1, 7) AND (f.transition & 255) NOT IN (3, 4) "
    "AND (f.transition & 536870912) != 0 AND f.visit_duration >= 100000 "
    "AND v.visit_time >= ? AND f.visit_time >= ? ORDER BY v.visit_time LIMIT 1"
)

type Query = tuple[str, tuple[int, ...]]


@dataclass(frozen=True, slots=True)
class Classification:
    """Hosts sorted by what the login did with them.

    ``allow`` holds the site's registrable domain (covering its subdomains) and the exact hosts of
    everything else the login used. ``excluded`` holds the exact hosts that look like ads or
    tracking. Both are sorted.
    """

    allow: tuple[str, ...]
    excluded: tuple[str, ...]
    owned: tuple[str, ...] = ()
    """The hosts in ``allow``, apart from the site's own domain, that have its owner by name (see
    :func:`same_owner`). The summary names them with the site's own domains."""
    tracking: tuple[str, ...] = ()
    """The hosts in ``excluded`` that look like ads or tracking (see :mod:`valetkey.trackers`).
    That is all of them, now; the field stays so that the summary reads the same way."""
    background: tuple[str, ...] = ()
    """The hosts the browser contacted on its own, for its updates (see
    :data:`valetkey.trackers.BROWSER_BACKGROUND`). They are in neither ``allow`` nor
    ``excluded``: they are not the site's, and not tracking."""


@dataclass(frozen=True, slots=True)
class Navigation:
    """The hosts of a login's top-level pages, split by whether the person was shown a page."""

    shown: frozenset[str]
    """Hosts with a page that ended its redirect chain and stayed open for :data:`SHOWN_MS`."""
    passed: frozenset[str]
    """Every other host the browser navigated to: it only redirected, or was left at once."""


class HistoryError(sqlite3.DatabaseError):
    """The login's history cannot be read, or is not to be trusted.

    The message is always the same fixed phrase. What the file said about itself is in the log.
    """


_UNREADABLE = "the login's history could not be read"


def _copy_capped(source: Path, target: Path, *, required: bool) -> bool:
    """Copy ``source`` to ``target`` without following a link and without passing the cap.

    The file is opened with ``O_NOFOLLOW`` and checked with ``fstat`` on the open file, so what
    is checked is what is read: it must be a regular file no larger than :data:`MAX_BYTES`. Bytes
    are counted as they are copied too, in case the file grows. Returns whether it was copied;
    a missing file is not copied, and is an error only when ``required``.
    """
    try:
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        if required:
            raise
        return False
    with os.fdopen(descriptor, "rb") as origin:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            message = f"{source} is not a regular file"
            raise HistoryError(message)
        if info.st_size > MAX_BYTES:
            message = f"{source} is {info.st_size} bytes, over the cap of {MAX_BYTES}"
            raise HistoryError(message)
        copied = 0
        with target.open("wb") as destination:
            while chunk := origin.read(_COPY_CHUNK):
                copied += len(chunk)
                if copied > MAX_BYTES:
                    message = f"{source} grew past the cap of {MAX_BYTES} while it was copied"
                    raise HistoryError(message)
                destination.write(chunk)
    return True


def _allow_tables(tables: frozenset[str]) -> Callable[..., int]:
    """Return a guard that allows a SELECT reading ``tables``, and nothing else.

    No function, no write, no setting, no attach, no other table: the queries here need none.
    """

    def authorize(action: int, name: str | None, *_: object) -> int:
        if action == sqlite3.SQLITE_SELECT:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ and name in tables:
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    return authorize


_authorize = _allow_tables(_TABLES)
"""The authorizer of a history: it reads the ``urls`` and ``visits`` tables."""


def _authorize_schema(action: int, name: str | None, *_: object) -> int:
    """Allow a SELECT that reads ``sqlite_master``, for the check of the schema, and no more."""
    if action == sqlite3.SQLITE_SELECT or (
        action == sqlite3.SQLITE_READ and name == "sqlite_master"
    ):
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _check_schema(database: sqlite3.Connection, tables: frozenset[str] = _TABLES) -> None:
    """Refuse a database whose ``tables`` are not plain tables, or that has extras.

    A view or trigger could run code of the page's choosing in place of a table, and a virtual
    table could be a module that does more than store rows. Chromium's history has tables and
    indexes, and the two tables are all that is read.
    """
    database.set_authorizer(_authorize_schema)
    entries = database.execute("SELECT type, name, sql FROM sqlite_master LIMIT ?", (MAX_ROWS,))
    found = set()
    for kind, name, definition in entries:
        if kind not in {"table", "index"}:
            message = f"the schema holds a {kind}"
            raise HistoryError(message)
        if kind == "table":
            found.add(name)
            if (definition or "").lstrip().upper().startswith("CREATE VIRTUAL"):
                message = f"{name} is a virtual table"
                raise HistoryError(message)
    if not found >= tables:
        message = "the schema lacks the tables that were to be read"
        raise HistoryError(message)


def _query_history(history_path: Path, *queries: Query) -> list[list[tuple[Any, ...]]]:
    """Run ``queries`` on a copy of the history database and return their rows.

    See :func:`query_database`.
    """
    return query_database(history_path, _TABLES, *queries)


def query_database(
    path: Path, tables: frozenset[str], *queries: Query
) -> list[list[tuple[Any, ...]]]:
    """Run ``queries``, which read only ``tables``, on a copy of a profile's database.

    The database is copied, with its ``-wal`` and ``-journal`` files, to a temporary directory
    and opened read-only there, so a browser that still holds the live file is never disturbed.
    See the module docstring for what is done about a hostile file; it applies to any database
    the login window wrote, such as the cookies.

    Raises:
        HistoryError: when the file or the database cannot be trusted or read. Its message is a
            fixed phrase; the cause is logged.

    """
    try:
        with tempfile.TemporaryDirectory(prefix="valetkey-history-") as scratch:
            copy = Path(scratch) / path.name
            _copy_capped(path, copy, required=True)
            for side in _SIDE_FILES:
                _copy_capped(
                    path.with_name(path.name + side),
                    copy.with_name(copy.name + side),
                    required=False,
                )
            return _read(copy, queries, tables)
    except (OSError, sqlite3.Error) as error:
        logger.warning("the database at %s could not be read: %r", path, error)
        raise HistoryError(_UNREADABLE) from None


def _read(
    copy: Path, queries: tuple[Query, ...], tables: frozenset[str] = _TABLES
) -> list[list[tuple[Any, ...]]]:
    deadline = time.monotonic() + QUERY_SECONDS
    with contextlib.closing(sqlite3.connect(f"{copy.as_uri()}?mode=ro", uri=True)) as database:
        database.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)  # noqa: FBT003
        database.setconfig(sqlite3.SQLITE_DBCONFIG_TRUSTED_SCHEMA, False)  # noqa: FBT003
        database.set_progress_handler(lambda: time.monotonic() > deadline, _PROGRESS_STEP)
        database.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_BYTES)
        _check_schema(database, tables)
        database.set_authorizer(_allow_tables(tables))
        return [
            [
                (row[0][:MAX_URL] if isinstance(row[0], str) else row[0], *row[1:])
                for row in database.execute(sql, params)
            ]
            for sql, params in queries
        ]


def as_int(value: object) -> int:
    """Return ``value`` if it is an integer, else 0: a history is not trusted to hold numbers."""
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def navigation(history_path: Path, *, since: datetime) -> Navigation:
    """Return the hosts of the top-level pages a profile's history recorded since ``since``.

    ``since`` is when the login began. The profile keeps its history from one login to the next,
    so without it a host that the person removed would come back at the next login.

    A visit counts unless it is a subframe load, so each hop of a redirect chain counts. Only
    ``http`` and ``https`` pages count. A host is ``shown`` when one of its visits ended its
    redirect chain and stayed open for :data:`SHOWN_MS` (see the module docstring), and ``passed``
    otherwise. A missing file gives nothing: the profile has no history yet.

    Raises:
        HistoryError: when the file is not a history database, or cannot be trusted or read.

    """
    if not history_path.is_file():
        return Navigation(frozenset(), frozenset())
    shown: set[str] = set()
    seen: set[str] = set()
    for url, transition, duration in _query_history(
        history_path, (_NAVIGATION, (chrome_time(since),))
    )[0]:
        if urlsplit(url or "").scheme not in {"http", "https"}:
            continue
        with contextlib.suppress(ValueError):
            host = sites.host_of(url)
            seen.add(host)
            ended = as_int(transition) & _FLAGS & _CHAIN_END
            if ended and as_int(duration) >= SHOWN_MS * 1000:
                shown.add(host)
    return Navigation(frozenset(shown), frozenset(seen - shown))


def first_submit(history_path: Path, *, since: datetime) -> int | None:
    """Return when the first form was submitted since ``since``, in Chromium's time, or ``None``.

    It is the same leaving of a page by a form that :func:`login_pages` looks for: the time of
    the first visit that came from a page the person used and was reached by a form. Cookies a
    site set before that were set to a visitor, not to a person who had signed in. A missing
    history, or none that shows a form, gives ``None``.

    Raises:
        HistoryError: when the file is not a history database, or cannot be trusted or read.

    """
    if not history_path.is_file():
        return None
    moment = chrome_time(since)
    ((*rows,),) = _query_history(history_path, (_FIRST_SUBMIT, (moment, moment)))
    return as_int(rows[0][0]) or None if rows else None


def login_pages(history_path: Path, start_url: str, *, since: datetime) -> tuple[str, ...]:
    """Return the sign-in pages of a login, as ``host/path`` keys.

    A sign-in page is a page the person could use and stayed on, that they then left by
    submitting a form and not by a link. Chromium records that leaving as a form submission
    (core type 7), or, when the form was posted to a redirect, as a typed visit that has a
    ``from_visit``: a typed address has none (see the module docstring). Only a page that ended
    its redirect chain counts, so the hops of a redirect and the callback a provider sends the
    browser through do not, and it must have been open for :data:`LOGIN_PAGE_MS`, which leaves
    out a page that submits itself.

    Two pages are left out. The start page, because a start URL that is not redirected ends on
    itself and must not look like a login page. And the page the login ended on (the last
    top-level visit), which is where a signed-in person lands. Only visits since ``since``, when
    the login began, count. A missing file gives ``()``.

    Raises:
        HistoryError: when the file is not a history database, or cannot be trusted or read.

    """
    if not history_path.is_file():
        return ()
    moment = chrome_time(since)
    origins, last = _query_history(
        history_path, (_FORM_ORIGINS, (moment, moment)), (_LAST_PAGE, (moment,))
    )
    skipped = {sites.page_key(start_url), *(sites.page_key(url or "") for (url,) in last)}
    keys = {sites.page_key(url or "") for (url,) in origins}
    return tuple(sorted(key for key in keys - skipped if key is not None))


MIN_OWNER_LABEL = 3
"""The shortest name label that makes two domains the same owner's. A shorter one (``x.com`` and
``x.org``) is too easy for someone else to register under another suffix."""


def same_owner(host: str, domain: str, suffixes: sites.SuffixList | None = None) -> bool:
    """Tell whether ``host`` belongs to whoever owns the registrable ``domain``.

    That is so when the registrable domain of ``host`` is ``domain``, or when it has the same
    name label under another suffix (``sitex.com`` and ``sitex.eu`` for ``sitex.se``), and the
    label is at least :data:`MIN_OWNER_LABEL` characters. This is a judgement on the name alone:
    nothing here proves who registered the other domain. An IP address is never the same owner.
    """
    host = sites.normalize_host(host)
    if sites.is_ip_literal(host):
        return False
    other = sites.registrable_domain(host, suffixes)
    if "." not in other or "." not in domain:
        return False
    label = domain.partition(".")[0]
    return other == domain or (len(label) >= MIN_OWNER_LABEL and other.partition(".")[0] == label)


def classify(
    start_url: str,
    seen_hosts: Iterable[str],
    shown_hosts: Iterable[str],
    passed_hosts: Iterable[str] = (),
    suffixes: sites.SuffixList | None = None,
) -> Classification:
    """Sort the hosts a login reached into ``allow`` and ``excluded``.

    The registrable domain of ``start_url`` is always allowed, and a host under it is covered by
    it. Every other host the login reached is allowed as itself: one the proxy saw
    (``seen_hosts``), and one the browser navigated to, whether it showed a page (``shown_hosts``)
    or only redirected (``passed_hosts``). The exceptions are the hosts that look like ads or
    tracking (see :mod:`valetkey.trackers`), which are excluded as themselves and counted in
    ``tracking``, and anything under the site's own domain, which is never excluded. The hosts of
    ``trackers.CONDITIONAL`` (Facebook's) count as tracking too, unless the login window navigated
    to one of them, so that signing in with Facebook still works. The hosts that
    have the site's owner by name (see :func:`same_owner`) are named in ``owned``, for the
    summary. An IP address is never covered by a domain, so it follows the rules of any other
    host. The hosts the browser contacts on its own for updates (``trackers.BROWSER_BACKGROUND``)
    are neither allowed nor excluded; they are named in ``background``. A host that another
    allowed host covers is not listed apart. An excluded host is dropped
    if it would block an allowed one. Entries that are not plausible hosts are ignored.
    """
    domain = sites.registrable_domain(sites.host_of(start_url), suffixes)
    reached = _hosts(seen_hosts) | _hosts(shown_hosts) | _hosts(passed_hosts)
    background = {host for host in reached if trackers.is_browser_background(host)}
    reached -= background
    others = {host for host in reached if not sites.host_matches(host, [domain])}
    navigated = _hosts(shown_hosts) | _hosts(passed_hosts)
    social = any(trackers.is_conditional(host) for host in navigated)
    tracking = {
        host
        for host in others
        if trackers.is_tracking(host) or (trackers.is_conditional(host) and not social)
    }
    allow = {domain} | (others - tracking)
    allow = {host for host in allow if not sites.host_matches(host, allow - {host})}
    excluded = {host for host in tracking if not sites.excluded_conflicts(host, allow)}
    return Classification(
        allow=tuple(sorted(allow)),
        excluded=tuple(sorted(excluded)),
        owned=tuple(sorted(h for h in allow - {domain} if same_owner(h, domain, suffixes))),
        tracking=tuple(sorted(excluded)),
        background=tuple(sorted(background)),
    )


def _hosts(values: Iterable[str]) -> set[str]:
    found: set[str] = set()
    for value in values:
        with contextlib.suppress(ValueError):
            found.add(sites.host_of(value))
    return found


def merge(  # noqa: PLR0913  # the last two are keyword-only extras with defaults
    existing: sites.Policy | None,
    classification: Classification,
    start_url: str,
    now: datetime,
    *,
    site: str | None = None,
    pages: Iterable[str] = (),
    login_cookies: Iterable[str] | None = None,
) -> sites.Policy:
    """Fold ``classification`` into ``existing``, keeping everything already approved.

    ``allow`` is the union of the old and new lists, except that a host an entry of the old
    ``denied`` list blocks is not added: what the person denied stays denied, and ``denied`` is
    kept as it is. ``excluded`` is built again from this login, minus every entry that would block
    an ``allow`` entry (see :func:`valetkey.sites.excluded_conflicts`); the old one is dropped,
    so a host left out before can be allowed now. ``start`` becomes ``start_url`` and ``learned``
    becomes ``now`` in UTC, rounded down to whole seconds (``now`` must carry a time zone). The
    site name is ``existing``'s, else ``site``, else one derived from ``start_url``. ``pages`` are
    the login pages this login recorded (see :func:`login_pages`); they replace the old ones, and
    if none were recorded the old ones are kept. ``login_cookies`` are the cookies this login set
    that look like its sign-in (see :mod:`valetkey.cookies`). They replace the old ones even when
    there are none, because cookies that are gone must not keep a site from opening; ``None``
    means they could not be read, and the old ones are kept. The person's
    ``private_networks`` are kept as they are; a login never adds to them.
    """
    old_allow = existing.allow if existing else ()
    old_denied = existing.denied if existing else ()
    held = {
        host
        for host in classification.allow
        if any(sites.excluded_conflicts(entry, [host]) for entry in old_denied)
    }
    allow = tuple(sorted({*old_allow, *(h for h in classification.allow if h not in held)}))
    excluded = tuple(
        sorted(
            host for host in classification.excluded if not sites.excluded_conflicts(host, allow)
        )
    )
    name = existing.site if existing else site or sites.site_name_for(start_url)
    return sites.Policy(
        site=name,
        start=start_url,
        allow=allow,
        excluded=excluded,
        denied=old_denied,
        learned=now.astimezone(UTC).replace(microsecond=0),
        login_pages=tuple(sorted(set(pages))) or (existing.login_pages if existing else ()),
        login_cookies=(
            tuple(sorted(set(login_cookies)))
            if login_cookies is not None
            else (existing.login_cookies if existing else ())
        ),
        private_networks=existing.private_networks if existing else (),
    )


def _named(hosts: Iterable[str]) -> str:
    """List ``hosts``, each shown safely; past the first twenty the rest are counted."""
    ordered = sorted(hosts)
    shown = [sites.shown_host(host) for host in ordered[:_MAX_NAMED_THIRD_PARTIES]]
    more = len(ordered) - len(shown)
    return ", ".join(shown) + (f" and {more} more" if more > 0 else "")


def summary(policy: sites.Policy, classification: Classification) -> str:
    """Describe a saved login: what sessions may reach, in groups, and what was left out.

    The hosts this login allowed are named in two groups: the site's own domains (its registrable
    domain and the hosts that have its owner by name), and the other services the pages used.
    Past twenty names the rest are counted. The `valetkey deny` command is named, for any the
    person does not want. A host that a denied entry blocks is named apart, with how to allow it.
    The ads and tracking hosts that were left out are counted, never named, and so are the hosts
    the browser contacted on its own.
    """
    own = sites.registrable_domain(sites.host_of(policy.start))
    text = (
        f"Saved your {policy.site} login. Sessions will be limited to the hosts it used, "
        "apart from ads and tracking."
    )
    new = [host for host in classification.allow if host in policy.allow]
    mine = [host for host in new if sites.host_matches(host, [own]) or host in classification.owned]
    services = [host for host in new if host not in mine]
    if mine:
        text += f" The site's own domains: {_named(mine)}."
    if services:
        text += f" Other services the pages used: {_named(services)}."
    if services or len(mine) > 1:
        text += f" Run `valetkey deny {policy.site} HOST` for any you do not want."
    held = [host for host in classification.allow if host not in policy.allow]
    if held:
        text += (
            f" Not allowed, because they are on the denied list: {_named(held)}. Run "
            f"`valetkey allow {policy.site} HOST` to allow one."
        )
    tracking = [host for host in classification.tracking if host in policy.excluded]
    if tracking:
        noun = "host" if len(tracking) == 1 else "hosts"
        text += f" Left out {len(tracking)} ads and tracking {noun}."
    if classification.background:
        noun = "host" if len(classification.background) == 1 else "hosts"
        text += (
            f" Never allowed: {len(classification.background)} {noun} the browser contacts "
            "on its own, for its updates."
        )
    return text
