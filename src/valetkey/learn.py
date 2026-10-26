# SPDX-License-Identifier: Apache-2.0
"""Turn what a login touched into the hosts a site may reach.

After a person logs in, two lists say what the login reached:

* the hosts the recording proxy saw, for any reason, and
* the hosts of the pages the browser navigated to, read from the login profile's history.

:func:`classify` splits them. The site's own domain and any host the browser navigated to (an
SSO provider, for example) are allowed. A host that only loaded in the background, such as an
image, script or beacon, is left out. :func:`merge` folds the result into the site's existing
policy without dropping hosts the person approved earlier, and :func:`summary` describes it.

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

from valetkey import sites

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = logging.getLogger(__name__)

_SIDE_FILES = ("-wal", "-journal")
_MAX_NAMED = 4
_SHOWN_WHEN_TRIMMED = 3
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

_CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def chrome_time(moment: datetime) -> int:
    """Return ``moment`` as Chromium writes a visit time: microseconds since 1601-01-01 UTC."""
    delta = moment.astimezone(UTC) - _CHROME_EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


# Core types 3 and 4 are the subframe loads. Every query takes the time the login began, as the
# integer :func:`chrome_time` gives: a profile outlives its logins, and what it recorded before
# is not what this login did.
_NAVIGATION = (
    "SELECT u.url FROM visits AS v JOIN urls AS u ON u.id = v.url "
    "WHERE (v.transition & 255) NOT IN (3, 4) AND v.visit_time >= ? LIMIT 100000"
)

# A form submission is core type 7; the visit it came from is the page that held the form.
_FORM_ORIGINS = (
    "SELECT p.url FROM visits AS v JOIN visits AS f ON f.id = v.from_visit "
    "JOIN urls AS p ON p.id = f.url "
    "WHERE (v.transition & 255) = 7 AND (f.transition & 255) NOT IN (3, 4) "
    "AND v.visit_time >= ? AND f.visit_time >= ? LIMIT 100000"
)
_LAST_PAGE = (
    "SELECT u.url FROM visits AS v JOIN urls AS u ON u.id = v.url "
    "WHERE (v.transition & 255) NOT IN (3, 4) AND v.visit_time >= ? "
    "ORDER BY v.visit_time DESC, v.id DESC LIMIT 1"
)

type Query = tuple[str, tuple[int, ...]]


@dataclass(frozen=True, slots=True)
class Classification:
    """Hosts sorted by what the login did with them.

    ``allow`` holds the site's registrable domain (covering its subdomains) and the exact hosts
    of other sites the browser navigated to. ``excluded`` holds the exact hosts that only loaded
    in the background. Both are sorted.
    """

    allow: tuple[str, ...]
    excluded: tuple[str, ...]


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


def _authorize(action: int, name: str | None, *_: object) -> int:
    """Allow a SELECT that reads the ``urls`` and ``visits`` tables, and nothing else.

    No function, no write, no setting, no attach, no other table: the queries here need none.
    """
    if action == sqlite3.SQLITE_SELECT:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ and name in _TABLES:
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _authorize_schema(action: int, name: str | None, *_: object) -> int:
    """Allow a SELECT that reads ``sqlite_master``, for the check of the schema, and no more."""
    if action == sqlite3.SQLITE_SELECT or (
        action == sqlite3.SQLITE_READ and name == "sqlite_master"
    ):
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _check_schema(database: sqlite3.Connection) -> None:
    """Refuse a database whose ``urls`` or ``visits`` is not a plain table, or that has extras.

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
    if not found >= _TABLES:
        message = "the schema lacks the tables of a history"
        raise HistoryError(message)


def _query_history(history_path: Path, *queries: Query) -> list[list[tuple[Any, ...]]]:
    """Run ``queries`` on a copy of the history database and return their rows.

    The database is copied, with its ``-wal`` and ``-journal`` files, to a temporary directory
    and opened read-only there, so a browser that still holds the live file is never disturbed.
    See the module docstring for what is done about a hostile file.

    Raises:
        HistoryError: when the file or the database cannot be trusted or read. Its message is a
            fixed phrase; the cause is logged.

    """
    try:
        with tempfile.TemporaryDirectory(prefix="valetkey-history-") as scratch:
            copy = Path(scratch) / "History"
            _copy_capped(history_path, copy, required=True)
            for side in _SIDE_FILES:
                _copy_capped(
                    history_path.with_name(history_path.name + side),
                    copy.with_name(copy.name + side),
                    required=False,
                )
            return _read(copy, queries)
    except (OSError, sqlite3.Error) as error:
        logger.warning("the history at %s could not be read: %r", history_path, error)
        raise HistoryError(_UNREADABLE) from None


def _read(copy: Path, queries: tuple[Query, ...]) -> list[list[tuple[Any, ...]]]:
    deadline = time.monotonic() + QUERY_SECONDS
    with contextlib.closing(sqlite3.connect(f"{copy.as_uri()}?mode=ro", uri=True)) as database:
        database.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)  # noqa: FBT003
        database.setconfig(sqlite3.SQLITE_DBCONFIG_TRUSTED_SCHEMA, False)  # noqa: FBT003
        database.set_progress_handler(lambda: time.monotonic() > deadline, _PROGRESS_STEP)
        database.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_BYTES)
        _check_schema(database)
        database.set_authorizer(_authorize)
        return [
            [
                (row[0][:MAX_URL] if isinstance(row[0], str) else row[0],)
                for row in database.execute(sql, params)
            ]
            for sql, params in queries
        ]


def navigation_hosts(history_path: Path, *, since: datetime) -> set[str]:
    """Return the hosts of the top-level pages a profile's history recorded since ``since``.

    ``since`` is when the login began. The profile keeps its history from one login to the next,
    so without it a host that the person removed would come back at the next login.

    A visit counts unless it is a subframe load, so each hop of a redirect chain counts. Only
    ``http`` and ``https`` pages count. A missing file gives an empty set: the profile has no
    history yet.

    Raises:
        HistoryError: when the file is not a history database, or cannot be trusted or read.

    """
    if not history_path.is_file():
        return set()
    hosts: set[str] = set()
    for (url,) in _query_history(history_path, (_NAVIGATION, (chrome_time(since),)))[0]:
        if urlsplit(url or "").scheme in {"http", "https"}:
            with contextlib.suppress(ValueError):
                hosts.add(sites.host_of(url))
    return hosts


def login_pages(history_path: Path, start_url: str, *, since: datetime) -> tuple[str, ...]:
    """Return the pages a form was submitted from during a login, as ``host/path`` keys.

    These are the pages where credentials, or a second factor, were entered: the page a
    form-submit navigation came from. That is a navigation Chromium marks as a form submission
    (core type 7), and its ``from_visit`` is the visit of the page that held the form. Sign-in
    pages are the only top-level pages that reliably have this in common across sites.

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


def classify(
    start_url: str,
    seen_hosts: Iterable[str],
    navigation_hosts: Iterable[str],
    suffixes: frozenset[str] = sites.TWO_LEVEL_SUFFIXES,
) -> Classification:
    """Sort the hosts a login reached into ``allow`` and ``excluded``.

    The registrable domain of ``start_url`` is always allowed. A host under it is covered by it.
    Any other host that was navigated to is allowed as itself, even if the proxy never saw it.
    Any other host that was only seen is excluded as itself. An IP address is never covered by
    a domain, so it follows the same rules as a third party. A host that an allowed host covers,
    or that covers an allowed host, is not listed as excluded, because an excluded entry would
    override the allowed one.
    Entries that are not plausible hosts are ignored.
    """
    domain = sites.registrable_domain(sites.host_of(start_url), suffixes)
    navigated = _hosts(navigation_hosts)
    allow = {domain}
    allow.update(host for host in navigated if not sites.host_matches(host, [domain]))
    excluded = {
        host
        for host in _hosts(seen_hosts)
        if not (sites.host_matches(host, allow) or sites.excluded_conflicts(host, allow))
    }
    return Classification(allow=tuple(sorted(allow)), excluded=tuple(sorted(excluded)))


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
) -> sites.Policy:
    """Fold ``classification`` into ``existing``, keeping everything already approved.

    ``allow`` is the union of the old and new lists. ``excluded`` is the union of the old and new
    lists minus every entry that would block an ``allow`` entry (see
    :func:`valetkey.sites.excluded_conflicts`). An excluded host under an allowed domain stays: the
    person carved it out with ``valetkey deny``. ``start`` becomes ``start_url`` and ``learned``
    becomes ``now`` in UTC, rounded down to whole seconds (``now`` must carry a time zone). The
    site name is ``existing``'s, else ``site``, else one derived from ``start_url``. ``pages`` are
    the login pages this login recorded (see :func:`login_pages`); they replace the old ones, and
    if none were recorded the old ones are kept. The person's ``private_networks`` are kept as
    they are; a login never adds to them.
    """
    old_allow = existing.allow if existing else ()
    old_excluded = existing.excluded if existing else ()
    allow = tuple(sorted({*old_allow, *classification.allow}))
    excluded = tuple(
        sorted(
            host
            for host in {*old_excluded, *classification.excluded}
            if not sites.excluded_conflicts(host, allow)
        )
    )
    name = existing.site if existing else site or sites.site_name_for(start_url)
    return sites.Policy(
        site=name,
        start=start_url,
        allow=allow,
        excluded=excluded,
        learned=now.astimezone(UTC).replace(microsecond=0),
        login_pages=tuple(sorted(set(pages))) or (existing.login_pages if existing else ()),
        private_networks=existing.private_networks if existing else (),
    )


def summary(policy: sites.Policy, classification: Classification) -> str:
    """Describe a saved login in one line: what sessions may reach and what was left out.

    Allowed hosts are named, the site's own domain first; with more than four, the first three
    are named and the rest counted. Excluded hosts from this login are counted, never named.
    """
    own = sites.registrable_domain(sites.host_of(policy.start))
    allowed = sorted(policy.allow, key=lambda host: (not sites.host_matches(host, [own]), host))
    if len(allowed) > _MAX_NAMED:
        rest = len(allowed) - _SHOWN_WHEN_TRIMMED
        named = f"{', '.join(allowed[:_SHOWN_WHEN_TRIMMED])} and {rest} more"
    elif len(allowed) > 1:
        named = f"{', '.join(allowed[:-1])} and {allowed[-1]}"
    else:
        named = allowed[0] if allowed else "no hosts"
    text = f"Saved your {policy.site} login. Sessions will be limited to {named}."
    left_out = sum(1 for host in classification.excluded if host in policy.excluded)
    if left_out:
        noun = "host" if left_out == 1 else "hosts"
        text += f" Left out {left_out} {noun} that only loaded in the background."
    return text
