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
"""

import contextlib
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from valetkey import sites

if TYPE_CHECKING:
    from collections.abc import Iterable

_SIDE_FILES = ("-wal", "-journal")
_MAX_NAMED = 4
_SHOWN_WHEN_TRIMMED = 3

# Core types 3 and 4 are the subframe loads.
_QUERY = (
    "SELECT u.url FROM visits AS v JOIN urls AS u ON u.id = v.url "
    "WHERE (v.transition & 255) NOT IN (3, 4)"
)


@dataclass(frozen=True, slots=True)
class Classification:
    """Hosts sorted by what the login did with them.

    ``allow`` holds the site's registrable domain (covering its subdomains) and the exact hosts
    of other sites the browser navigated to. ``excluded`` holds the exact hosts that only loaded
    in the background. Both are sorted.
    """

    allow: tuple[str, ...]
    excluded: tuple[str, ...]


def navigation_hosts(history_path: Path) -> set[str]:
    """Return the hosts of the top-level pages a profile's history recorded.

    A visit counts unless it is a subframe load, so each hop of a redirect chain counts. Only
    ``http`` and ``https`` pages count. The database is copied, with its ``-wal`` and
    ``-journal`` files, to a temporary directory and opened read-only there, so a browser that
    still holds the live file is never disturbed. A missing file gives an empty set: the profile
    has no history yet.

    Raises:
        sqlite3.DatabaseError: when the file is not a Chromium history database.

    """
    if not history_path.is_file():
        return set()
    with tempfile.TemporaryDirectory(prefix="valetkey-history-") as scratch:
        copy = Path(scratch) / "History"
        shutil.copyfile(history_path, copy)
        for side in _SIDE_FILES:
            source = history_path.with_name(history_path.name + side)
            if source.is_file():
                shutil.copyfile(source, copy.with_name(copy.name + side))
        with contextlib.closing(sqlite3.connect(f"{copy.as_uri()}?mode=ro", uri=True)) as database:
            urls = [row[0] for row in database.execute(_QUERY)]
    hosts: set[str] = set()
    for url in urls:
        if urlsplit(url or "").scheme in {"http", "https"}:
            with contextlib.suppress(ValueError):
                hosts.add(sites.host_of(url))
    return hosts


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


def merge(
    existing: sites.Policy | None,
    classification: Classification,
    start_url: str,
    now: datetime,
    site: str | None = None,
) -> sites.Policy:
    """Fold ``classification`` into ``existing``, keeping everything already approved.

    ``allow`` is the union of the old and new lists. ``excluded`` is the union of the old and new
    lists minus every entry that would block an ``allow`` entry (see
    :func:`valetkey.sites.excluded_conflicts`). An excluded host under an allowed domain stays: the
    person carved it out with ``valetkey deny``. ``start`` becomes ``start_url`` and ``learned``
    becomes ``now`` in UTC, rounded down to whole seconds (``now`` must carry a time zone). The
    site name is ``existing``'s, else ``site``, else one derived from ``start_url``.
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
