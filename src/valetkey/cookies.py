# SPDX-License-Identifier: Apache-2.0
"""Notice that a saved login is gone from the profile, by the cookies the login set.

A site that forgets a person usually sends their browser to a sign-in page, and
:mod:`valetkey.expiry` looks for that. A site that does not, shows its front page logged out,
and the only sign is that the cookies of the login are no longer there. So when a login is saved,
the cookies it set on the site's own hosts and that look like its sign-in are recorded, by host
and name and never by value (``login_cookies`` in the policy). When the site is opened, before
the browser starts, the profile is read once more: if none of those cookies is in it, or each
has run out, the login has expired. Reading before the browser starts matters: a site often
gives every visitor an anonymous cookie of the same name, which would hide the loss.

**Which cookies.** One that the login set on the site's own domain (or a domain with the same
owner), that is ``HttpOnly`` or ``Secure``, whose name is not an analytics or consent cookie, and
that was created after the first form was submitted, when the history shows one. The history
cannot say which cookie is the sign-in, so several are kept (at most
:data:`valetkey.sites.MAX_LOGIN_COOKIES`), and the login counts as gone only when all of them
are. A site that rotates the name of one (``wordpress_logged_in_<hash>``) while another stays
raises no alarm.

**When to say nothing.** When nothing was recorded, when the database is missing or cannot be
read or trusted, and when any recorded cookie is still there and has not run out. A site that
keeps its session somewhere other than cookies is the one case this misses, or mistakes: the
recorded cookies are then harmless ones, and losing them would look like a lost login. Keeping
to cookies that look like a sign-in is the guard against that.

The database is the browser's, and a page could have tampered with it, so it is read the way the
history is: a copy, read-only, with an authorizer that allows nothing but reading its
``cookies`` table (see :func:`valetkey.learn.query_database`).
"""

import logging
import re
from typing import TYPE_CHECKING

from valetkey import learn, sites

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime
    from pathlib import Path

logger = logging.getLogger(__name__)

TABLES = frozenset({"cookies"})
DATABASE = "Default/Cookies"
"""Where Chromium keeps a profile's cookies, below the profile directory."""
MARGIN_US = 2_000_000
"""A cookie set this long before the first form was submitted still counts: the browser stamps
a cookie when it takes the response, a moment before the page it belongs to is recorded."""
IGNORED = re.compile(
    r"(?i)(_ga.*|_gid|_gat.*|_gcl_.*|_fb.*|fbp|__utm.*|_hj.*|ajs_.*|_pk_.*|_clck|_clsk|_uet.*"
    r"|mp_.*|amplitude.*|.*consent.*|optanon.*|cookie(law)?inspector.*|cb-enabled)"
)
"""Names of cookies that are never the sign-in: analytics, advertising and consent."""
_RECORDED = (
    "SELECT host_key, name, creation_utc, expires_utc, has_expires, is_secure, is_httponly "
    "FROM cookies WHERE creation_utc >= ? LIMIT 100000"
)
_PRESENT = "SELECT host_key, name, expires_utc, has_expires FROM cookies LIMIT 100000"


def database(profile: Path) -> Path:
    """Return the path of the profile's cookie database."""
    return profile / DATABASE


def entry(host: str, name: str) -> str:
    """Return how a cookie is written in the policy: its host, a space, its name."""
    return f"{host} {name}"


def recorded(
    profile: Path,
    history: Path,
    *,
    since: datetime,
    now: datetime,
    own: Callable[[str], bool],
) -> tuple[str, ...]:
    """Return the cookies to record for the login that began at ``since`` and has just ended.

    ``own`` tells whether a host is the site's own (or has its owner). A profile with no cookie
    database, or one that cannot be read, gives ``()``, and so does a history that cannot be
    read when it is needed for the first form's time.
    """
    path = database(profile)
    if not path.is_file():
        return ()
    anchor: int | None
    try:
        anchor = learn.first_submit(history, since=since)
    except learn.HistoryError:
        anchor = None
    try:
        (rows,) = learn.query_database(path, TABLES, (_RECORDED, (learn.chrome_time(since),)))
    except learn.HistoryError:
        return ()
    current = learn.chrome_time(now)
    found: set[str] = set()
    for host, name, created, expires, has_expires, secure, http_only in rows:
        if not (isinstance(host, str) and isinstance(name, str)):
            continue
        written = entry(host, name)
        if (
            (secure or http_only)
            and not IGNORED.fullmatch(name)
            and own(host.lstrip("."))
            and not (has_expires and learn.as_int(expires) <= current)
            and (anchor is None or learn.as_int(created) >= anchor - MARGIN_US)
            and sites.is_login_cookie(written)
        ):
            found.add(written)
    return tuple(sorted(found)[: sites.MAX_LOGIN_COOKIES])


def gone(profile: Path, login_cookies: tuple[str, ...], *, now: datetime) -> bool:
    """Tell whether the login is gone: none of its recorded cookies is in the profile.

    A cookie that has run out counts as not there. This is ``False`` whenever the answer is not
    certain: nothing was recorded, the database exists but cannot be read, or any recorded cookie
    is still there. A profile without a cookie database has no cookies, so the login is gone.
    """
    if not login_cookies:
        return False
    path = database(profile)
    if not path.exists():
        return True
    try:
        (rows,) = learn.query_database(path, TABLES, (_PRESENT, ()))
    except learn.HistoryError:
        return False
    current = learn.chrome_time(now)
    present = {
        entry(host, name)
        for host, name, expires, has_expires in rows
        if isinstance(host, str)
        and isinstance(name, str)
        and not (has_expires and learn.as_int(expires) <= current)
    }
    return not present.intersection(login_cookies)
