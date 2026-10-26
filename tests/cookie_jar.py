# SPDX-License-Identifier: Apache-2.0
"""A fabricated cookie database and history, in the shape Chromium 156 writes them."""

import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from valetkey import cookies, learn

if TYPE_CHECKING:
    from pathlib import Path

BEGAN = datetime(2026, 10, 26, 9, 0, 0, tzinfo=UTC)
NOW = BEGAN + timedelta(hours=2)
SUBMITTED = BEGAN + timedelta(seconds=20)
FUTURE = learn.chrome_time(NOW + timedelta(days=30))
PAST = learn.chrome_time(BEGAN - timedelta(days=1))

COOKIES_SCHEMA = """
CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
CREATE TABLE cookies(creation_utc INTEGER NOT NULL, host_key TEXT NOT NULL,
    top_frame_site_key TEXT NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
    encrypted_value BLOB NOT NULL, path TEXT NOT NULL, expires_utc INTEGER NOT NULL,
    is_secure INTEGER NOT NULL, is_httponly INTEGER NOT NULL, last_access_utc INTEGER NOT NULL,
    has_expires INTEGER NOT NULL, is_persistent INTEGER NOT NULL, priority INTEGER NOT NULL,
    samesite INTEGER NOT NULL, source_scheme INTEGER NOT NULL, source_port INTEGER NOT NULL,
    last_update_utc INTEGER NOT NULL, source_type INTEGER NOT NULL,
    has_cross_site_ancestor INTEGER NOT NULL);
"""
HISTORY_SCHEMA = """
CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT, url LONGVARCHAR, title LONGVARCHAR,
    visit_count INTEGER DEFAULT 0 NOT NULL, typed_count INTEGER DEFAULT 0 NOT NULL,
    last_visit_time INTEGER NOT NULL, hidden INTEGER DEFAULT 0 NOT NULL);
CREATE TABLE visits(id INTEGER PRIMARY KEY AUTOINCREMENT, url INTEGER NOT NULL,
    visit_time INTEGER NOT NULL, from_visit INTEGER, transition INTEGER DEFAULT 0 NOT NULL,
    visit_duration INTEGER DEFAULT 0 NOT NULL);
"""


def cookie(  # noqa: PLR0913 - a row of the table
    host: str,
    name: str,
    *,
    created: datetime = SUBMITTED + timedelta(seconds=1),
    expires: int | None = None,
    secure: bool = False,
    http_only: bool = True,
) -> tuple[object, ...]:
    return (
        learn.chrome_time(created),
        host,
        "",
        name,
        "",
        b"v10x",
        "/",
        expires or 0,
        int(secure),
        int(http_only),
        0,
        int(expires is not None),
        int(expires is not None),
        1,
        -1,
        2,
        443,
        learn.chrome_time(created),
        0,
        0,
    )


def jar(profile: Path, *rows: tuple[object, ...]) -> Path:
    path = cookies.database(profile)
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as database:
        database.executescript(COOKIES_SCHEMA)
        marks = ",".join("?" * 20)
        database.executemany(f"INSERT INTO cookies VALUES ({marks})", rows)  # noqa: S608
        database.commit()
    return path


def history_with_a_form(profile: Path) -> Path:
    """A history whose first form was submitted at ``SUBMITTED``."""
    path = profile / "Default" / "History"
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as database:
        database.executescript(HISTORY_SCHEMA)
        visits = [
            (1, "http://sitex.com/login", 0, 0x30000001, 6450_000, BEGAN + timedelta(seconds=5)),
            (2, "http://sitex.com/home", 1, 0x30000007, 3700_000, SUBMITTED),
        ]
        for number, url, origin, transition, duration, when in visits:
            database.execute(
                "INSERT INTO urls(id, url, last_visit_time) VALUES (?, ?, 1)", (number, url)
            )
            database.execute(
                "INSERT INTO visits(id, url, visit_time, from_visit, transition, visit_duration)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (number, number, learn.chrome_time(when), origin or None, transition, duration),
            )
        database.commit()
    return path
