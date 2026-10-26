# SPDX-License-Identifier: Apache-2.0
"""Refresh the vendored list of ad and tracking domains.

    python tools/update_trackers.py

Downloads Peter Lowe's "Ad and tracking server domain list" (https://pgl.yoyo.org/adservers/) in
hosts format, checks that it is what valetkey expects, writes it to
``src/valetkey/data/adservers.txt`` exactly as served, and records its SHA-256 and the date it
says it was updated in ``tools/trackers.lock``. Review the change, run the tests and commit it.
A list that does not look right (too short, or a line that is not ``127.0.0.1 DOMAIN``) writes
nothing.
"""

import hashlib
import re
import sys
import urllib.request
from typing import TYPE_CHECKING

import conventional

from valetkey import trackers

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

URL = (
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=1&mimetype=plaintext"
)
LOCK = conventional.ROOT / "tools" / "trackers.lock"
DESTINATION = conventional.ROOT / "src" / "valetkey" / trackers.DATA
MINIMUM = 1000
"""Fewer domains than this is not the list."""
TIMEOUT = 60
_UPDATED = re.compile(r"# last updated:\s+(.+)")


class UpdateError(Exception):
    """The list could not be fetched, or is not what was expected."""


def download(url: str) -> bytes:
    """Return the body of ``url``."""
    with urllib.request.urlopen(url, timeout=TIMEOUT) as response:  # noqa: S310 - HTTPS
        return response.read()


def check(text: str) -> tuple[int, str]:
    """Return how many domains ``text`` holds and the date it says it was updated.

    Raises:
        UpdateError: when it is not a list in hosts format, is too short or names no date.

    """
    try:
        count = len(trackers.parse(text))
    except ValueError as error:
        raise UpdateError(str(error)) from error
    updated = _UPDATED.search(text)
    if count < MINIMUM or updated is None:
        message = f"this is not the list: {count} domains, updated {updated and updated[1]!r}"
        raise UpdateError(message)
    return count, updated[1].strip()


def update(
    destination: Path | None = None,
    lock: Path | None = None,
    fetcher: Callable[[str], bytes] = download,
) -> tuple[int, str]:
    """Fetch, check and write the list and its lock; return the domain count and date.

    ``destination`` and ``lock`` default to the vendored list and its lock.
    """
    destination, lock = destination or DESTINATION, lock or LOCK
    body = fetcher(URL)
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as error:
        message = "the list is not UTF-8 text"
        raise UpdateError(message) from error
    count, updated = check(text)
    destination.write_bytes(body)
    lock.write_text(f"{hashlib.sha256(body).hexdigest()} {count} {updated} {URL}\n")
    return count, updated


def main(argv: list[str], fetcher: Callable[[str], bytes] = download) -> int:
    """Refresh the vendored list."""
    if argv:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        count, updated = update(fetcher=fetcher)
    except (UpdateError, OSError) as error:
        print(f"update_trackers: {error}", file=sys.stderr)
        return 1
    print(f"{count} domains, updated {updated}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
