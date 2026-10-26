# SPDX-License-Identifier: Apache-2.0
"""What valetkey tells the browser about a site's profile before it starts.

The profile is the one place a login lives: the login window writes it, and every later session
reads it. A cookie that a site sets without an expiry is a session cookie, and Chromium forgets
it when it exits unless the profile says "continue where you left off". A site that signs a
person in until the browser is closed sets exactly that, so without the setting a login that
worked in the window is gone in the next browser. Chromium also reads the saved cookies back
only when it starts with the same setting, so the login window and the sessions both get it.

Continuing where it left off would also bring back the tabs of the last run, which a login window
and a session do not want: each starts at the page it was asked for. So the saved tabs are removed
when the profile is prepared; the cookies are not among them.

The browser writes the file this module edits, inside the sandbox, so the file is not trusted:
it is read without following a link and within a size limit, and a file that is not the JSON
object Chromium writes is replaced.
"""

import contextlib
import json
import os
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any

MAX_BYTES = 16 * 1024 * 1024
"""The most a preferences file may hold. Chromium's are a few kilobytes, so more is not its own."""
RESTORE_LAST_SESSION = 1
"""Chromium's value of ``session.restore_on_startup`` for "continue where you left off"."""


def prepare(profile: Path) -> None:
    """Make the profile keep session cookies, and forget the tabs the browser last had open.

    Call it before every start of a browser on the profile, when none is running on it.
    """
    keep_session_cookies(profile)
    _remove(profile / "Default" / "Sessions")


def keep_session_cookies(profile: Path) -> None:
    """Set the profile's preferences to continue where the browser left off.

    ``Default/Preferences`` is created when it is missing. Every other preference stays as it
    was. A file that cannot be read as JSON, is not an object, is too big or is not a plain file
    is replaced by one with this setting alone.
    """
    default = profile / "Default"
    default.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = default / "Preferences"
    preferences = _read(path)
    session = preferences.get("session")
    if not isinstance(session, dict):
        session = preferences["session"] = {}
    if session.get("restore_on_startup") == RESTORE_LAST_SESSION and path.is_file():
        return
    session["restore_on_startup"] = RESTORE_LAST_SESSION
    _write(path, preferences)


def _remove(path: Path) -> None:
    """Remove a directory with its contents, or a file or link in its place, following no link."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISDIR(info.st_mode):
        shutil.rmtree(path, ignore_errors=True)
    else:
        path.unlink(missing_ok=True)


def _read(path: Path) -> dict[str, Any]:
    """Return the JSON object in ``path``, or an empty one when there is none to trust."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return {}
    with os.fdopen(descriptor, "rb") as file:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            return {}
        try:
            found = json.loads(file.read(MAX_BYTES + 1))
        except ValueError, RecursionError:
            return {}
    return found if isinstance(found, dict) else {}


def _write(path: Path, preferences: dict[str, Any]) -> None:
    """Replace ``path`` with ``preferences`` in one step, mode ``0600``, following no link."""
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=".Preferences-")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as file:
            json.dump(preferences, file, separators=(",", ":"))
        Path(name).replace(path)  # a link in the way is replaced, not followed
    except BaseException:
        with contextlib.suppress(OSError):
            Path(name).unlink()
        raise
