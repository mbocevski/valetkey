# SPDX-License-Identifier: Apache-2.0
"""Valetkey daemons that a test run starts and does not stop, and how to find and stop them.

A client starts a daemon on its first connection, so a test that runs one (the remote login and
bridge tests, through ``fake_ssh.py``) leaves a daemon behind when it ends. The daemon is told
apart from every other one on the machine by where its environment points: ``HOME`` or
``XDG_RUNTIME_DIR`` under a directory this run made. Processes are found and stopped by process
number, never by name.
"""

import contextlib
import os
import signal
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

DAEMON = ("-m", "valetkey", "daemon")
GRACE = 10.0
"""Seconds a daemon gets to end on SIGTERM before it is killed."""


def _arguments(pid: int) -> list[str]:
    try:
        raw = (Path("/proc") / str(pid) / "cmdline").read_bytes()
    except OSError:
        return []
    return raw.decode(errors="replace").split("\0")


def _environment(pid: int) -> dict[str, str]:
    try:
        raw = (Path("/proc") / str(pid) / "environ").read_bytes()
    except OSError:  # another user's process, or one that has just ended
        return {}
    pairs = (item.partition("=") for item in raw.decode(errors="replace").split("\0") if item)
    return {name: value for name, _, value in pairs}


def _is_daemon(arguments: list[str]) -> bool:
    size = len(DAEMON)
    return any(tuple(arguments[i : i + size]) == DAEMON for i in range(len(arguments) - size + 1))


def daemons_under(roots: Iterable[Path]) -> dict[int, Path]:
    """Return ``{pid: directory}`` for the valetkey daemons whose environment is under ``roots``.

    ``directory`` is the root that holds the daemon's ``HOME`` or ``XDG_RUNTIME_DIR``.
    """
    resolved = [Path(root) for root in roots]
    found: dict[int, Path] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or not _is_daemon(_arguments(int(entry.name))):
            continue
        environment = _environment(int(entry.name))
        for name in ("HOME", "XDG_RUNTIME_DIR"):
            value = environment.get(name)
            owner = next((r for r in resolved if value and Path(value).is_relative_to(r)), None)
            if owner is not None:
                found[int(entry.name)] = owner
                break
    return found


def _gone(pid: int) -> bool:
    try:
        stat = (Path("/proc") / str(pid) / "stat").read_text()
    except OSError:
        return True
    return stat.rpartition(")")[2].split()[0] == "Z"  # a zombie has ended; its parent is slow


def stop(pids: Iterable[int], grace: float = GRACE) -> None:
    """End the processes ``pids``: SIGTERM, then SIGKILL for those still there after ``grace``."""
    waiting = list(pids)
    for pid in waiting:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline and not all(_gone(pid) for pid in waiting):
        time.sleep(0.05)
    for pid in waiting:
        if not _gone(pid):
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)


def stop_under(roots: Iterable[Path]) -> list[int]:
    """Stop the daemons under ``roots``; return their process numbers."""
    pids = list(daemons_under(roots))
    stop(pids)
    return pids


def leftovers_message(made: Mapping[Path, str]) -> str | None:
    """Stop every daemon left under the directories in ``made``, and say what was left.

    ``made`` maps each directory a run created to the test module that created it. Returns
    ``None`` when nothing was left.
    """
    found = daemons_under(made)
    if not found:
        return None
    stop(found)
    lines = [f"  pid {pid}: started under {root} by {made[root]}" for pid, root in found.items()]
    return "tests left valetkey daemons running (stopped now):\n" + "\n".join(lines)
