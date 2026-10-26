# SPDX-License-Identifier: Apache-2.0
"""Look at the host's process table.

Browsers run in their own sandbox and process namespace, so a process ID from inside means
nothing here, and Chromium's own lock file names it. The host's ``/proc`` shows every process,
sandboxed ones included, with their arguments. Matching a profile directory in those arguments
answers "is something using this profile?" without trusting anything the browser wrote.
"""

import os
from pathlib import Path

USER_DATA_DIR = "--user-data-dir="


def command_lines(proc: Path = Path("/proc")) -> list[list[str]]:
    """Return the arguments of every process the host can see, except this one."""
    lines: list[list[str]] = []
    for entry in proc.iterdir():
        if not entry.name.isdigit() or entry.name == str(os.getpid()):
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue  # the process ended, or belongs to someone else
        lines.append(raw.decode(errors="replace").split("\0"))
    return lines


def uses_path(arguments: list[str], path: Path) -> bool:
    """Tell whether an argument, or the part after ``=``, resolves to ``path``."""
    target = path.resolve()
    for argument in arguments:
        for candidate in {argument, argument.partition("=")[2]}:
            if candidate and Path(candidate).resolve() == target:
                return True
    return False


def browser_running(profile: Path, lines: list[list[str]]) -> bool:
    """Tell whether ``lines`` hold a Chromium main process that uses ``profile``.

    The helper processes of a browser (renderers, the GPU process, the zygote) carry the same
    profile argument and a ``--type=`` flag; only the main process has none, and it is the one
    whose death ends the session.
    """
    for arguments in lines:
        if any(a.startswith("--type=") for a in arguments):
            continue
        if any(a.startswith(USER_DATA_DIR) for a in arguments) and uses_path(arguments, profile):
            return True
    return False
