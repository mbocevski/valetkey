# SPDX-License-Identifier: Apache-2.0
"""Whether the machine can run the integration tests, and what they may ask about processes."""

import os
import shutil
import subprocess
from pathlib import Path

from valetkey import sandbox


def unusable_reason(*programs: str) -> str | None:
    """Return why the sandbox tests cannot run here, or ``None`` when they can.

    The programs must be on ``PATH``, and a minimal bubblewrap sandbox, built the way
    ``valetkey.sandbox`` builds it, must start.
    """
    for program in programs:
        if shutil.which(program) is None:
            return f"{program} is not installed"
    probe = subprocess.run(  # noqa: S603  # fixed argument list
        [
            shutil.which("bwrap") or "bwrap",
            "--unshare-all",
            "--ro-bind",
            "/usr",
            "/usr",
            *sandbox.system_link_args(),
            "/usr/bin/true",
        ],
        capture_output=True,
        check=False,
        timeout=30,
    )
    return None if probe.returncode == 0 else "unprivileged user namespaces are unavailable"


def processes_with(*needles: str) -> list[int]:
    """Return the ids of the processes whose command line holds every one of ``needles``.

    Other people's tests run on the same machine, so the needles must be something only the
    caller's own processes carry: a path in the test's own temporary directory, or a number the
    test drew at random. Never a bare program name. The caller's own process is left out.
    """
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            line = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
        except OSError:
            continue  # it ended, or it is not ours to read
        if all(needle in line for needle in needles):
            found.append(int(entry.name))
    return found
