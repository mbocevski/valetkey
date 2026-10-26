# SPDX-License-Identifier: Apache-2.0
"""Whether the machine can run the integration tests."""

import shutil
import subprocess

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
