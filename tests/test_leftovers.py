# SPDX-License-Identifier: Apache-2.0
"""The guard against valetkey daemons that tests leave running."""

import os
import subprocess
import sys
import time
from typing import TYPE_CHECKING

import leftovers

if TYPE_CHECKING:
    from pathlib import Path


def start_daemon(home: Path) -> subprocess.Popen[bytes]:
    runtime = home / "rt"
    runtime.mkdir(mode=0o700)
    env = {"PATH": os.environ["PATH"], "HOME": str(home), "XDG_RUNTIME_DIR": str(runtime)}
    process = subprocess.Popen(  # fixed argument list
        [sys.executable, "-m", "valetkey", "daemon"],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 30
    while process.pid not in leftovers.daemons_under([home]):
        assert time.monotonic() < deadline, "the daemon never showed its environment"
        time.sleep(0.05)
    return process


def test_a_daemon_is_found_by_its_environment_and_stopped(short_dir: Path) -> None:
    process = start_daemon(short_dir)
    try:
        assert leftovers.daemons_under([short_dir]) == {process.pid: short_dir}
        assert leftovers.daemons_under([short_dir / "elsewhere"]) == {}
        assert leftovers.stop_under([short_dir]) == [process.pid]
        process.wait(10)
        assert leftovers.daemons_under([short_dir]) == {}
    finally:
        process.kill()
        process.wait()


def test_a_daemon_left_behind_is_reported_with_the_module_that_made_its_home(
    short_dir: Path,
) -> None:
    process = start_daemon(short_dir)
    try:
        message = leftovers.leftovers_message({short_dir: "test_somewhere"})
        assert message is not None
        assert f"pid {process.pid}" in message
        assert "test_somewhere" in message
        process.wait(10)  # the report stopped it
        assert leftovers.leftovers_message({short_dir: "test_somewhere"}) is None
    finally:
        process.kill()
        process.wait()
