# SPDX-License-Identifier: Apache-2.0
import os
import secrets
import subprocess

from environment import processes_with


def test_processes_with_finds_a_process_by_what_only_it_carries() -> None:
    mark = f"{secrets.randbelow(10**9):09d}"
    first = subprocess.Popen(["sleep", f"400.{mark}"])  # noqa: S603, S607 - a fixed command
    second = subprocess.Popen(["sleep", f"401.{mark}"])  # noqa: S603, S607 - a fixed command
    try:
        assert processes_with(f"sleep 400.{mark}") == [first.pid]
        assert sorted(processes_with(mark)) == sorted([first.pid, second.pid])
        assert processes_with("sleep", f"401.{mark}") == [second.pid]
        assert processes_with(f"400.{mark}", f"401.{mark}") == []  # every needle must match
        assert processes_with(f"no-such-{mark}") == []
    finally:
        for process in (first, second):
            process.kill()
            process.wait()
    assert processes_with(mark) == []


def test_processes_with_leaves_out_the_caller_and_a_process_that_ended() -> None:
    # This test's own command line holds the pytest arguments, and its id is never listed.
    assert os.getpid() not in processes_with("pytest")
    child = subprocess.Popen(["true"])  # noqa: S607 - a fixed command
    child.wait()
    assert child.pid not in processes_with("true")
