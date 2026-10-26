# SPDX-License-Identifier: Apache-2.0
"""The tests never reach the person's session bus, and fail when something tries to notify on it."""

import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import REAL_USER_SESSION

needs_notify_send = pytest.mark.skipif(
    shutil.which("notify-send") is None, reason="notify-send is not installed"
)


def test_a_test_runs_with_a_session_bus_that_is_not_the_persons(
    runtime_base: str,
) -> None:
    address = os.environ["DBUS_SESSION_BUS_ADDRESS"]
    assert address == f"unix:path={runtime_base}/no-session-bus"
    assert not Path(address.removeprefix("unix:path=")).exists()
    assert address != REAL_USER_SESSION.get("DBUS_SESSION_BUS_ADDRESS")
    assert os.environ["XDG_RUNTIME_DIR"] != REAL_USER_SESSION.get("XDG_RUNTIME_DIR")
    assert os.environ["DBUS_SYSTEM_BUS_ADDRESS"].endswith("/no-system-bus")


def test_a_child_process_inherits_the_same_dead_bus() -> None:
    result = subprocess.run(
        [sys.executable, "-c", "import os; print(os.environ['DBUS_SESSION_BUS_ADDRESS'])"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == os.environ["DBUS_SESSION_BUS_ADDRESS"]


def calls(guard: Path) -> str:
    return (guard / "calls").read_text(encoding="utf-8")


@needs_notify_send
def test_notify_send_on_the_inherited_bus_is_refused_and_recorded(notify_guard: Path) -> None:
    result = subprocess.run(  # noqa: S603 - the guard, first on PATH
        [shutil.which("notify-send") or "", "hello"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 1
    assert "not allowed" in result.stderr
    assert "hello" in calls(notify_guard)
    # Here the test means it, so it takes the record back out, or the guard would fail it.
    (notify_guard / "calls").write_text("", encoding="utf-8")


@needs_notify_send
def test_notify_send_on_another_bus_than_a_private_one_is_refused(
    notify_guard: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A socket that exists but is not under the tests' own directories is someone else's."""
    path = tmp_path / "bus"
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(path))
        listener.listen()
        monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", f"unix:path={path}")
        result = subprocess.run(  # noqa: S603 - the guard, first on PATH
            [shutil.which("notify-send") or "", "other"],
            capture_output=True,
            text=True,
            check=False,
        )
    assert result.returncode == 1
    assert "other" in calls(notify_guard)
    (notify_guard / "calls").write_text("", encoding="utf-8")


def test_the_guard_fails_a_test_that_notifies_on_the_real_bus(pytester: pytest.Pytester) -> None:
    """A test run of its own, with the same guard, ends in a failure when it notifies."""
    if shutil.which("notify-send") is None:
        pytest.skip("notify-send is not installed")
    for name in ("conftest.py", "require_integration.py"):
        shutil.copy(Path(__file__).parent / name, pytester.path / name)
    pytester.makepyfile(
        test_inner="""
        import subprocess

        def test_notifies():
            subprocess.run(["notify-send", "leak"], check=False, capture_output=True)
        """
    )
    result = pytester.runpytest_subprocess("-p", "no:cacheprovider", "-W", "default")
    result.assert_outcomes(passed=1, errors=1)  # the failure is reported at the end of the test
    result.stdout.fnmatch_lines(["*a test notified on a session bus it does not own*leak*"])
