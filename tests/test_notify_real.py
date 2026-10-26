# SPDX-License-Identifier: Apache-2.0
"""The question as a real notification daemon shows it, answered with the daemon's own control.

Mako runs on a private headless sway and a private session bus, so nothing appears on a real
desktop. ``makoctl`` plays the person: it presses a button or dismisses the notification.
"""

import asyncio
import os
import subprocess
import time
from typing import TYPE_CHECKING, Any

import pytest
from conftest import REAL_NOTIFY_ASK
from environment import unusable_reason
from sway import Sway

from valetkey import notify

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

_SKIP_REASON = unusable_reason("sway", "mako", "makoctl", "dbus-daemon", "notify-send", "busctl")
needs_mako = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")
TITLE = "Allow sitex to reach cdn.example.com?"


@pytest.fixture
def desktop(short_dir: Path) -> Iterator[Sway]:
    (short_dir / "sw").mkdir(mode=0o700)
    sway = Sway(short_dir / "sw")
    try:
        sway.start()
        yield sway
    finally:
        sway.stop()


def owns_notification_name(env: dict[str, str]) -> bool:
    """Tell whether anything owns the notification name on the private bus, without starting it."""
    done = subprocess.run(  # fixed argument list
        [  # noqa: S607
            "busctl",
            "--user",
            "--json=short",
            "call",
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "NameHasOwner",
            "s",
            "org.freedesktop.Notifications",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    return done.returncode == 0 and '"data":[true]' in done.stdout.replace(" ", "")


@pytest.fixture
def session_env(short_dir: Path, desktop: Sway) -> Iterator[dict[str, str]]:
    """A session bus with mako on it, on the private sway; yields the environment to use."""
    bus = short_dir / "bus"
    daemon = subprocess.Popen(  # noqa: S603  # fixed argument list
        ["dbus-daemon", "--session", "--nofork", f"--address=unix:path={bus}"],  # noqa: S607
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(short_dir),
        "XDG_RUNTIME_DIR": str(desktop.runtime),
        "WAYLAND_DISPLAY": str(desktop.display),
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={bus}",
    }
    notifier: subprocess.Popen[bytes] | None = None
    try:
        deadline = time.monotonic() + 10
        while not bus.exists():
            assert time.monotonic() < deadline, "the session bus did not start"
            time.sleep(0.05)
        notifier = subprocess.Popen(  # fixed argument list
            ["mako"],  # noqa: S607
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Asking the bus for the daemon before it owns its name would start a second one, from
        # the service file the bus finds, and one of the two would exit. Wait without asking it.
        deadline = time.monotonic() + 30
        while not owns_notification_name(env):
            assert time.monotonic() < deadline, "mako did not take its name on the bus"
            assert notifier.poll() is None, "mako exited"
            time.sleep(0.05)
        deadline = time.monotonic() + 30
        while not asyncio.run(notify.has_actions(env)):
            assert time.monotonic() < deadline, "mako did not offer actions"
            assert notifier.poll() is None, "mako exited"
            time.sleep(0.1)
        yield env
    finally:
        for process in (notifier, daemon):
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(10)


def makoctl(env: dict[str, str], *args: str) -> str:
    done = subprocess.run(  # noqa: S603  # fixed argument list
        ["makoctl", *args],  # noqa: S607
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    return done.stdout


async def answered(env: dict[str, str], act: tuple[str, ...], limit: float = 30) -> Any:  # noqa: ANN401
    """Ask the question, wait until mako shows it, then do ``act`` with ``makoctl``."""
    question = asyncio.create_task(
        REAL_NOTIFY_ASK(
            notify.Question("sitex", "cdn.example.com", seen=True, reason="it loads"), env, limit
        )
    )
    deadline = time.monotonic() + 30
    while TITLE not in await asyncio.to_thread(makoctl, env, "list"):
        assert time.monotonic() < deadline, "the notification never appeared"
        assert not question.done(), "the question ended before it was shown"
        await asyncio.sleep(0.1)
    shown = await asyncio.to_thread(makoctl, env, "list")
    assert "App name: valetkey" in shown
    assert "allow: Allow" in shown
    assert "deny: Deny" in shown
    await asyncio.to_thread(makoctl, env, *act)
    return await asyncio.wait_for(question, 30)


@pytest.mark.integration
@needs_mako
def test_the_daemon_offers_buttons(session_env: dict[str, str]) -> None:
    assert asyncio.run(notify.has_actions(session_env)) is True


@pytest.mark.integration
@needs_mako
@pytest.mark.parametrize(
    ("act", "expected"),
    [
        (("invoke", "allow"), "yes"),
        (("invoke", "deny"), "no"),
        (("dismiss",), "timeout"),  # closing it is not a no
    ],
)
def test_the_buttons_and_closing_answer_a_real_notification(
    session_env: dict[str, str], act: tuple[str, ...], expected: str
) -> None:
    assert asyncio.run(answered(session_env, act)) == expected


@pytest.mark.integration
@needs_mako
def test_a_notification_nobody_answers_expires(session_env: dict[str, str]) -> None:
    outcome = asyncio.run(
        REAL_NOTIFY_ASK(
            notify.Question("sitex", "cdn.example.com", seen=False, reason=""), session_env, 1.5
        )
    )
    assert outcome == "timeout"
