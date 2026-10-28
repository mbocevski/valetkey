# SPDX-License-Identifier: Apache-2.0
"""``valetkey login`` against a real daemon and a real login window in a private sway."""

import asyncio
import functools
import os
import signal
import sys
import time
from typing import TYPE_CHECKING, Any

import pytest
from environment import unusable_reason
from login_site import LoginSite
from sway import Sway

from valetkey import daemon, login, sites

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

_SKIP_REASON = unusable_reason("bwrap", "chromium", "agent-browser", "sway", "swaymsg")
needs_everything = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")


@pytest.fixture
def world(short_dir: Path) -> Iterator[tuple[sites.Roots, LoginSite, Sway]]:
    runtime = short_dir / "rt"
    runtime.mkdir(mode=0o700)
    desktop_dir = short_dir / "sw"
    desktop_dir.mkdir(mode=0o700)
    roots = sites.Roots(short_dir / "cfg", short_dir / "state", runtime)
    desktop = Sway(desktop_dir)
    try:
        desktop.start()
        with LoginSite() as site:
            yield roots, site, desktop
    finally:
        desktop.stop()


async def wait_for(check: Any, what: str, limit: float = 60) -> None:  # noqa: ANN401
    deadline = time.monotonic() + limit
    while not check():
        assert time.monotonic() < deadline, what
        await asyncio.sleep(0.2)


async def valetkey(roots: sites.Roots, *args: str) -> asyncio.subprocess.Process:
    """Start ``valetkey ARGS`` as the person runs it: its own process, the daemon's directories."""
    environment = {
        "PATH": os.environ["PATH"],
        "HOME": str(roots.state),
        "XDG_CONFIG_HOME": str(roots.config),
        "XDG_STATE_HOME": str(roots.state),
        "XDG_RUNTIME_DIR": str(roots.runtime),
    }
    return await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "valetkey",
        *args,
        env=environment,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )


async def finished(process: asyncio.subprocess.Process, limit: float = 60) -> tuple[int, str, str]:
    out, err = await asyncio.wait_for(process.communicate(), limit)
    assert process.returncode is not None
    return process.returncode, out.decode(), err.decode()


@pytest.mark.integration
@needs_everything
def test_the_command_logs_in_through_a_real_window_and_ends_on_no_wait_and_ctrl_c(
    world: tuple[sites.Roots, LoginSite, Sway],
) -> None:
    roots, site, desktop = world

    async def resolve(_host: str, _port: int) -> list[str]:
        return ["127.0.0.1"]

    async def connect(_address: str, _port: int) -> Any:  # noqa: ANN401
        return await asyncio.open_connection(*site.address)

    options = {"resolver": resolve, "connector": connect, "address_check": lambda _a: None}
    starter = functools.partial(
        login.start_login, wayland_socket=desktop.display, proxy_options=options
    )

    async def scenario() -> None:
        server = daemon.Daemon(roots, login_starter=starter, proxy_options=options)
        await server.start()
        try:
            # The window opens, the page signs itself in, the person closes the window.
            process = await valetkey(roots, "login", "http://site.test/")
            await wait_for(lambda: "GET /app" in site.hits, f"no sign-in: {site.hits}")
            await asyncio.sleep(1)
            await desktop.close("chromium")
            status, out, err = await finished(process)
            assert (status, err) == (0, "")
            assert "A login window for site is open on your screen." in out
            assert "Saved your site login" in out
            assert "site.test" in out
            policy = sites.load_policy(roots, "site")
            assert "site.test" in policy.allow

            # --no-wait returns at once, with the window open; a second login is refused.
            site.auto_login = False
            started = time.monotonic()
            quick = await valetkey(roots, "login", "site", "--no-wait")
            status, out, err = await finished(quick, 30)
            assert (status, err) == (0, "")
            assert "is open on your screen" in out
            assert time.monotonic() - started < 30
            assert server.registry.sites["site"].kind == "login"
            second = await valetkey(roots, "login", "site")
            status, out, err = await finished(second, 30)
            assert status == 1
            assert "a login window for site is already open" in err
            await desktop.close("chromium")
            await wait_for(lambda: server.registry.sites["site"].kind == "idle", "window open")

            # Ctrl-C closes the window and ends the login: nothing new is saved.
            learned = sites.load_policy(roots, "site").learned
            waiting = await valetkey(roots, "login", "site")
            await wait_for(lambda: server.registry.sites["site"].kind == "login", "no window")
            await asyncio.sleep(1)
            waiting.send_signal(signal.SIGINT)
            status, out, err = await finished(waiting, 30)
            assert status == 1
            assert "nothing was saved" in out
            await wait_for(lambda: server.registry.sites["site"].kind == "idle", "window open")
            assert not [w for w in await desktop.windows() if w.get("app_id") == "chromium"]
            assert sites.load_policy(roots, "site").learned == learned
        finally:
            await server.shutdown()

    asyncio.run(asyncio.wait_for(scenario(), 240))
