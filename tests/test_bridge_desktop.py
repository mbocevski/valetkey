# SPDX-License-Identifier: Apache-2.0
"""The bridge end to end: a real waypipe, a real compositor, a real daemon, no real ssh.

A private headless sway stands in for the laptop. The server is this machine with its own runtime
directory. ``tests/fake_ssh.py`` carries the forwarded socket across and runs ``bridge-hold`` with
the server's environment, so nothing touches ``~/.ssh``, the person's agent or the network.
"""

import asyncio
import json
import os
import signal
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from environment import processes_with, unusable_reason
from sway import Sway

from valetkey import bridge, client, daemon, sites

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

_SKIP_REASON = unusable_reason("sway", "swaymsg", "waypipe", "foot", "grim")
needs_desktop = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")
FAKE_SSH = Path(__file__).with_name("fake_ssh.py")
REFUSED = "compositor doesn't support the screen capture protocol"


@pytest.fixture
def sway(short_dir: Path) -> Iterator[Sway]:
    (short_dir / "laptop").mkdir(mode=0o700)
    desktop = Sway(short_dir / "laptop")
    try:
        desktop.start()
        yield desktop
    finally:
        desktop.stop()


async def until(check: Callable[[], object], limit: float = 40) -> None:
    deadline = time.monotonic() + limit
    while not check():
        assert time.monotonic() < deadline, "timed out"
        await asyncio.sleep(0.1)


async def windows(desktop: Sway, app_id: str) -> list[dict[str, Any]]:
    return [w for w in await desktop.windows() if w["app_id"] == app_id]


async def launch(
    path: Path, server_env: dict[str, str], *program: str
) -> asyncio.subprocess.Process:
    """Start a program on the "server", forwarded through the bridge socket ``path``."""
    return await asyncio.create_subprocess_exec(
        "waypipe",
        "-s",
        str(path),
        "server",
        "--",
        *program,
        env=server_env,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )


@pytest.mark.integration
@needs_desktop
def test_a_bridge_gives_windows_on_the_laptop_and_cleans_up_when_the_link_drops(  # noqa: PLR0915 - one story, told in order
    short_dir: Path, sway: Sway
) -> None:
    laptop = sites.Roots(short_dir / "lc", short_dir / "ls", sway.runtime)
    (short_dir / "srv").mkdir(mode=0o700)
    server = sites.Roots(short_dir / "sc", short_dir / "ss", short_dir / "srv")
    server_runtime = sites.runtime_path(server)
    base = {"PATH": os.environ["PATH"], "HOME": str(short_dir)}
    remote_env = base | {"XDG_RUNTIME_DIR": str(server.runtime)}
    ssh_env = base | {
        "XDG_RUNTIME_DIR": str(sway.runtime),
        "WAYLAND_DISPLAY": str(sway.display),
        "FAKE_SSH_REMOTE_ENV": json.dumps(remote_env),
    }
    names: list[str] = []

    async def scenario() -> None:
        stop = asyncio.Event()
        service = daemon.Daemon(server, user_environment=dict)
        await service.start()
        task = asyncio.ensure_future(
            bridge.run_bridge(
                "server1",
                laptop,
                ssh=[sys.executable, str(FAKE_SSH)],
                valetkey=[sys.executable, "-m", "valetkey"],
                remote_runtime=server.runtime,
                environ=ssh_env,
                stop=stop,
                on_connect=names.append,
                draw=lambda: 0.0,
            )
        )
        try:
            async with await client.Client.connect(client.socket_path(server)) as c:
                # 1. The bridge comes up, and bridge-hold registers it with the daemon.
                async def registered() -> list[str]:
                    return [b["bridge"] for b in (await c.call("status"))["bridges"]]

                deadline = time.monotonic() + 40
                while not await registered():
                    assert time.monotonic() < deadline, "no bridge registered"
                    assert not task.done(), task.exception()
                    await asyncio.sleep(0.2)
                (name,) = await registered()
                assert name == f"bridge-{names[0]}"
                path = server_runtime / f"{name}.sock"
                assert path.is_socket()
                # 2. A client on the "server" gets a window on the laptop.
                first = await launch(path, remote_env, "foot")
                await until_async(lambda: _some(windows(sway, "foot")))
                # 3. A second launch over the same connection works too.
                second = await launch(path, remote_env, "foot")
                await until_async(lambda: _at_least(windows(sway, "foot"), 2))
                assert path.is_socket()  # a launch never removes the bridge's socket
                await sway.msg("[app_id=foot]", "kill")
                for process in (first, second):
                    await asyncio.wait_for(process.communicate(), 30)
                assert path.is_socket()
                # 4. grim through the bridge is refused: the context hides screen capture.
                target = short_dir / "shot.png"
                grim = await launch(path, remote_env, "grim", str(target))
                _, error = await asyncio.wait_for(grim.communicate(), 30)
                assert grim.returncode != 0
                assert REFUSED in error.decode(errors="replace")
                assert not target.exists()
                # 5. Kill the stand-in ssh: the bridge is forgotten and its socket is gone.
                (victim,) = processes_with(str(FAKE_SSH), f"bridge-hold {names[0]}")
                os.kill(victim, signal.SIGKILL)
                await until_async(lambda: _gone(registered, name), 30)
                assert not path.exists()
                # The bridge tries again under a new name.
                await until_async(lambda: _renamed(registered, name), 30)
        finally:
            stop.set()
            await asyncio.wait_for(task, 30)
            await service.shutdown()

    asyncio.run(asyncio.wait_for(scenario(), 240))
    assert list(sites.runtime_path(server).glob("bridge-*.sock")) == []
    assert not (sites.runtime_path(laptop) / "wp.sock").exists()
    # Only this test's own stand-in ssh: other tests run theirs at the same time, and the name of
    # each bridge was drawn at random for this one.
    assert names
    for name in names:
        assert processes_with(str(FAKE_SSH), f"bridge-hold {name}") == []
    assert processes_with("waypipe", str(sites.runtime_path(laptop))) == []


async def until_async(check: Callable[[], Any], limit: float = 40) -> None:
    deadline = time.monotonic() + limit
    while not await check():
        assert time.monotonic() < deadline, "timed out"
        await asyncio.sleep(0.1)


async def _at_least(found: Any, count: int) -> bool:  # noqa: ANN401 - a coroutine
    return len(await found) >= count


async def _gone(registered: Callable[[], Any], name: str) -> bool:
    return name not in await registered()


async def _renamed(registered: Callable[[], Any], name: str) -> bool:
    now = await registered()
    return bool(now) and name not in now


async def _some(found: Any) -> bool:  # noqa: ANN401 - a coroutine
    return bool(await found)
