# SPDX-License-Identifier: Apache-2.0
"""A login window on the laptop: the sandbox under waypipe server, through a real bridge.

A private headless sway is the laptop, ``tests/fake_ssh.py`` carries the bridge's socket, and the
login runs on this machine with its own runtime directory, as it would on a server.
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from environment import processes_with, unusable_reason
from proxy_stub import PageServer
from sway import Sway

from valetkey import bridge, client, daemon, login, sites

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from valetkey.proxy import SeenHost

_SKIP_REASON = unusable_reason("bwrap", "chromium", "sway", "swaymsg", "waypipe", "setpriv")
needs_desktop = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")
FAKE_SSH = Path(__file__).with_name("fake_ssh.py")
PAGES = {"/": "<title>Remote login</title><h1>sign in</h1>"}


@pytest.fixture
def sway(short_dir: Path) -> Iterator[Sway]:
    (short_dir / "laptop").mkdir(mode=0o700)
    desktop = Sway(short_dir / "laptop")
    try:
        desktop.start()
        yield desktop
    finally:
        desktop.stop()


async def until(check: Callable[[], Any], limit: float = 60) -> None:
    deadline = time.monotonic() + limit
    while not await check():
        assert time.monotonic() < deadline, "timed out"
        await asyncio.sleep(0.2)


@pytest.mark.integration
@needs_desktop
def test_a_login_window_opens_on_the_laptop_and_the_login_completes(
    short_dir: Path, sway: Sway
) -> None:
    laptop = sites.Roots(short_dir / "lc", short_dir / "ls", sway.runtime)
    (short_dir / "srv").mkdir(mode=0o700)
    server = sites.Roots(short_dir / "sc", short_dir / "ss", short_dir / "srv")
    base = {"PATH": os.environ["PATH"], "HOME": str(short_dir)}
    remote_env = base | {"XDG_RUNTIME_DIR": str(server.runtime)}
    ssh_env = base | {
        "XDG_RUNTIME_DIR": str(sway.runtime),
        "WAYLAND_DISPLAY": str(sway.display),
        "FAKE_SSH_REMOTE_ENV": json.dumps(remote_env),
    }
    sites.ensure_runtime(server)  # valetkeyd makes this directory; ssh needs it to bind in
    names: list[str] = []
    finished: list[tuple[list[SeenHost], Path]] = []

    async def scenario() -> None:
        stop = asyncio.Event()
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
        with PageServer(PAGES) as pages:

            async def resolve(_host: str, _port: int) -> list[str]:
                return ["127.0.0.1"]

            async def connect(_address: str, _port: int) -> Any:  # noqa: ANN401
                return await asyncio.open_connection(*pages.address)

            options = {"resolver": resolve, "connector": connect, "address_check": lambda _a: None}
            try:
                # The socket is there as soon as the stand-in ssh has bound it, and valetkeyd
                # would hand this very path to the login.
                async def forwarded() -> bool:
                    return (
                        bool(names)
                        and (sites.runtime_path(server) / f"bridge-{names[0]}.sock").is_socket()
                    )

                await until(forwarded)
                path = sites.runtime_path(server) / f"bridge-{names[0]}.sock"
                handle = await login.start_login(
                    "demo",
                    "http://login.test/",
                    server,
                    lambda seen, profile: finished.append((seen, profile)),
                    bridge=path,
                    proxy_options=options,
                )

                async def window() -> bool:
                    return any(w["app_id"] == "chromium" for w in await sway.windows())

                await until(window)  # the window is on the laptop's screen
                await until(lambda: asyncio.sleep(0, bool(pages.hits)))
                assert handle.running
                assert path.is_socket()  # the login never removes the bridge's socket
                await sway.msg("[app_id=chromium]", "kill")
                result = await asyncio.wait_for(handle.wait(), 60)
                assert result.cancelled is False
                assert [h.host for h in result.seen_hosts] == ["login.test"]
                assert path.is_socket()  # still there for the next login
                assert not (sites.runtime_path(server) / "logins" / "demo").exists()
            finally:
                stop.set()
                await asyncio.wait_for(task, 30)

    asyncio.run(asyncio.wait_for(scenario(), 240))
    ((seen, profile),) = finished
    assert profile == sites.profile_path(server, "demo")
    assert [h.host for h in seen] == ["login.test"]
    assert list(sites.runtime_path(server).glob("bridge-*.sock")) == []
    assert processes_with(str(sites.runtime_path(server))) == []


@pytest.mark.integration
@needs_desktop
def test_browser_login_goes_to_a_connected_bridge_and_the_login_completes(
    short_dir: Path, sway: Sway, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole route: no screen here, a bridge from the laptop, ``login``, close, learned."""

    def no_screen(*_: object) -> Path:
        raise login.NoDisplayError(login.NO_SESSION)

    # This machine has no screen of its own. The real lookup would also ask the user manager and
    # find the display of whoever runs the tests, so it is replaced rather than hidden.
    monkeypatch.setattr(login, "find_wayland_socket", no_screen)
    laptop = sites.Roots(short_dir / "lc", short_dir / "ls", sway.runtime)
    (short_dir / "srv").mkdir(mode=0o700)
    server = sites.Roots(short_dir / "sc", short_dir / "ss", short_dir / "srv")
    (server.config / "valetkey").mkdir(parents=True)
    (server.config / "valetkey" / "config.json").write_text(
        json.dumps({"remote_logins": {"waypipe": True}}), encoding="utf-8"
    )
    base = {"PATH": os.environ["PATH"], "HOME": str(short_dir)}
    remote_env = base | {"XDG_RUNTIME_DIR": str(server.runtime)}
    ssh_env = base | {
        "XDG_RUNTIME_DIR": str(sway.runtime),
        "WAYLAND_DISPLAY": str(sway.display),
        "FAKE_SSH_REMOTE_ENV": json.dumps(remote_env),
    }

    async def scenario() -> None:
        stop = asyncio.Event()
        with PageServer(PAGES) as pages:

            async def resolve(_host: str, _port: int) -> list[str]:
                return ["127.0.0.1"]

            async def connect(_address: str, _port: int) -> Any:  # noqa: ANN401
                return await asyncio.open_connection(*pages.address)

            options = {"resolver": resolve, "connector": connect, "address_check": lambda _a: None}
            service = daemon.Daemon(server, proxy_options=options, user_environment=dict)
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
                    draw=lambda: 0.0,
                )
            )
            try:
                async with await client.Client.connect(client.socket_path(server)) as c:

                    async def bridged() -> bool:
                        return bool((await c.call("status"))["bridges"])

                    await until(bridged)
                    answer = await c.call("login", target="http://login.test/")
                    assert answer == {"site": "login", "window": "open", "route": "bridge"}

                    async def window() -> bool:
                        return any(w["app_id"] == "chromium" for w in await sway.windows())

                    await until(window)  # on the laptop's screen
                    await sway.msg("[app_id=chromium]", "kill")

                    async def learned() -> bool:
                        try:
                            return sites.load_policy(server, "login").learned is not None
                        except FileNotFoundError:
                            return False

                    await until(learned)
                    policy = sites.load_policy(server, "login")
                    assert "login.test" in policy.allow
                    await until(lambda: asyncio.sleep(0, not _logins(service)))
                    summary = next(
                        e["summary"]
                        for e in (await c.call("sites"))["sites"]
                        if e["site"] == "login"
                    )
                    assert summary.startswith("Saved your login login.")
            finally:
                stop.set()
                await asyncio.wait_for(task, 30)
                await service.shutdown()

    asyncio.run(asyncio.wait_for(scenario(), 240))
    assert list(sites.runtime_path(server).glob("bridge-*.sock")) == []
    assert processes_with(str(sites.runtime_path(server))) == []


def _logins(service: daemon.Daemon) -> list[str]:
    """The sites with a login window open, read from the daemon's own bookkeeping."""
    return [name for name, state in service.registry.sites.items() if state.kind == "login"]
