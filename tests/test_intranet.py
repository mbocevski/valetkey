# SPDX-License-Identifier: Apache-2.0
"""A site on a private network, from ``valetkey add`` to a page that loads.

The fixture site resolves to a ``10.x`` address. The real login window runs in a private sway
and the real browser session runs through the daemon; only the DNS answer and the connection are
replaced, so the address check is the production one.
"""

import asyncio
import functools
import time
from typing import TYPE_CHECKING, Any

import pytest
from environment import unusable_reason
from proxy_stub import PageServer
from sway import Sway

from valetkey import client, daemon, login, sites
from valetkey.cli import main
from valetkey.client import DaemonError

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

_SKIP_REASON = unusable_reason("bwrap", "chromium", "sway", "swaymsg", "agent-browser")
needs_everything = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")
HOST = "intra.corp.test"
ADDRESS = "10.20.1.5"
PAGES = {"/": "<title>Intranet home</title><h1>welcome</h1>"}


@pytest.fixture
def roots(short_dir: Path, monkeypatch: pytest.MonkeyPatch) -> sites.Roots:
    (short_dir / "run").mkdir(mode=0o700)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(short_dir / "cfg"))
    monkeypatch.setenv("XDG_STATE_HOME", str(short_dir / "state"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(short_dir / "run"))
    return sites.roots_from_env()


@pytest.fixture
def sway(short_dir: Path) -> Iterator[Sway]:
    (short_dir / "sway").mkdir(mode=0o700)
    desktop = Sway(short_dir / "sway")
    try:
        desktop.start()
        yield desktop
    finally:
        desktop.stop()


async def until(check: Any, limit: float = 40) -> None:  # noqa: ANN401 - a sync predicate
    deadline = time.monotonic() + limit
    while not check():
        assert time.monotonic() < deadline, "timed out"
        await asyncio.sleep(0.2)


@pytest.mark.integration
@needs_everything
def test_a_site_on_a_private_network_from_add_to_a_loaded_page(
    sway: Sway, roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    async def scenario() -> None:
        with PageServer(PAGES) as pages:
            reached: list[str] = []

            async def resolve(_host: str, _port: int) -> list[str]:
                return [ADDRESS]

            async def connect(address: str, _port: int) -> Any:  # noqa: ANN401
                reached.append(address)
                return await asyncio.open_connection(*pages.address)

            server = daemon.Daemon(
                roots,
                proxy_options={"resolver": resolve, "connector": connect},
                login_starter=functools.partial(login.start_login, wayland_socket=sway.display),
            )
            await server.start()
            try:
                async with await client.Client.connect(client.socket_path(roots)) as c:
                    # 1. An agent cannot get a login for the unknown private host.
                    with pytest.raises(DaemonError) as refused:
                        await c.call("login", target=f"http://{HOST}/")
                    assert refused.value.code == "private_address"
                    assert f"valetkey add corp http://{HOST}/ --private-network RANGE" in (
                        refused.value.message
                    )
                    assert pages.hits == []
                    # 2. The person creates the site with the range.
                    command = [
                        "add",
                        "intra",
                        f"http://{HOST}/",
                        "--private-network",
                        "10.20.1.0/24",
                    ]
                    assert await asyncio.to_thread(main, command) == 0
                    assert "added" in capsys.readouterr().out
                    # 3. A real login window opens, and loads the page through the range.
                    assert (await c.call("login", target="intra"))["window"] == "open"
                    await until(lambda: pages.hits)
                    await sway.msg("[app_id=chromium]", "kill")
                    await until(lambda: sites.load_policy(roots, "intra").learned is not None)
                    learned = sites.load_policy(roots, "intra")
                    assert learned.private_networks == ("10.20.1.0/24",)
                    assert HOST in learned.allow
                    assert set(reached) == {ADDRESS}
                    await until(lambda: not server_logins(server))
                    # 4. The signed-in browser loads the page.
                    opened = await c.call("open", site="intra")
                    assert opened["page"]["title"]["text"] == "Intranet home"
                    assert opened["refused"] == []
                    assert (await c.call("close", site="intra"))["closed"] is True
            finally:
                await server.shutdown()

    asyncio.run(asyncio.wait_for(scenario(), 150))


def server_logins(server: daemon.Daemon) -> list[str]:
    """The sites with a login window open, read from the daemon's own bookkeeping."""
    return [name for name, state in server._sites.items() if state.kind == "login"]  # noqa: SLF001
