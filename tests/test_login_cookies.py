# SPDX-License-Identifier: Apache-2.0
"""What a person signs in to in the login window is what the session then has."""

import asyncio
import contextlib
import functools
import shutil
import sqlite3
import time
from typing import TYPE_CHECKING, Any

import pytest
from environment import unusable_reason
from login_site import LoginSite
from sway import Sway

from valetkey import client, daemon, login, sites

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

_SKIP_REASON = unusable_reason("bwrap", "chromium", "agent-browser", "sway", "swaymsg")
needs_everything = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")


@pytest.fixture(params=[True, False], ids=["persistent-cookie", "session-cookie"])
def world(
    short_dir: Path, request: pytest.FixtureRequest
) -> Iterator[tuple[sites.Roots, LoginSite, Sway]]:
    runtime = short_dir / "rt"
    runtime.mkdir(mode=0o700)
    desktop_dir = short_dir / "sw"
    desktop_dir.mkdir(mode=0o700)
    roots = sites.Roots(short_dir / "cfg", short_dir / "state", runtime)
    desktop = Sway(desktop_dir)
    try:
        desktop.start()
        with LoginSite(persistent=request.param) as site:
            yield roots, site, desktop
    finally:
        desktop.stop()


async def wait_for(check: Any, what: str, limit: float = 60) -> None:  # noqa: ANN401
    deadline = time.monotonic() + limit
    while not check():
        assert time.monotonic() < deadline, what
        await asyncio.sleep(0.2)


def cookie_store_prefix(profile: Path) -> bytes:
    """The first three bytes of the saved cookie's encrypted value: ``v10`` is the basic store."""
    copy = profile.parent / "Cookies-copy"
    shutil.copyfile(profile / "Default" / "Cookies", copy)
    with contextlib.closing(sqlite3.connect(copy)) as database:
        ((value,),) = database.execute(
            "SELECT encrypted_value FROM cookies WHERE name = 'session'"
        ).fetchall()
    copy.unlink()
    return bytes(value[:3])


@pytest.mark.integration
@needs_everything
def test_a_login_in_the_window_is_a_login_in_the_session(
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
            async with await client.Client.connect(client.socket_path(roots)) as c:
                # The person signs in (the page does it for them) and closes the window.
                started = await c.call("login", target="http://site.test/")
                name = started["site"]
                await wait_for(lambda: "POST /login" in site.hits, f"no sign-in: {site.hits}")
                await wait_for(lambda: "GET /app" in site.hits, f"not signed in: {site.hits}")
                await asyncio.sleep(1)
                await desktop.msg("[app_id=chromium]", "kill")
                await wait_for(
                    lambda: sites.policy_path(roots, name).exists(), "the login was not saved"
                )
                await wait_for(lambda: server._sites[name].kind == "idle", "still logging in")  # noqa: SLF001
                # The session is signed in: it is not sent to the sign-in page.
                site.auto_login = False
                opened = await c.call("open", site=name)
                assert "login_expired" not in opened, (site.hits, opened)
                assert opened["url"] == "http://site.test/"
                assert opened["page"]["title"]["text"] == "Home"
                await c.call("close", site=name)
                # The window stored it with the key a session's browser reads: no keyring.
                assert cookie_store_prefix(sites.profile_path(roots, name)) == b"v10"
        finally:
            await server.shutdown()

    asyncio.run(asyncio.wait_for(scenario(), 150))
