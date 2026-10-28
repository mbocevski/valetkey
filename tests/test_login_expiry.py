# SPDX-License-Identifier: Apache-2.0
import asyncio
import dataclasses
import functools
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


def clear_cookies(profile: Path) -> list[str]:
    gone = []
    for path in (profile / "Default").glob("Cookies*"):
        path.unlink()
        gone.append(path.name)
    return gone


async def wait_for(check: Any, what: str, limit: float = 60) -> None:  # noqa: ANN401
    deadline = time.monotonic() + limit
    while not check():
        assert time.monotonic() < deadline, what
        await asyncio.sleep(0.2)


@pytest.mark.integration
@needs_everything
def test_a_login_expires_when_its_cookie_is_gone_and_a_working_one_never_looks_expired(  # noqa: PLR0915 - one story
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
                # A fresh login in a real window: the page signs itself in, the person closes it.
                started = await c.call("login", target="http://site.test/")
                name = started["site"]
                await wait_for(lambda: "GET /app" in site.hits, f"no sign-in: {site.hits}")
                await asyncio.sleep(1)
                await desktop.close("chromium")
                await wait_for(
                    lambda: sites.policy_path(roots, name).exists(), "the login was not saved"
                )
                await wait_for(
                    lambda: server.registry.sites[name].kind == "idle", "still logging in"
                )
                policy = sites.load_policy(roots, name)
                assert policy.login_pages == ("site.test/login",)
                assert policy.login_cookies == ("site.test session",)
                assert "site.test" in policy.allow

                # Signed in: the start page stays the start page, and nothing is expired.
                site.auto_login = False
                healthy = await c.call("open", site=name)
                assert "login_expired" not in healthy
                assert healthy["url"] == "http://site.test/"
                assert healthy["page"]["title"]["text"] == "Home"
                await c.call("close", site=name)

                # The session cookie goes. The profile says so before a browser starts, and none
                # does: the site is not even asked.
                assert clear_cookies(sites.profile_path(roots, name))
                before = len(site.hits)
                gone = await c.call("open", site=name)
                assert gone["login_expired"] is True
                assert "the cookies it set are gone" in gone["message"]
                assert site.hits[before:] == []
                assert (await c.call("status", site=name))["state"] == "idle"

                # Without the record of the cookies, the site sends the browser to its sign-in
                # page, which says the same.
                sites.save_policy(roots, dataclasses.replace(policy, login_cookies=()))
                expired = await c.call("open", site=name)
                assert expired["login_expired"] is True
                assert expired["url"].startswith("http://site.test/login")
                assert "has expired" in expired["message"]
                assert any(hit.startswith("GET /login") for hit in site.hits[before:])
                assert (await c.call("status", site=name))["state"] == "idle"

                # A redirect inside the site to a normal page is not an expired login.
                sites.save_policy(
                    roots,
                    sites.Policy(
                        "promo",
                        "http://site.test/promo",
                        ("site.test",),
                        login_pages=policy.login_pages,
                    ),
                )
                promo = await c.call("open", site="promo")
                assert "login_expired" not in promo
                assert promo["url"] == "http://site.test/welcome"

                # A public start page with a login box, and no redirect, is not either.
                sites.save_policy(
                    roots, sites.Policy("public", "http://site.test/public", ("site.test",))
                )
                public = await c.call("open", site="public")
                assert "login_expired" not in public
                assert public["url"] == "http://site.test/public"
        finally:
            await server.shutdown()

    asyncio.run(asyncio.wait_for(scenario(), 240))
