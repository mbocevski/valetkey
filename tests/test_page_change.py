# SPDX-License-Identifier: Apache-2.0
"""A click on a real page says what changed, and a reference from that change can be clicked."""

import asyncio
import re
from typing import TYPE_CHECKING, Any

import pytest
from environment import unusable_reason
from proxy_stub import PageServer

from valetkey import client, daemon, sites

if TYPE_CHECKING:
    from pathlib import Path

_SKIP_REASON = unusable_reason("bwrap", "chromium", "agent-browser")
needs_everything = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")

PAGE = (
    b"<title>Shop</title><h1>Account</h1>"
    + b"".join(b"<p>Row %d <a href=/row%d>Item %d</a></p>" % (n, n, n) for n in range(60))
    + b"<button onclick=\"document.getElementById('menu').innerHTML = "
    b"'<ul><li><a href=/orders>Orders</a></li><li><a href=/settings>Settings</a></li></ul>'\">"
    b"Menu</button><div id=menu></div><a href='/other'>Other</a>"
)
PAGES = {
    "/": ({"Content-Type": "text/html"}, PAGE),
    "/orders": ({"Content-Type": "text/html"}, b"<title>Your orders</title><h1>Orders</h1>"),
    "/other": ({"Content-Type": "text/html"}, b"<title>Other page</title><h1>Other</h1>"),
}


def run[T](scenario: Any) -> T:  # noqa: ANN401 - any awaitable
    return asyncio.run(asyncio.wait_for(scenario, 180))


@pytest.mark.integration
@needs_everything
def test_a_click_says_what_changed_and_its_new_references_work(short_dir: Path) -> None:
    runtime = short_dir / "rt"
    runtime.mkdir(mode=0o700)
    roots = sites.Roots(short_dir / "cfg", short_dir / "state", runtime)
    sites.save_policy(roots, sites.Policy("demo", "http://site.test/", ("site.test",)))

    async def resolve(_host: str, _port: int) -> list[str]:
        return ["127.0.0.1"]

    async def scenario() -> None:
        with PageServer({}, files=PAGES) as pages:

            async def connect(_address: str, _port: int) -> Any:  # noqa: ANN401
                return await asyncio.open_connection(*pages.address)

            options = {"resolver": resolve, "connector": connect, "address_check": lambda _a: None}
            server = daemon.Daemon(roots, proxy_options=options)
            await server.start()
            try:
                async with await client.Client.connect(client.socket_path(roots)) as c:
                    await c.call("open", site="demo")
                    # No snapshot yet: nothing to compare with.
                    assert "change" not in await c.call("click", site="demo", text="Menu")
                    await c.call("navigate", site="demo", url="http://site.test/")
                    await c.call("snapshot", site="demo", interactive=True)
                    opened = (await c.call("click", site="demo", text="Menu"))["change"]
                    assert opened["kind"] == "delta"
                    added = opened["added"]["text"]
                    assert 'link "Orders"' in added
                    assert 'link "Settings"' in added
                    ref = re.search(r'link "Orders" \[ref=(e\d+)\]', added)
                    assert ref is not None
                    # The reference came with the change: no snapshot was taken to learn it.
                    went = await c.call("click", site="demo", ref=ref.group(1))
                    assert went["change"]["kind"] == "full"
                    assert went["change"]["title"]["text"] == "Your orders"
                    assert went["url"].endswith("/orders")
                    # The page is a new one now; a snapshot and a click on it start over.
                    await c.call("navigate", site="demo", url="http://site.test/")
                    await c.call("snapshot", site="demo", interactive=True)
                    again = await c.call("click", site="demo", text="Other")
                    assert again["change"]["kind"] == "full"
                    assert again["change"]["title"]["text"] == "Other page"
            finally:
                await server.shutdown()

    run(scenario())
