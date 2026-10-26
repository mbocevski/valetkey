# SPDX-License-Identifier: Apache-2.0
"""A snapshot of a real page holds its text, and a reference from it can be clicked."""

import asyncio
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
    b"<title>Shop</title><h1>Account</h1><p>Signed in as tester.</p>"
    b"<ul><li>First item</li><li>Second item</li></ul>"
    b"<table><tr><th>Order</th><th>Total</th></tr><tr><td>A-100</td><td>42.00</td></tr></table>"
    b"<a href='/inbox'>Inbox</a>"
)
INBOX = b"<title>Inbox</title><h1>Your inbox</h1><p>No new mail.</p>"
PAGES = {
    "/": ({"Content-Type": "text/html"}, PAGE),
    "/inbox": ({"Content-Type": "text/html"}, INBOX),
}


def run[T](scenario: Any) -> T:  # noqa: ANN401 - any awaitable
    return asyncio.run(asyncio.wait_for(scenario, 180))


@pytest.mark.integration
@needs_everything
def test_a_snapshot_has_the_pages_text_and_its_references_work(short_dir: Path) -> None:
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
                    whole = await c.call("snapshot", site="demo")
                    tree = whole["snapshot"]["text"]
                    for text in (
                        "Signed in as tester.",
                        "First item",
                        "Second item",
                        "A-100",
                        "42.00",
                    ):
                        assert text in tree
                    short = await c.call("snapshot", site="demo", interactive=True)
                    assert "Signed in as tester." not in short["snapshot"]["text"]
                    assert 'link "Inbox"' in short["snapshot"]["text"]
                    link = next(r for r, role in whole["refs"].items() if role == "link")
                    await c.call("click", site="demo", ref=link)
                    after = await c.call("snapshot", site="demo")
                    assert "No new mail." in after["snapshot"]["text"]
            finally:
                await server.shutdown()

    run(scenario())
