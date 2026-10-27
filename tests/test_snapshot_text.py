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
FORM = (
    b"<title>Form</title><h1>Settings</h1><p>Some long text that is not in the form.</p>"
    b"<form id='prefs'><label>Name <input name='n'></label>"
    b"<button type='button' onclick=\"document.getElementById('r').textContent='Saved'\">"
    b"Save</button></form><p id='r'></p>"
    b"<main id='list'><article><h2>One</h2></article><article><h2>Two</h2></article>"
    b"<article><h2>Three</h2></article></main>"
)
PAGES = {
    "/": ({"Content-Type": "text/html"}, PAGE),
    "/inbox": ({"Content-Type": "text/html"}, INBOX),
    "/form": ({"Content-Type": "text/html"}, FORM),
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
                    assert 'StaticText "Inbox"' not in tree  # it repeats the link's name
                    assert 'link "Inbox" [ref=' in tree
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


@pytest.mark.integration
@needs_everything
def test_a_snapshot_scoped_to_a_form_has_refs_that_can_be_clicked(short_dir: Path) -> None:
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
                    await c.call("navigate", site="demo", url="http://site.test/form")
                    await c.call("snapshot", site="demo")  # the whole page: the baseline
                    part = await c.call("snapshot", site="demo", selector="#prefs")
                    tree = part["snapshot"]["text"]
                    assert part["scope"] == "#prefs"
                    assert 'button "Save"' in tree
                    assert "Some long text" not in tree
                    save = next(r for r, role in part["refs"].items() if role == "button")
                    done = await c.call(
                        "click", site="demo", ref=save, expect={"text_appears": "Saved"}
                    )
                    assert done["outcome"] == "met"
                    # The part did not move the baseline, so the click's change is a delta.
                    assert done["change"]["kind"] == "delta"
                    many = await c.call("snapshot", site="demo", selector="article")
                    assert many["matches"] == 3  # only the first is shown
                    assert "One" in many["snapshot"]["text"]
                    assert "Two" not in many["snapshot"]["text"]
                    holder = await c.call("snapshot", site="demo", selector="#list")
                    assert "matches" not in holder  # one element: the one that holds them all
                    assert "Three" in holder["snapshot"]["text"]
                    with pytest.raises(client.DaemonError) as info:
                        await c.call("snapshot", site="demo", selector="#nothing-here")
                    assert info.value.code == "browser_error"
                    assert info.value.message == (
                        "No element on the page matches the selector #nothing-here."
                    )
            finally:
                await server.shutdown()

    run(scenario())
