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
NAV_PAGE = (
    b"<title>Shop</title><nav><button onclick=\"document.getElementById('menu').innerHTML = "
    b"'<ul><li><a href=/orders>Orders</a></li><li><a href=/settings>Settings</a></li></ul>'\">"
    b"Account</button><div id=menu></div></nav><h1>Shop</h1>"
    + b"".join(b"<p>Row %d <a href=/row%d>Item %d</a></p>" % (n, n, n) for n in range(60))
)
TALL_PAGE = (
    b"<title>Tall</title><header><button onclick=\"document.getElementById('menu').innerHTML = "
    b"'<ul><li><a href=/orders>Orders</a></li><li><a href=/settings>Settings</a></li></ul>';"
    b"document.getElementById('foot').setAttribute('aria-expanded', 'true')\">Account</button>"
    b"<div id=menu></div></header>"
    + b"".join(b"<p>Row %d <a href=/row%d>Item %d</a></p>" % (n, n, n) for n in range(300))
    + b"<button id=foot aria-expanded=false>Cookies</button>"
    + b"".join(b"<p>Tail %d <a href=/tail%d>Tail item %d</a></p>" % (n, n, n) for n in range(400))
)
"""A page of over a thousand tree lines. A click on the first button opens a menu at the top and
changes the other button, far below it, so agent-browser's one splice holds all the rows between."""
BIG_MENU_PAGE = (
    b"<title>Big menu</title><header><button onclick=\"document.getElementById('menu').innerHTML = "
    b"'<ul>"
    + b"".join(b"<li><a href=/m%d>Menu entry %d</a></li>" % (n, n) for n in range(300))
    + b"</ul>'\">Account</button><div id=menu></div></header>"
    + b"".join(b"<p>Row %d <a href=/row%d>Item %d</a></p>" % (n, n, n) for n in range(300))
)
"""A menu of 300 entries on a page of 300 rows: so large a change that agent-browser sends the whole
tree again, not a delta, though the address is the same."""
PAGES = {
    "/": ({"Content-Type": "text/html"}, PAGE),
    "/bigmenu": ({"Content-Type": "text/html"}, BIG_MENU_PAGE),
    "/tall": ({"Content-Type": "text/html"}, TALL_PAGE),
    "/nav": ({"Content-Type": "text/html"}, NAV_PAGE),
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
                    # No snapshot yet: a baseline is taken for the click, and the change is told.
                    first = await c.call("click", site="demo", text="Menu")
                    assert first["change"]["kind"] == "delta"
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


@pytest.mark.integration
@needs_everything
def test_a_click_after_a_snapshot_of_only_the_nav_still_says_what_changed(short_dir: Path) -> None:
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
                    await c.call("navigate", site="demo", url="http://site.test/nav")
                    scoped = await c.call("snapshot", site="demo", selector="nav")
                    assert scoped["scope"] == "nav"
                    assert "Item 3" not in scoped["snapshot"]["text"]
                    opened = (await c.call("click", site="demo", text="Account"))["change"]
                    assert opened["kind"] == "delta"
                    added = opened["added"]["text"]
                    assert 'link "Orders"' in added
                    assert 'link "Settings"' in added
                    ref = re.search(r'link "Orders" \[ref=(e\d+)\]', added)
                    assert ref is not None
                    went = await c.call("click", site="demo", ref=ref.group(1))
                    assert went["url"].endswith("/orders")
            finally:
                await server.shutdown()

    run(scenario())


@pytest.mark.integration
@needs_everything
def test_a_menu_that_opens_far_from_another_change_is_still_listed(short_dir: Path) -> None:
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
                    await c.call("navigate", site="demo", url="http://site.test/tall")
                    whole = await c.call("snapshot", site="demo")
                    assert whole["snapshot"]["text"].count("\n") > 1000
                    change = (await c.call("click", site="demo", text="Account"))["change"]
                    assert (
                        change["kind"] == "delta"
                    )  # not "a lot": the rows between were carried along
                    added = change["added"]["text"]
                    assert 'link "Orders"' in added
                    assert 'link "Settings"' in added
                    assert "expanded=true" in added  # the other change is there too
                    assert 'link "Item 150"' not in added  # and the rows between are not
                    ref = re.search(r'link "Orders" \[ref=(e\d+)\]', added)
                    assert ref is not None
                    went = await c.call("click", site="demo", ref=ref.group(1))
                    assert went["url"].endswith("/orders")
            finally:
                await server.shutdown()

    run(scenario())


@pytest.mark.integration
@needs_everything
def test_a_click_with_an_expectation_lists_the_menu_it_opened(short_dir: Path) -> None:
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
                    await c.call("navigate", site="demo", url="http://site.test/tall")
                    await c.call("snapshot", site="demo")
                    clicked = await c.call(
                        "click",
                        site="demo",
                        text="Account",
                        expect={"text_appears": "Orders"},
                    )
                    assert clicked["outcome"] == "met"
                    change = clicked["change"]
                    assert change["kind"] == "delta", change  # not the text of a new page
                    added = change["added"]["text"]
                    assert 'link "Orders"' in added
                    assert 'link "Settings"' in added
                    ref = re.search(r'link "Orders" \[ref=(e\d+)\]', added)
                    assert ref is not None
                    went = await c.call("click", site="demo", ref=ref.group(1))
                    assert went["url"].endswith("/orders")
            finally:
                await server.shutdown()

    run(scenario())


@pytest.mark.integration
@needs_everything
def test_a_menu_so_large_that_the_whole_tree_comes_again_is_still_a_change(short_dir: Path) -> None:
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
                    await c.call("navigate", site="demo", url="http://site.test/bigmenu")
                    await c.call("snapshot", site="demo")
                    clicked = await c.call(
                        "click",
                        site="demo",
                        text="Account",
                        expect={"text_appears": "Menu entry 0"},
                    )
                    assert clicked["outcome"] == "met"
                    change = clicked["change"]
                    assert change["kind"] == "delta", change  # not the text of a new page
                    shown = change["added"]["text"].split("\n")
                    assert (
                        'link "Menu entry 0"' in shown[0]
                    )  # the lines with a reference come first
                    assert change["more"] > 0  # the entries that did not fit are counted
                    ref = re.search(r'link "Menu entry 0" \[ref=(e\d+)\]', change["added"]["text"])
                    assert ref is not None
                    went = await c.call("click", site="demo", ref=ref.group(1))
                    assert went["url"].endswith("/m0")
            finally:
                await server.shutdown()

    run(scenario())
