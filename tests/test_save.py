# SPDX-License-Identifier: Apache-2.0
"""``browser_save`` against a real browser: the picture comes from the site, through the proxy."""

import asyncio
import struct
import zlib
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from environment import unusable_reason
from proxy_stub import PageServer

from valetkey import client, daemon, sessions, sites
from valetkey.client import DaemonError

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Iterator

_SKIP_REASON = unusable_reason("bwrap", "chromium", "agent-browser")
needs_everything = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")
pytestmark = [pytest.mark.integration, needs_everything]


def png(width: int, height: int, colour: tuple[int, int, int]) -> bytes:
    """A real picture of one colour, which the browser can draw and measure."""

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    row = b"\x00" + bytes(colour) * width
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(row * height))
        + chunk(b"IEND", b"")
    )


SMALL = png(64, 64, (200, 0, 0))
BIG = png(128, 128, (0, 200, 0))
TINY = png(8, 8, (0, 0, 200))
BROCHURE = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\nthe brochure\n"
JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"j" * 200

SHOP = """<title>Shop</title><h1>Shop</h1>
<img src="/small.png" srcset="/small.png 1x, /big.png 2x" width="64" height="64" alt="Red shoe">
<img src="/tiny.png" alt="a dot">
<img src="/cdn-cgi/image/fit=contain,width=640/p.png" width="64" height="64" alt="By size"
 srcset="/cdn-cgi/image/fit=contain,width=640/p.png 640w,
 /cdn-cgi/image/fit=contain,width=1280/p.png 1280w">
<a href="/brochure.pdf">Brochure</a>
<a href="/invoice">Invoice</a>"""
GUARDED = {
    "Content-Type": "image/png",
    "Content-Security-Policy": "default-src 'none'; sandbox",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
}
"""What a picture service sends that a script in the page cannot read: no CSP exception, no CORS."""
FILES = {
    "/guarded.png": (GUARDED, BIG),
    "/cdn-cgi/image/fit=contain,width=640/p.png": (GUARDED, SMALL),
    "/cdn-cgi/image/fit=contain,width=1280/p.png": (GUARDED, BIG),
    "/small.png": ({"Content-Type": "image/png"}, SMALL),
    "/big.png": ({"Content-Type": "image/png"}, BIG),
    "/tiny.png": ({"Content-Type": "image/png"}, TINY),
    "/brochure.pdf": ({"Content-Type": "application/pdf"}, BROCHURE),
    "/noext": ({"Content-Type": "image/jpeg"}, JPEG),
    "/invoice": (
        {"Content-Type": "text/plain", "Content-Disposition": 'attachment; filename="invoice.txt"'},
        b"the invoice\n",
    ),
}


@pytest.fixture
def world(short_dir: Path) -> Iterator[tuple[sites.Roots, PageServer]]:
    runtime = short_dir / "rt"
    runtime.mkdir(mode=0o700)
    roots = sites.Roots(short_dir / "cfg", short_dir / "state", runtime)
    sites.save_policy(roots, sites.Policy("demo", "http://site.test/", ("site.test",)))
    with PageServer(
        {"/": SHOP}, redirects={"/moved": "/guarded.png", "/moved-twice": "/moved"}, files=FILES
    ) as pages:
        yield roots, pages


def run[T](scenario: Any) -> T:  # noqa: ANN401 - any awaitable
    return asyncio.run(asyncio.wait_for(scenario, 180))


async def session(
    roots: sites.Roots, pages: PageServer
) -> AsyncGenerator[tuple[client.Client, daemon.Daemon]]:
    async def resolve(_host: str, _port: int) -> list[str]:
        return ["127.0.0.1"]

    async def connect(_address: str, _port: int) -> Any:  # noqa: ANN401
        return await asyncio.open_connection(*pages.address)

    options = {"resolver": resolve, "connector": connect, "address_check": lambda _a: None}
    server = daemon.Daemon(roots, proxy_options=options)
    await server.start()
    try:
        async with await client.Client.connect(client.socket_path(roots)) as c:
            await c.call("open", site="demo")
            yield c, server
    finally:
        await server.shutdown()


def saved(result: dict[str, Any]) -> list[tuple[str, int, str]]:
    return [
        (Path(e["path"]["text"]).name, e["size"], e["mime"]) for e in result["downloads"]["new"]
    ]


def folder_of(roots: sites.Roots) -> Path:
    return sites.downloads_path(roots, "demo")


def only_tab_left(server: daemon.Daemon) -> list[dict[str, Any]]:
    live = server._sites["demo"].session  # noqa: SLF001 - what the browser really has open
    assert isinstance(live, sessions.Session)
    return live._call("tab", "list")["tabs"]  # noqa: SLF001


def test_a_picture_is_saved_by_address_with_its_name_size_and_type(
    world: tuple[sites.Roots, PageServer],
) -> None:
    roots, pages = world

    async def scenario() -> None:
        async for c, server in session(roots, pages):
            before = await c.call("snapshot", site="demo")
            result = await c.call("save", site="demo", url="http://site.test/big.png")
            assert saved(result) == [("big.png", len(BIG), "image/png")]
            assert (folder_of(roots) / "big.png").read_bytes() == BIG
            assert result["source"]["text"] == "http://site.test/big.png"
            assert "content" not in result["downloads"]["new"][0]  # no bytes in the answer
            # The page the agent was on did not move, and no tab was left behind.
            assert result["url"] == before["url"] == "http://site.test/"
            tabs = await asyncio.to_thread(only_tab_left, server)
            assert [t["url"] for t in tabs] == ["http://site.test/"]
            assert [t["active"] for t in tabs] == [True]

    run(scenario())


def test_saving_the_same_picture_again_never_replaces_the_first(
    world: tuple[sites.Roots, PageServer],
) -> None:
    roots, pages = world

    async def scenario() -> None:
        async for c, _ in session(roots, pages):
            await c.call("save", site="demo", url="http://site.test/big.png")
            again = await c.call("save", site="demo", url="http://site.test/big.png")
            assert saved(again) == [("big (2).png", len(BIG), "image/png")]
            assert sorted(
                p.name for p in folder_of(roots).iterdir() if not p.name.startswith(".")
            ) == [
                "big (2).png",
                "big.png",
            ]

    run(scenario())


def test_the_snapshot_lists_the_pictures_with_the_largest_srcset_address(
    world: tuple[sites.Roots, PageServer],
) -> None:
    roots, pages = world

    async def scenario() -> None:
        async for c, _ in session(roots, pages):
            plain = await c.call("snapshot", site="demo")
            assert "images" not in plain
            listed = await c.call("snapshot", site="demo", images=True)
            by_alt = {i["alt"]["text"]: i for i in listed["images"]}  # the 8 by 8 dot is too small
            assert sorted(by_alt) == ["By size", "Red shoe"]
            shoe, sized = by_alt["Red shoe"], by_alt["By size"]
            assert shoe["kind"] == "image"
            assert shoe["alt"] == {"untrusted": True, "text": "Red shoe"}
            assert shoe["url"] == {"untrusted": True, "text": "http://site.test/big.png"}
            assert (shoe["width"], shoe["height"]) == (64, 64)
            # Commas inside an address do not split it: the largest of the two is listed whole.
            assert (
                sized["url"]["text"]
                == "http://site.test/cdn-cgi/image/fit=contain,width=1280/p.png"
            )
            # The address it gave is one that save takes.
            result = await c.call("save", site="demo", url=shoe["url"]["text"])
            assert saved(result) == [("big.png", len(BIG), "image/png")]

    run(scenario())


def test_a_link_is_saved_by_its_reference(world: tuple[sites.Roots, PageServer]) -> None:
    roots, pages = world

    async def scenario() -> None:
        async for c, _ in session(roots, pages):
            snap = await c.call("snapshot", site="demo")
            ref = next(r for r, role in snap["refs"].items() if role == "link")
            result = await c.call("save", site="demo", ref=ref)
            assert saved(result) == [("brochure.pdf", len(BROCHURE), "application/pdf")]
            assert result["source"]["text"] == "http://site.test/brochure.pdf"

    run(scenario())


def test_a_file_the_server_calls_an_attachment_is_saved_too(
    world: tuple[sites.Roots, PageServer],
) -> None:
    roots, pages = world

    async def scenario() -> None:
        async for c, server in session(roots, pages):
            result = await c.call("save", site="demo", url="http://site.test/invoice")
            assert saved(result) == [("invoice.txt", len(b"the invoice\n"), "text/plain")]
            tabs = await asyncio.to_thread(only_tab_left, server)
            assert [t["url"] for t in tabs] == ["http://site.test/"]

    run(scenario())


def test_an_address_with_no_file_name_gets_one_from_its_type(
    world: tuple[sites.Roots, PageServer],
) -> None:
    roots, pages = world

    async def scenario() -> None:
        async for c, _ in session(roots, pages):
            result = await c.call("save", site="demo", url="http://site.test/noext")
            assert saved(result) == [("noext.jpg", len(JPEG), "image/jpeg")]

    run(scenario())


def test_a_host_the_site_may_not_reach_is_refused_and_nothing_is_saved(
    world: tuple[sites.Roots, PageServer],
) -> None:
    roots, pages = world

    async def scenario() -> None:
        async for c, server in session(roots, pages):
            with pytest.raises(DaemonError) as info:
                await c.call("save", site="demo", url="http://evil.test/x.png")
            assert info.value.code == "browser_error"
            assert {entry["host"] for entry in info.value.details["refused"]} == {"evil.test"}
            assert [p.name for p in folder_of(roots).iterdir() if not p.name.startswith(".")] == []
            tabs = await asyncio.to_thread(only_tab_left, server)
            assert [t["url"] for t in tabs] == ["http://site.test/"]

    run(scenario())


def test_an_address_the_server_does_not_have_is_an_error_and_saves_nothing(
    world: tuple[sites.Roots, PageServer],
) -> None:
    roots, pages = world

    async def scenario() -> None:
        async for c, _ in session(roots, pages):
            with pytest.raises(DaemonError) as info:
                await c.call("save", site="demo", url="http://site.test/missing.png")
            assert "404" in info.value.message
            assert [p.name for p in folder_of(roots).iterdir() if not p.name.startswith(".")] == []

    run(scenario())


def test_a_file_over_the_limit_is_not_saved(
    world: tuple[sites.Roots, PageServer], monkeypatch: pytest.MonkeyPatch
) -> None:
    roots, pages = world
    monkeypatch.setattr(sessions, "SAVE_LIMIT", len(BIG) - 1)
    monkeypatch.setattr(sessions, "_TOO_BIG", f"the file is larger than {len(BIG) - 1} bytes")

    async def scenario() -> None:
        async for c, _ in session(roots, pages):
            with pytest.raises(DaemonError) as info:
                await c.call("save", site="demo", url="http://site.test/big.png")
            assert f"larger than {len(BIG) - 1} bytes" in info.value.message
            assert [p.name for p in folder_of(roots).iterdir() if not p.name.startswith(".")] == []
            # A file under it still goes.
            small = await c.call("save", site="demo", url="http://site.test/small.png")
            assert saved(small) == [("small.png", len(SMALL), "image/png")]

    run(scenario())


def test_a_picture_whose_own_policy_forbids_scripts_is_saved(
    world: tuple[sites.Roots, PageServer],
) -> None:
    """A script fetching it from a page of its own address is blocked, so none is used."""
    roots, pages = world

    async def scenario() -> None:
        async for c, server in session(roots, pages):
            result = await c.call("save", site="demo", url="http://site.test/guarded.png")
            assert saved(result) == [("guarded.png", len(BIG), "image/png")]
            assert (folder_of(roots) / "guarded.png").read_bytes() == BIG
            tabs = await asyncio.to_thread(only_tab_left, server)
            assert [t["url"] for t in tabs] == ["http://site.test/"]

    run(scenario())


@pytest.mark.parametrize("start", ["/moved", "/moved-twice"])
def test_a_picture_behind_redirects_is_saved_under_the_name_it_ends_at(
    world: tuple[sites.Roots, PageServer], start: str
) -> None:
    roots, pages = world

    async def scenario() -> None:
        async for c, _ in session(roots, pages):
            result = await c.call("save", site="demo", url=f"http://site.test{start}")
            assert saved(result) == [("guarded.png", len(BIG), "image/png")]
            assert result["source"]["text"] == f"http://site.test{start}"

    run(scenario())


def test_a_picture_listed_with_commas_in_its_address_is_saved(
    world: tuple[sites.Roots, PageServer],
) -> None:
    roots, pages = world

    async def scenario() -> None:
        async for c, _ in session(roots, pages):
            listed = await c.call("snapshot", site="demo", images=True)
            address = next(i for i in listed["images"] if i["alt"]["text"] == "By size")["url"][
                "text"
            ]
            result = await c.call("save", site="demo", url=address)
            assert saved(result) == [("p.png", len(BIG), "image/png")]

    run(scenario())


@pytest.mark.parametrize(
    ("address", "scheme"),
    [("data:image/png;base64,AAAA", "data"), ("blob:http://site.test/1", "blob")],
)
def test_a_data_or_blob_address_is_refused_with_the_reason(
    world: tuple[sites.Roots, PageServer], address: str, scheme: str
) -> None:
    roots, pages = world

    async def scenario() -> None:
        async for c, _ in session(roots, pages):
            with pytest.raises(DaemonError) as info:
                await c.call("save", site="demo", url=address)
            assert f"the address is a {scheme}: URL" in info.value.message
            assert "nothing to fetch from a server" in info.value.message

    run(scenario())
