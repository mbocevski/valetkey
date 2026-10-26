# SPDX-License-Identifier: Apache-2.0
"""A login through a sign-in provider on other domains, and a session that needs them later.

The site sends the browser to a provider on another registrable domain. The provider's page loads
its script from a CDN host of its own, exchanges a token with an XHR and sends the browser back
without anyone touching it, so none of its hosts ever shows the person a page. Later the site's
page makes a silent refresh to the provider. If the login left out any of those hosts, the refresh
fails. The test runs a real browser against all four host names, served by one local listener.
"""

import asyncio
import contextlib
import functools
import time
from typing import TYPE_CHECKING, Any

import pytest
from environment import unusable_reason
from sway import Sway

from valetkey import client, daemon, login, sites

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

_SKIP_REASON = unusable_reason("bwrap", "chromium", "agent-browser", "sway", "swaymsg")
needs_everything = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")

SITE, IDP, IDP_CDN, TRACKER = (
    "app.shop.test",
    "login.idp.test",
    "static.idpcdn.test",
    "ads.beacon.test",
)
SESSION = "session=ok"
IDP_SCRIPT = (
    "fetch('/token').then(r => r.json()).then(t => setTimeout("
    f"() => {{ location.href = 'http://{SITE}/callback?code=' + t.code; }}, 300));"
)
APP = (
    "<title>Dashboard</title><h1 id=s>refreshing</h1>"
    f"<script src='http://{TRACKER}/pixel.js'></script>"
    "<script>"
    f"fetch('http://{IDP}/silent').then(r => r.text()).then(t => {{"
    "document.getElementById('s').textContent = 'silent ' + t;"
    "}).catch(() => { document.getElementById('s').textContent = 'silent failed'; });"
    "</script>"
)


def respond(status: int, body: str, **headers: str) -> bytes:
    reason = {200: "OK", 302: "Found", 404: "Not Found"}[status]
    head = f"HTTP/1.1 {status} {reason}\r\nConnection: close\r\n"
    head += "".join(f"{name.replace('_', '-')}: {value}\r\n" for name, value in headers.items())
    return (head + f"Content-Length: {len(body.encode())}\r\n\r\n{body}").encode()


class Providers:
    """One listener that answers as the site, the provider, its CDN and a tracker."""

    def __init__(self) -> None:
        self.log: list[tuple[str, str]] = []
        self.port = 0

    def answer(self, host: str, path: str, cookie: str) -> bytes:  # noqa: PLR0911 - one route each
        page = {"Content_Type": "text/html"}
        if host == SITE:
            if path == "/callback":
                return respond(302, "", Location="/", Set_Cookie=f"{SESSION}; Path=/; Max-Age=3600")
            if path == "/" and SESSION not in cookie:
                return respond(302, "", Location=f"http://{IDP}/authorize")
            if path == "/":
                return respond(200, APP, **page)
        if host == IDP and path == "/authorize":
            return respond(200, f"<script src='http://{IDP_CDN}/idp.js'></script>", **page)
        if host == IDP and path == "/token":
            return respond(200, '{"code": "abc"}', Content_Type="application/json")
        if host == IDP and path == "/silent":
            return respond(200, "ok", Access_Control_Allow_Origin=f"http://{SITE}")
        if host == IDP_CDN and path == "/idp.js":
            return respond(200, IDP_SCRIPT, Content_Type="text/javascript")
        if host == TRACKER and path == "/pixel.js":
            return respond(200, "", Content_Type="text/javascript")
        return respond(404, "not found")

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        with contextlib.suppress(OSError, asyncio.IncompleteReadError):
            head = (await reader.readuntil(b"\r\n\r\n")).decode("latin-1")
            first, *lines = head.split("\r\n")
            headers = {k.lower(): v for k, _, v in (ln.partition(": ") for ln in lines if ln)}
            host = headers.get("host", "").split(":")[0]
            path = first.split(" ")[1].split("?")[0]
            self.log.append((host, path))
            writer.write(self.answer(host, path, headers.get("cookie", "")))
            await writer.drain()
        writer.close()

    @contextlib.asynccontextmanager
    async def serving(self) -> Any:  # noqa: ANN401 - an async generator
        server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = server.sockets[0].getsockname()[1]
        try:
            yield self
        finally:
            server.close()
            server.close_clients()
            await server.wait_closed()

    def proxy_options(self) -> dict[str, Any]:
        async def resolve(_host: str, _port: int) -> list[str]:
            return ["127.0.0.1"]

        async def connect(_address: str, _port: int) -> tuple[Any, Any]:
            return await asyncio.open_connection("127.0.0.1", self.port)

        return {"resolver": resolve, "connector": connect, "address_check": lambda _a: None}

    def reached(self, host: str, path: str) -> bool:
        return (host, path) in self.log


@pytest.fixture
def desktop(short_dir: Path) -> Iterator[Sway]:
    (short_dir / "sw").mkdir(mode=0o700)
    sway = Sway(short_dir / "sw")
    try:
        sway.start()
        yield sway
    finally:
        sway.stop()


async def wait_for(check: Any, what: str, limit: float = 60) -> None:  # noqa: ANN401
    deadline = time.monotonic() + limit
    while not check():
        assert time.monotonic() < deadline, what
        await asyncio.sleep(0.2)


@pytest.mark.integration
@needs_everything
def test_a_session_can_use_the_providers_hosts_its_login_used(
    short_dir: Path, desktop: Sway
) -> None:
    roots = sites.Roots(short_dir / "cfg", short_dir / "state", short_dir / "rt")
    (short_dir / "rt").mkdir(mode=0o700)

    async def scenario() -> None:
        async with Providers().serving() as hosts:
            options = hosts.proxy_options()
            starter = functools.partial(
                login.start_login, wayland_socket=desktop.display, proxy_options=options
            )
            server = daemon.Daemon(roots, login_starter=starter, proxy_options=options)
            await server.start()
            try:
                async with await client.Client.connect(client.socket_path(roots)) as c:
                    name = (await c.call("login", target=f"http://{SITE}/"))["site"]
                    await wait_for(lambda: hosts.reached(SITE, "/callback"), f"{hosts.log}")
                    await wait_for(lambda: hosts.log.count((SITE, "/")) >= 2, f"{hosts.log}")
                    await asyncio.sleep(1)
                    await desktop.msg("[app_id=chromium]", "kill")
                    await wait_for(lambda: server._sites[name].kind == "idle", "still logging in")  # noqa: SLF001
                    policy = sites.load_policy(roots, name)
                    for host in (SITE, IDP, IDP_CDN):
                        assert sites.allows(policy, host), (host, policy)
                    assert not sites.allows(policy, TRACKER)
                    assert TRACKER in policy.excluded

                    # No `valetkey allow`: the page's silent refresh reaches the provider.
                    await c.call("open", site=name)
                    seen = ""
                    for _ in range(50):
                        snapshot = await c.call("snapshot", site=name)
                        seen = str(snapshot["snapshot"])
                        if "silent" in seen:
                            break
                        await asyncio.sleep(0.2)
                    assert "silent ok" in seen, seen
                    await c.call("close", site=name)
            finally:
                await server.shutdown()

    asyncio.run(asyncio.wait_for(scenario(), 240))
