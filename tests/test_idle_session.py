# SPDX-License-Identifier: Apache-2.0
"""A real browser session that nobody uses is closed by the daemon, and opens again logged in."""

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

PAGES = {
    "/": (
        {"Content-Type": "text/html", "Set-Cookie": "token=kept; Max-Age=3600; Path=/"},
        b"<title>Welcome</title><p>signed in</p>",
    ),
    "/who": (
        {"Content-Type": "text/html"},
        b"<title>who</title><script>document.title = 'cookie:' + document.cookie</script>",
    ),
}
IDLE_SECONDS = 4.0


def run[T](scenario: Any) -> T:  # noqa: ANN401 - any awaitable
    return asyncio.run(asyncio.wait_for(scenario, 180))


@pytest.mark.integration
@needs_everything
def test_a_session_nobody_uses_closes_and_opens_again_still_logged_in(short_dir: Path) -> None:
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
            server = daemon.Daemon(
                roots, proxy_options=options, idle_limit=IDLE_SECONDS, poll_interval=0.2
            )
            await server.start()
            try:
                async with await client.Client.connect(client.socket_path(roots)) as c:
                    await c.call("open", site="demo")
                    first = await c.call("navigate", site="demo", url="http://site.test/")
                    assert first["page"]["title"]["text"] == "Welcome"
                    for _ in range(100):
                        if not (await c.call("status"))["sessions"]:
                            break
                        await asyncio.sleep(0.2)
                    assert (await c.call("status"))["sessions"] == []
                    with pytest.raises(client.DaemonError) as info:
                        await c.call("snapshot", site="demo")
                    assert info.value.code == "session_idle"
                    assert "Call browser_open" in info.value.message
                    assert sites.profile_path(roots, "demo").is_dir()
                    await c.call("open", site="demo")
                    again = await c.call("navigate", site="demo", url="http://site.test/who")
                    assert again["page"]["title"]["text"] == "cookie:token=kept"
            finally:
                await server.shutdown()

    run(scenario())
