# SPDX-License-Identifier: Apache-2.0
"""``browser_console`` on a real page that throws, logs, and makes requests that fail."""

import asyncio
import time
from typing import TYPE_CHECKING, Any

import pytest
from environment import unusable_reason
from proxy_stub import PageServer

from valetkey import client, daemon, sites

if TYPE_CHECKING:
    from pathlib import Path

_SKIP_REASON = unusable_reason("bwrap", "chromium", "agent-browser")
needs_everything = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")

PAGE = """<title>Stuck</title><p>Loading...</p>
<script>
console.log("plain log");
console.warn("a warning");
console.error("an error", {a: 1});
fetch("/missing").then((r) => console.error("answer " + r.status));
fetch("https://blocked.test/x").catch((e) => console.error("blocked " + e));
setTimeout(() => { throw new Error("kaboom"); }, 100);
setTimeout(() => { Promise.reject(new Error("rejected")); }, 150);
</script>
"""


def run[T](scenario: Any) -> T:  # noqa: ANN401 - any awaitable
    return asyncio.run(asyncio.wait_for(scenario, 180))


async def settled(c: client.Client) -> dict[str, Any]:
    """Ask for the console until the page has thrown both errors, made its requests and logged."""
    deadline = time.monotonic() + 30
    while True:
        result = await c.call("console", site="demo")
        if (
            result["errors"]["total"] >= 2
            and result["console"]["total"] >= 4
            and result["requests"]["total"] >= 2
        ):
            return result
        assert time.monotonic() < deadline, result
        await asyncio.sleep(0.3)


def texts(section: dict[str, Any], key: str = "text") -> list[str]:
    return [entry[key]["text"] for entry in section["entries"]]


@pytest.mark.integration
@needs_everything
def test_a_page_that_fails_shows_its_errors_console_and_failed_requests(short_dir: Path) -> None:
    runtime = short_dir / "rt"
    runtime.mkdir(mode=0o700)
    roots = sites.Roots(short_dir / "cfg", short_dir / "state", runtime)
    sites.save_policy(roots, sites.Policy("demo", "http://site.test/", ("site.test",)))

    async def resolve(_host: str, _port: int) -> list[str]:
        return ["127.0.0.1"]

    async def scenario() -> None:
        with PageServer({"/": PAGE}) as pages:

            async def connect(_address: str, _port: int) -> Any:  # noqa: ANN401
                return await asyncio.open_connection(*pages.address)

            options = {"resolver": resolve, "connector": connect, "address_check": lambda _a: None}
            server = daemon.Daemon(roots, proxy_options=options)
            await server.start()
            try:
                async with await client.Client.connect(client.socket_path(roots)) as c:
                    await c.call("open", site="demo")
                    result = await settled(c)
                    errors = texts(result["errors"])
                    assert any("kaboom" in text for text in errors)
                    assert any("rejected" in text for text in errors)
                    assert all(e["line"] is not None for e in result["errors"]["entries"])
                    console = [
                        (e["level"], e["text"]["text"]) for e in result["console"]["entries"]
                    ]
                    assert ("warning", "a warning") in console
                    assert any(lvl == "error" and "an error" in text for lvl, text in console)
                    assert ("error", "answer 404") in console
                    assert any(
                        "blocked" in text and "Failed to fetch" in text for _, text in console
                    )
                    assert not any("plain log" in text for _, text in console)
                    failed = {
                        e["request"]["text"]: (e["status"], e["refused"])
                        for e in result["requests"]["entries"]
                    }
                    assert failed["GET http://site.test/missing"] == (404, False)
                    assert failed["GET https://blocked.test/x"] == (None, True)
                    assert "GET http://site.test/" not in failed  # the page itself was fine
                    # Clearing empties the buffers: the next call shows only what came after.
                    await c.call("console", site="demo", clear=True)
                    after = await c.call("console", site="demo")
                    assert after["errors"]["total"] == 0
                    assert after["console"]["total"] == 0
                    assert after["requests"]["total"] == 0
            finally:
                await server.shutdown()

    run(scenario())
