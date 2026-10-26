# SPDX-License-Identifier: Apache-2.0
"""A login on a machine with no screen, shown in a web browser: the real thing, end to end.

A real daemon starts a login with no display to use, so it opens a private sway, wayvnc, the
gateway and a contained Chromium. The test fetches the viewer with the link, opens the WebSocket
and reads the VNC banner, checks what the gateway refuses, then ends the login in two ways (the
person closes the window, and the daemon is stopped) and checks that nothing is left.
"""

import asyncio
import base64
import json
import os
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from environment import unusable_reason
from proxy_stub import PageServer

from valetkey import client, daemon, display, login, sites

if TYPE_CHECKING:
    from collections.abc import Awaitable

_PROBLEM = unusable_reason("bwrap", "chromium", "sway", "swaymsg", "wayvnc", "ss")
if _PROBLEM is None:
    try:
        display.novnc_root()
    except display.RemoteDisplayError:
        _PROBLEM = "the noVNC viewer is not fetched; run `just novnc`"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(_PROBLEM is not None, reason=_PROBLEM or ""),
]

PAGES = {"/": "<title>Sign in</title><input placeholder='Your name'>"}


def run[T](scenario: Awaitable[T]) -> T:
    return asyncio.run(asyncio.wait_for(scenario, 120))


class Screenless:
    """``login.start_login``, except that it finds no screen of its own to open a window on."""

    async def __call__(self, *args: Any, **options: Any) -> login.LoginHandle:  # noqa: ANN401
        if "wayland_socket" not in options:
            message = "no desktop session here"
            raise login.NoDisplayError(message)
        return await login.start_login(*args, **options)


def swaymsg(directory: Path, *arguments: str) -> str:
    socket_path = next(directory.glob("sway-ipc.*.sock"))
    environment = {"PATH": os.environ["PATH"], "SWAYSOCK": str(socket_path)}
    result = subprocess.run(  # noqa: S603 - fixed arguments, a socket of this test's own
        ["swaymsg", *arguments],  # noqa: S607 - from PATH
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    return result.stdout


def chromium_windows(directory: Path) -> list[str]:
    def walk(node: dict[str, Any]) -> list[str]:
        found = [node["app_id"]] if node.get("app_id") else []
        for child in (*node.get("nodes", []), *node.get("floating_nodes", [])):
            found += walk(child)
        return found

    tree = json.loads(swaymsg(directory, "-t", "get_tree", "-r"))
    return [app for app in walk(tree) if app == "chromium"]


def belonging_to(directory: Path) -> list[tuple[int, str]]:
    """Processes that have ``directory`` in their arguments or environment (and nothing else)."""
    needle = str(directory).encode()
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            arguments = (entry / "cmdline").read_bytes()
            environment = (entry / "environ").read_bytes()
        except OSError:
            continue
        if needle in arguments or needle in environment:
            found.append((int(entry.name), arguments.replace(b"\0", b" ").decode(errors="replace")))
    return found


def listening(port: int, directory: Path) -> str:
    """What ``ss`` lists for the TCP port, and for unix sockets under ``directory``."""
    tcp = subprocess.run(  # noqa: S603 - fixed arguments
        ["ss", "-ltnH", f"sport = :{port}"],  # noqa: S607 - from PATH
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    unix = subprocess.run(
        ["ss", "-lxH"],  # noqa: S607 - from PATH
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return tcp + "".join(line for line in unix.splitlines(keepends=True) if str(directory) in line)


def fetch(url: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(url, headers=headers or {})  # noqa: S310 - a loopback URL
    try:
        with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        with error:
            return error.code, dict(error.headers), error.read()


def websocket_banner(
    port: int, token: str, origin: str | None, cookie: str | None = None
) -> tuple[str, bytes]:
    """Open the viewer's WebSocket and return the status line and the first frame's payload."""
    with socket.create_connection(("127.0.0.1", port), timeout=15) as connection:
        key = base64.b64encode(os.urandom(16)).decode()
        lines = [
            f"GET /{token}/websockify HTTP/1.1",
            f"Host: 127.0.0.1:{port}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
            "Sec-WebSocket-Protocol: binary",
        ]
        if origin:
            lines.append(f"Origin: {origin}")
        if cookie:
            lines.append(f"Cookie: {cookie}")
        connection.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        data = b""
        while b"\r\n\r\n" not in data:
            data += connection.recv(4096)
        head, _, rest = data.partition(b"\r\n\r\n")
        status = head.decode().splitlines()[0]
        if " 101 " not in status:
            return status, b""
        while len(rest) < 14:
            rest += connection.recv(4096)
        return status, rest[2 : 2 + rest[1]]


async def eventually(check: Any, limit: float = 90) -> None:  # noqa: ANN401 - a callable
    deadline = time.monotonic() + limit
    while not check():
        assert time.monotonic() < deadline, "timed out"
        await asyncio.sleep(0.2)


async def start_remote_login(
    roots: sites.Roots, pages: PageServer, socket_path: Path
) -> tuple[daemon.Daemon, asyncio.Task[int], dict[str, Any]]:
    async def resolve(_host: str, _port: int) -> list[str]:
        return ["127.0.0.1"]

    async def connect(_address: str, _port: int) -> Any:  # noqa: ANN401
        return await asyncio.open_connection(*pages.address)

    options = {"resolver": resolve, "connector": connect, "address_check": lambda _a: None}
    server = daemon.Daemon(roots, login_starter=Screenless(), proxy_options=options)
    ready = asyncio.Event()
    task = asyncio.ensure_future(daemon.run(server, socket_path, ready=ready))
    await ready.wait()
    async with await client.Client.connect(socket_path) as c:
        answer = await c.call("login", target="http://login.test/")
    assert answer["window"] == "open"
    return server, task, answer["remote"]


def assert_nothing_is_left(directory: Path, port: int, profile: Path) -> None:
    assert not directory.exists(), "the display's directory is still there"
    assert listening(port, directory) == "", "something still listens"
    assert belonging_to(directory) == [], "sway or wayvnc is still running"
    assert belonging_to(profile) == [], "the login's browser is still running"


@pytest.fixture
def roots(short_dir: Path) -> sites.Roots:
    (short_dir / "r").mkdir(mode=0o700)
    roots = sites.Roots(short_dir / "c", short_dir / "s", short_dir / "r")
    config = roots.config / "valetkey" / "config.json"
    config.parent.mkdir(parents=True)
    config.write_text('{"remote_logins": {"novnc": true}}', encoding="utf-8")
    return roots


async def check_the_link(port: int, token: str, url: str) -> None:
    """Load the viewer once with the link, then try what a copied link and a stranger can do."""
    status, headers, body = await asyncio.to_thread(fetch, url)
    assert status == 200
    assert b"noVNC" in body
    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Content-Security-Policy"] == "frame-ancestors 'none'"
    cookie = headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie
    pair = cookie.split(";")[0]
    # The link is spent: the same address without the cookie is refused.
    assert (await asyncio.to_thread(fetch, url))[0] == 404
    assert (await asyncio.to_thread(fetch, url, {"Cookie": pair}))[0] == 200
    other = f"http://127.0.0.1:{port}/not-the-token/vnc.html"
    assert (await asyncio.to_thread(fetch, other))[0] == 404
    no_cookie = await asyncio.to_thread(websocket_banner, port, token, f"http://127.0.0.1:{port}")
    assert no_cookie[0].split()[1] == "404"
    refused = await asyncio.to_thread(websocket_banner, port, token, "https://evil.example", pair)
    assert refused[0].split()[1] == "403"
    status_line, banner = await asyncio.to_thread(
        websocket_banner, port, token, f"http://127.0.0.1:{port}", pair
    )
    assert " 101 " in status_line
    assert banner.startswith(b"RFB 003.")


def test_a_login_with_no_screen_is_shown_in_a_web_browser_and_ends_with_the_window(
    roots: sites.Roots, short_dir: Path
) -> None:
    directory = sites.runtime_path(roots) / "displays" / "login"
    profile = sites.profile_path(roots, "login")

    async def scenario() -> None:
        with PageServer(PAGES) as pages:
            server, task, remote = await start_remote_login(roots, pages, short_dir / "d.sock")
            port, url = remote["port"], remote["url"]
            token = url.split("/")[3]
            assert url.startswith(f"http://127.0.0.1:{port}/{token}/vnc.html?")
            assert remote["ssh"].startswith(f"ssh -L {port}:localhost:{port} ")
            try:
                await check_the_link(port, token, url)
                await eventually(lambda: chromium_windows(directory))
                swaymsg(directory, "[app_id=chromium]", "kill")  # the person closes the window
                async with await client.Client.connect(short_dir / "d.sock") as c:
                    hidden = (await c.call("status"))["logins"]
                    assert "remote" not in hidden[0]
                    shown = (await c.call("status", links=True))["logins"]
                    assert shown[0]["remote"]["url"] == url

                    async def idle() -> bool:
                        return not (await c.call("status"))["logins"]

                    deadline = time.monotonic() + 60
                    while not await idle():
                        assert time.monotonic() < deadline, "the login did not end"
                        await asyncio.sleep(0.2)
                # The window is closed and the daemon still runs: the display is gone anyway.
                await asyncio.to_thread(assert_nothing_is_left, directory, port, profile)
            finally:
                os.kill(os.getpid(), signal.SIGTERM)
                assert await task == 0
            del server
            await asyncio.to_thread(assert_nothing_is_left, directory, port, profile)

    run(scenario())


def test_stopping_the_daemon_takes_the_whole_display_with_it(
    roots: sites.Roots, short_dir: Path
) -> None:
    directory = sites.runtime_path(roots) / "displays" / "login"
    profile = sites.profile_path(roots, "login")

    async def scenario() -> None:
        with PageServer(PAGES) as pages:
            _, task, remote = await start_remote_login(roots, pages, short_dir / "d.sock")
            port = remote["port"]
            await eventually(lambda: chromium_windows(directory))
            assert listening(port, directory) != ""
            os.kill(os.getpid(), signal.SIGTERM)
            assert await task == 0
            await asyncio.to_thread(assert_nothing_is_left, directory, port, profile)

    run(scenario())
