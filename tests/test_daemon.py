# SPDX-License-Identifier: Apache-2.0
import asyncio
import contextlib
import json
import os
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from environment import unusable_reason
from proxy_stub import PageServer

from valetkey import clicks, client, daemon, login, sessions, sites
from valetkey.client import DaemonError
from valetkey.proxy import SeenHost

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Awaitable, Callable

type Finish = Callable[[list[SeenHost], Path], Awaitable[None]]
NOW = datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC)


def run[T](scenario: Awaitable[T]) -> T:
    return asyncio.run(asyncio.wait_for(scenario, 60))


# -- pure pieces ---------------------------------------------------------------------------


def test_parse_request() -> None:
    request = daemon.parse_request(b'{"id": 7, "op": "open", "args": {"site": "sitex"}}\n')
    assert request == daemon.Request(7, "open", {"site": "sitex"})
    assert daemon.parse_request(b'{"id": "a", "op": "sites"}') == daemon.Request("a", "sites", {})
    assert daemon.parse_request(b'{"op": "sites"}').id is None


@pytest.mark.parametrize(
    ("line", "request_id"),
    [
        (b"", None),
        (b"not json", None),
        (b"[1, 2]", None),
        (b'"text"', None),
        (b'{"id": 3}', 3),
        (b'{"id": 3, "op": ""}', 3),
        (b'{"id": 3, "op": 5}', 3),
        (b'{"id": "x", "op": "open", "args": [1]}', "x"),
        (b'{"id": true, "op": 5}', None),
        (b'{"id": [1], "op": 5}', None),
    ],
)
def test_parse_request_rejects_bad_lines(line: bytes, request_id: int | str | None) -> None:
    with pytest.raises(DaemonError) as info:
        daemon.parse_request(line)
    assert info.value.code == "bad_request"
    assert daemon.request_id_of(info.value) == request_id


def test_request_id_of_other_errors_is_none() -> None:
    assert daemon.request_id_of(DaemonError("x", "y")) is None


def test_responses_are_single_compact_lines() -> None:
    ok = daemon.ok_response(4, {"a": "é\n"})
    assert ok.endswith(b"\n")
    assert ok.count(b"\n") == 1
    assert json.loads(ok) == {"id": 4, "ok": True, "result": {"a": "é\n"}}
    error = daemon.error_response(None, DaemonError("unknown_op", "no", {"k": 1}))
    assert json.loads(error) == {
        "id": None,
        "ok": False,
        "error": {"code": "unknown_op", "message": "no", "details": {"k": 1}},
    }
    assert daemon.untrusted("hi") == {"untrusted": True, "text": "hi"}


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (login.X11OnlyError("x"), "x11_only"),
        (login.NoDisplayError("x"), "no_display"),
        (sessions.AgentBrowserError("x"), "browser_error"),
        (sessions.VersionError("x"), "session_failed"),
        (sessions.SessionError("x"), "session_failed"),
        (sites.PolicyError("x"), "bad_policy"),
        (ValueError("x"), "bad_request"),
        (RuntimeError("secret detail"), "internal"),
        (DaemonError("unknown_site", "x"), "unknown_site"),
    ],
)
def test_map_error(error: Exception, code: str) -> None:
    mapped = daemon.map_error(error)
    assert mapped.code == code
    assert "secret" not in mapped.message


def test_daemon_error_carries_details() -> None:
    error = DaemonError("c", "m", {"a": 1})
    assert (error.code, error.message, error.details) == ("c", "m", {"a": 1})
    assert error.to_json() == {"code": "c", "message": "m", "details": {"a": 1}}
    assert DaemonError("c", "m").to_json() == {"code": "c", "message": "m"}


@pytest.mark.parametrize(
    ("environ", "count"),
    [
        ({}, 0),
        ({"LISTEN_PID": "10", "LISTEN_FDS": "1"}, 1),
        ({"LISTEN_PID": "10", "LISTEN_FDS": "3"}, 3),
        ({"LISTEN_PID": "11", "LISTEN_FDS": "1"}, 0),
        ({"LISTEN_PID": "10"}, 0),
        ({"LISTEN_FDS": "1"}, 0),
        ({"LISTEN_PID": "x", "LISTEN_FDS": "1"}, 0),
        ({"LISTEN_PID": "10", "LISTEN_FDS": "many"}, 0),
        ({"LISTEN_PID": "10", "LISTEN_FDS": "-2"}, 0),
    ],
)
def test_listen_fds(environ: dict[str, str], count: int) -> None:
    assert daemon.listen_fds(environ, 10) == count


def test_activated_socket(short_dir: Path) -> None:
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(short_dir / "a.sock"))
        listener.listen()
        pid = os.getpid()
        environ = {"LISTEN_PID": str(pid), "LISTEN_FDS": "1"}
        assert daemon.activated_socket({}, pid) is None
        assert daemon.activated_socket({"LISTEN_PID": "1", "LISTEN_FDS": "1"}, pid) is None
        descriptor = os.dup(listener.fileno())
        inherited = daemon.activated_socket(environ, pid, descriptor)
        assert inherited is not None
        with inherited:
            assert inherited.family == socket.AF_UNIX
            assert inherited.getsockname() == str(short_dir / "a.sock")
            assert not inherited.get_inheritable()
            assert inherited.getblocking() is False


def test_activated_socket_must_be_a_unix_stream_socket() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as other:
        descriptor = os.dup(other.fileno())
        environ = {"LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "1"}
        with pytest.raises(ValueError, match="Unix stream"):
            daemon.activated_socket(environ, os.getpid(), descriptor)


def test_peer_uid_reads_the_other_end() -> None:
    left, right = socket.socketpair()
    with left, right:
        assert daemon.peer_uid(left) == os.getuid()


def test_make_private_dirs(short_dir: Path) -> None:
    target = short_dir / "a" / "b" / "c"
    daemon.make_private_dirs(target)
    daemon.make_private_dirs(target)
    for path in (target, target.parent, target.parent.parent):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700


def test_socket_path_is_in_the_runtime_dir(short_dir: Path) -> None:
    roots = sites.Roots(short_dir / "c", short_dir / "s", short_dir / "r")
    assert client.socket_path(roots) == short_dir / "r" / "valetkey" / "daemon.sock"
    with pytest.raises(sites.RuntimeDirUnavailableError):
        client.socket_path(sites.Roots(short_dir, short_dir, None))


def test_socket_path_defaults_to_the_environment(
    monkeypatch: pytest.MonkeyPatch, short_dir: Path
) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(short_dir))
    assert client.socket_path() == short_dir / "valetkey" / "daemon.sock"


# -- fakes ---------------------------------------------------------------------------------


class FakeSession:
    """A browser session that records calls and checks nobody uses it twice at once."""

    def __init__(
        self, url: str = "https://sitex.test/", title: str = "Start", delay: float = 0
    ) -> None:
        self.first_page = sessions.Page(url, title)
        self.url = url
        self.delay = delay
        self.alive = True
        self.closed = 0
        self.calls: list[tuple[Any, ...]] = []
        self.fail: Exception | None = None
        self.close_error: Exception | None = None
        self.texts: list[str] = []
        self.on_click: Callable[[], None] | None = None
        self.active = 0
        self.most_active = 0
        self._lock = threading.Lock()

    def _use(self, *call: Any) -> None:  # noqa: ANN401 - whatever the call was
        with self._lock:
            self.active += 1
            self.most_active = max(self.most_active, self.active)
        try:
            time.sleep(self.delay)
            self.calls.append(call)
            if self.fail is not None:
                raise self.fail
        finally:
            with self._lock:
                self.active -= 1

    def open(self, url: str) -> sessions.Page:
        self._use("open", url)
        self.url = url
        return sessions.Page(url, f"Title of {url}")

    def snapshot(self) -> sessions.Snapshot:
        self._use("snapshot")
        return sessions.Snapshot(
            self.url, '- button "Go" [ref=e1]', {"e1": sessions.Ref("button", "Go")}
        )

    def outline(self) -> str:
        texts = [f'- StaticText "{text}"' for text in [f"page at {self.url}", *self.texts]]
        return "\n".join(['- button "Go" [ref=e1]', *texts])

    def click(self, ref: str) -> None:
        self._use("click", ref)
        if self.on_click is not None:
            self.on_click()

    def press_enter(self) -> None:
        self._use("press_enter")

    def fill(self, ref: str, text: str) -> None:
        self._use("fill", ref, text)

    def current_url(self) -> str:
        return self.url

    def screenshot(self, name: str = "screenshot.png") -> Path:
        self._use("screenshot", name)
        return Path("/shots") / name

    def is_alive(self) -> bool:
        return self.alive

    def close(self) -> None:
        self.closed += 1
        self.alive = False
        if self.close_error is not None:
            raise self.close_error


class Factory:
    """Starts fake sessions and remembers them."""

    def __init__(self) -> None:
        self.made: list[FakeSession] = []
        self.calls: list[tuple[str, str, Path]] = []
        self.fail: Exception | None = None
        self.delay = 0.0
        self.during_start: Callable[[Path], None] | None = None

    def __call__(
        self, _roots: sites.Roots, site: str, url: str, proxy_socket: Path
    ) -> daemon.BrowserSession:
        self.calls.append((site, url, proxy_socket))
        if self.during_start is not None:
            self.during_start(proxy_socket)
        time.sleep(self.delay)
        if self.fail is not None:
            raise self.fail
        session = FakeSession(url)
        self.made.append(session)
        return session


class FakeWindow:
    """A login window the test closes by hand."""

    def __init__(self, site: str, start: str, finish: Finish) -> None:
        self.site = site
        self.start = start
        self.finish = finish
        self.done = asyncio.Event()
        self.cancelled = False

    async def wait(self) -> login.LoginResult:
        await self.done.wait()
        return login.LoginResult([], Path("/profile"), 0, self.cancelled)

    async def cancel(self) -> login.LoginResult:
        self.cancelled = True
        self.done.set()
        return await self.wait()

    async def close_window(self, seen: list[SeenHost], profile: Path) -> None:
        """What the real runner does when the person closes the window."""
        await self.finish(seen, profile)
        self.done.set()


class Logins:
    """Stands in for ``login.start_login``."""

    def __init__(self) -> None:
        self.windows: list[FakeWindow] = []
        self.fail: Exception | None = None

    async def __call__(
        self,
        site: str,
        start: str,
        _roots: sites.Roots,
        finish: Finish,
        **_: Any,  # noqa: ANN401
    ) -> FakeWindow:
        if self.fail is not None:
            raise self.fail
        window = FakeWindow(site, start, finish)
        self.windows.append(window)
        return window


def add_site(
    roots: sites.Roots,
    site: str = "sitex",
    allow: tuple[str, ...] = ("sitex.test",),
    excluded: tuple[str, ...] = (),
) -> sites.Policy:
    policy = sites.Policy(site, f"https://{site}.test/", allow, excluded)
    sites.save_policy(roots, policy)
    return policy


@pytest.fixture
def roots(short_dir: Path) -> sites.Roots:
    (short_dir / "r").mkdir(mode=0o700)
    return sites.Roots(short_dir / "c", short_dir / "s", short_dir / "r")


class Rig:
    def __init__(self, server: daemon.Daemon, factory: Factory, logins: Logins) -> None:
        self.daemon = server
        self.factory = factory
        self.logins = logins
        self.path = client.socket_path(server.roots)

    def connect(self) -> Awaitable[client.Client]:
        return client.Client.connect(self.path)


@contextlib.asynccontextmanager
async def serving(roots: sites.Roots, **options: Any) -> AsyncGenerator[Rig]:  # noqa: ANN401
    factory, logins = Factory(), Logins()
    settings: dict[str, Any] = {
        "session_factory": factory,
        "login_starter": logins,
        "now": lambda: NOW,
    } | options
    server = daemon.Daemon(roots, **settings)
    await server.start()
    try:
        yield Rig(server, factory, logins)
    finally:
        await server.shutdown()


async def raw(path: Path) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_unix_connection(path)


def refuse_via_proxy(proxy_socket: Path, host: str) -> None:
    """Make the session's proxy refuse ``host``, as a browser asking for it would."""
    with socket.socket(socket.AF_UNIX) as connection:
        connection.connect(str(proxy_socket))
        connection.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
        assert connection.recv(100).startswith(b"HTTP/1.1 403")


# -- sessions ------------------------------------------------------------------------------


def test_a_session_from_open_to_close(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            opened = await c.call("open", site="sitex")
            assert opened == {
                "site": "sitex",
                "contained": True,
                "url": "https://sitex.test/",
                "refused": [],
                "reused": False,
                "page": {"title": {"untrusted": True, "text": "Start"}},
            }
            session = rig.factory.made[0]
            assert rig.factory.calls == [
                ("sitex", "https://sitex.test/", Path(session_socket(roots, "sitex")))
            ]
            snap = await c.call("snapshot", site="sitex")
            assert snap["snapshot"] == {"untrusted": True, "text": '- button "Go" [ref=e1]'}
            assert snap["refs"] == {"e1": "button"}
            assert snap["url"] == "https://sitex.test/"
            assert snap["contained"] is True
            nav = await c.call("navigate", site="sitex", url="https://sitex.test/two")
            assert nav["url"] == "https://sitex.test/two"
            assert nav["page"]["title"] == {
                "untrusted": True,
                "text": "Title of https://sitex.test/two",
            }
            clicked = await c.call("click", site="sitex", ref="e1")
            assert clicked["clicked"] == {
                "role": "button",
                "name": {"untrusted": True, "text": "Go"},
            }
            assert (clicked["attempts"], clicked["expect"], clicked["outcome"]) == (
                1,
                None,
                "unchecked",
            )
            assert clicked["url"] == "https://sitex.test/two"
            typed = await c.call("type", site="sitex", ref="e2", text="hello")
            assert typed["done"] is True
            assert typed["submitted"] is False
            shot = await c.call("screenshot", site="sitex", name="a.png")
            assert shot["path"] == "/shots/a.png"
            default_shot = await c.call("screenshot", site="sitex")
            assert default_shot["path"] == "/shots/screenshot.png"
            status = await c.call("status", site="sitex")
            assert status["state"] == "session"
            assert status["url"] == "https://sitex.test/two"
            assert "_value" not in status
            assert [call[0] for call in session.calls] == [
                "snapshot", "open", "snapshot", "click", "fill", "screenshot", "screenshot",
            ]  # fmt: skip
            assert ("fill", "e2", "hello") in session.calls
            closed = await c.call("close", site="sitex")
            assert closed == {"site": "sitex", "closed": True}
            assert session.closed == 1
            assert await c.call("close", site="sitex") == {"site": "sitex", "closed": False}
            assert session.closed == 1
            with pytest.raises(DaemonError) as info:
                await c.call("snapshot", site="sitex")
            assert info.value.code == "no_session"
            idle = await c.call("status", site="sitex")
            assert idle == {"site": "sitex", "state": "idle", "contained": True}

    run(scenario())


def session_socket(roots: sites.Roots, site: str) -> Path:
    return sessions.session_paths(roots, site).proxy_socket


def test_closing_removes_the_proxy_and_the_session_directory(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            paths = sessions.session_paths(roots, "sitex")
            assert stat.S_ISSOCK(paths.proxy_socket.stat().st_mode)
            assert stat.S_IMODE(paths.proxy_socket.parent.stat().st_mode) == 0o700
            await c.call("close", site="sitex")
            assert not paths.directory.exists()

    run(scenario())


def test_unknown_and_malformed_sites(roots: sites.Roots) -> None:
    add_site(roots, "alpha")
    add_site(roots, "beta")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            for op in ("open", "reload_policy", "status"):
                with pytest.raises(DaemonError) as info:
                    await c.call(op, site="nosuch")
                assert info.value.code == "unknown_site"
                assert "alpha, beta" in info.value.message
            for bad in ("../x", "A", "", 5, None):
                with pytest.raises(DaemonError) as info:
                    await c.call("open", site=bad)
                assert info.value.code == "bad_request"
            with pytest.raises(DaemonError, match="bad_request"):
                await c.call("open")
            with pytest.raises(DaemonError) as info:
                await c.call("screenshot", site="alpha", name=5)
            assert info.value.code == "bad_request"
            assert rig.factory.calls == []

    run(scenario())


def test_the_unknown_site_message_when_there_are_none(roots: sites.Roots) -> None:
    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            with pytest.raises(DaemonError, match="none yet"):
                await c.call("open", site="sitex")

    run(scenario())


def test_two_clients_share_one_session_and_never_interleave(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as one, await rig.connect() as two:
            first, second = await asyncio.gather(
                one.call("open", site="sitex"), two.call("open", site="sitex")
            )
            assert sorted([first["reused"], second["reused"]]) == [False, True]
            assert len(rig.factory.made) == 1
            session = rig.factory.made[0]
            session.delay = 0.05
            await asyncio.gather(
                one.call("snapshot", site="sitex"),
                two.call("type", site="sitex", ref="e1", text="x"),
                one.call("snapshot", site="sitex"),
                two.call("snapshot", site="sitex"),
            )
            assert session.most_active == 1
            assert len(session.calls) == 4

    run(scenario())


def test_refusals_are_reported_once_to_each_client(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig:
            rig.factory.during_start = lambda proxy: refuse_via_proxy(proxy, "early.test")
            async with await rig.connect() as one:
                opened = await one.call("open", site="sitex")
                # The opener hears about what was refused while the browser started.
                assert opened["refused"] == [
                    {"host": "early.test", "port": 443, "reason": "not in the allow list"}
                ]
                proxy = session_socket(roots, "sitex")
                await asyncio.to_thread(refuse_via_proxy, proxy, "evil.test")
                async with await rig.connect() as two:
                    joined = await two.call("open", site="sitex")
                    assert joined["reused"] is True
                    # A client that joins starts from what is refused from then on.
                    assert joined["refused"] == []
                    again = await one.call("snapshot", site="sitex")
                    assert [r["host"] for r in again["refused"]] == ["evil.test"]
                    assert (await one.call("snapshot", site="sitex"))["refused"] == []
                    await asyncio.to_thread(refuse_via_proxy, proxy, "tracker.test")
                    # One client asking does not use up the other's report.
                    seen_by_one = (await one.call("status", site="sitex"))["refused"]
                    seen_by_two = (await two.call("status", site="sitex"))["refused"]
                    assert [r["host"] for r in seen_by_one] == ["tracker.test"]
                    assert [r["host"] for r in seen_by_two] == ["tracker.test"]
                    assert (await two.call("status", site="sitex"))["refused"] == []

    run(scenario())


def test_a_client_that_never_opened_starts_from_now(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig:
            async with await rig.connect() as one:
                await one.call("open", site="sitex")
                await asyncio.to_thread(
                    refuse_via_proxy, session_socket(roots, "sitex"), "old.test"
                )
            async with await rig.connect() as other:
                assert (await other.call("snapshot", site="sitex"))["refused"] == []

    run(scenario())


def test_cursors_restart_with_a_new_session(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            await asyncio.to_thread(refuse_via_proxy, session_socket(roots, "sitex"), "a.test")
            await c.call("close", site="sitex")
            rig.factory.during_start = lambda proxy: refuse_via_proxy(proxy, "b.test")
            reopened = await c.call("open", site="sitex")
            assert [r["host"] for r in reopened["refused"]] == ["b.test"]

    run(scenario())


def test_reload_policy_reaches_the_live_proxy(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async def resolve(_host: str, _port: int) -> list[str]:
            return ["127.0.0.1"]

        async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            writer.write(await reader.read(1))
            writer.close()

        upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        port = upstream.sockets[0].getsockname()[1]

        async def connect(_address: str, _port: int) -> Any:  # noqa: ANN401
            return await asyncio.open_connection("127.0.0.1", port)

        options = {"resolver": resolve, "connector": connect, "address_check": lambda _a: None}
        async with serving(roots, proxy_options=options) as rig, await rig.connect() as c:
            idle = await c.call("reload_policy", site="sitex")
            assert idle == {"site": "sitex", "allow": ["sitex.test"], "excluded": [], "live": False}
            await c.call("open", site="sitex")
            proxy = session_socket(roots, "sitex")
            await asyncio.to_thread(refuse_via_proxy, proxy, "new.test")
            add_site(roots, allow=("sitex.test", "new.test"), excluded=("ads.sitex.test",))
            reloaded = await c.call("reload_policy", site="sitex")
            assert reloaded["live"] is True
            assert reloaded["allow"] == ["new.test", "sitex.test"] or reloaded["allow"] == [
                "sitex.test",
                "new.test",
            ]
            assert reloaded["excluded"] == ["ads.sitex.test"]
            reader, writer = await asyncio.open_unix_connection(proxy)
            writer.write(b"CONNECT new.test:443 HTTP/1.1\r\nHost: new.test:443\r\n\r\n")
            assert (await reader.readline()).startswith(b"HTTP/1.1 200")
            writer.close()
            await writer.wait_closed()
            sites.policy_path(roots, "sitex").write_text("{", encoding="utf-8")
            with pytest.raises(DaemonError) as info:
                await c.call("reload_policy", site="sitex")
            assert info.value.code == "bad_policy"
        upstream.close()
        await upstream.wait_closed()

    run(scenario())


def test_a_session_that_will_not_start_leaves_the_site_idle(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            rig.factory.fail = sessions.SessionError("the browser exited\nlog tail")
            with pytest.raises(DaemonError) as info:
                await c.call("open", site="sitex")
            assert info.value.code == "session_failed"
            assert "log tail" in info.value.message
            assert not sessions.session_paths(roots, "sitex").directory.exists()
            assert (await c.call("status", site="sitex"))["state"] == "idle"
            rig.factory.fail = None
            assert (await c.call("open", site="sitex"))["reused"] is False

    run(scenario())


def test_session_errors_name_the_refusals(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            session = rig.factory.made[0]
            await asyncio.to_thread(refuse_via_proxy, session_socket(roots, "sitex"), "evil.test")
            session.fail = sessions.AgentBrowserError("net::ERR_TUNNEL_CONNECTION_FAILED")
            with pytest.raises(DaemonError) as info:
                await c.call("navigate", site="sitex", url="https://evil.test/")
            assert info.value.code == "browser_error"
            assert "ERR_TUNNEL" in info.value.message
            assert info.value.details["site"] == "sitex"
            assert info.value.details["contained"] is True
            assert [r["host"] for r in info.value.details["refused"]] == ["evil.test"]
            session.fail = ValueError("not a reference")
            with pytest.raises(DaemonError) as info:
                await c.call("click", site="sitex", ref="bogus")
            assert info.value.code == "bad_request"

    run(scenario())


def test_a_dead_browser_ends_the_session(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            first = rig.factory.made[0]
            first.alive = False
            with pytest.raises(DaemonError) as info:
                await c.call("snapshot", site="sitex")
            assert info.value.code == "session_ended"
            assert first.closed == 1
            assert (await c.call("status", site="sitex"))["state"] == "idle"
            await c.call("open", site="sitex")
            second = rig.factory.made[1]
            second.alive = False
            reopened = await c.call("open", site="sitex")
            assert reopened["reused"] is False
            assert len(rig.factory.made) == 3
            assert second.closed == 1

    run(scenario())


def test_a_session_that_fails_to_close_is_still_forgotten(
    roots: sites.Roots, caplog: pytest.LogCaptureFixture
) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")

            rig.factory.made[0].close_error = RuntimeError("stuck")
            assert (await c.call("close", site="sitex"))["closed"] is True
            assert (await c.call("status", site="sitex"))["state"] == "idle"

    run(scenario())
    assert "closing the sitex session failed" in caplog.text


# -- logins --------------------------------------------------------------------------------


def test_a_login_learns_a_policy_and_reports_it_once(roots: sites.Roots) -> None:
    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            started = await c.call("login", target="https://newsite.test/signin")
            assert started == {"site": "newsite", "window": "open"}
            (window,) = rig.logins.windows
            assert window.start == "https://newsite.test/signin"
            listing = await c.call("sites")
            assert listing["sites"] == [
                {
                    "site": "newsite",
                    "state": "login",
                    "start": "https://newsite.test/signin",
                    "allow": [],
                    "learned": None,
                    "summary": None,
                }
            ]
            with pytest.raises(DaemonError) as info:
                await c.call("login", target="newsite.test")
            assert info.value.code == "login_in_progress"
            with pytest.raises(DaemonError) as info:
                await c.call("open", site="newsite")
            assert info.value.code == "login_in_progress"
            profile = roots.state / "profile"
            seen = [
                SeenHost("newsite.test", 5),
                SeenHost("login.okta.test", 2),
                SeenHost("o1.sentry.test", 1),
            ]
            history = profile / "Default" / "History"
            history.parent.mkdir(parents=True)
            make_history(history, ["https://newsite.test/signin", "https://login.okta.test/auth"])
            await window.close_window(seen, profile)
            await eventually(lambda: rig.daemon._sites["newsite"].kind == "idle")  # noqa: SLF001
            policy = sites.load_policy(roots, "newsite")
            assert policy.start == "https://newsite.test/signin"
            assert policy.allow == ("login.okta.test", "newsite.test")
            assert policy.excluded == ("o1.sentry.test",)
            assert policy.learned == NOW
            listing = await c.call("sites")
            (entry,) = listing["sites"]
            assert entry["state"] == "idle"
            assert entry["allow"] == ["login.okta.test", "newsite.test"]
            assert entry["learned"] == "2026-10-27T12:00:00Z"
            assert "Saved your newsite login" in entry["summary"]
            assert (await c.call("sites"))["sites"][0]["summary"] is None

    run(scenario())


def make_history(path: Path, urls: list[str]) -> None:
    database = sqlite3.connect(path)
    database.executescript(
        "CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT);"
        "CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, transition INTEGER);"
    )
    for number, url in enumerate(urls, start=1):
        database.execute("INSERT INTO urls VALUES (?, ?)", (number, url))
        database.execute("INSERT INTO visits(url, transition) VALUES (?, 1)", (number,))
    database.commit()
    database.close()


async def eventually(check: Callable[[], bool], limit: float = 10) -> None:
    deadline = time.monotonic() + limit
    while not check():
        assert time.monotonic() < deadline, "timed out"
        await asyncio.sleep(0.02)


def test_a_login_merges_into_an_existing_policy(roots: sites.Roots) -> None:
    add_site(roots, "sitex", allow=("sitex.test", "approved.test"), excluded=("old.test",))

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            assert await c.call("login", target="sitex") == {"site": "sitex", "window": "open"}
            (window,) = rig.logins.windows
            assert window.start == "https://sitex.test/"
            await window.close_window([SeenHost("cdn.other.test", 1)], roots.state / "p")
            await eventually(lambda: rig.daemon._sites["sitex"].kind == "idle")  # noqa: SLF001
            policy = sites.load_policy(roots, "sitex")
            assert policy.allow == ("approved.test", "sitex.test")
            assert policy.excluded == ("cdn.other.test", "old.test")

    run(scenario())


def test_login_targets(roots: sites.Roots) -> None:
    add_site(roots, "sitex")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            with pytest.raises(DaemonError) as info:
                await c.call("login", target="nosuch")
            assert info.value.code == "unknown_site"
            for bad in ("ftp://x.test", "", 5):
                with pytest.raises(DaemonError) as info:
                    await c.call("login", target=bad)
                assert info.value.code == "bad_request"
            # The same domain finds the same site; another domain gets a numbered one.
            await c.call("close", site="sitex")
            assert (await c.call("login", target="sitex.test"))["site"] == "sitex"
            await c.call("close", site="sitex")
            assert (await c.call("login", target="sitex.org"))["site"] == "sitex-2"

    run(scenario())


def test_login_and_session_exclude_each_other(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            with pytest.raises(DaemonError) as info:
                await c.call("login", target="sitex")
            assert info.value.code == "session_running"
            await c.call("close", site="sitex")
            await c.call("login", target="sitex")
            with pytest.raises(DaemonError) as info:
                await c.call("open", site="sitex")
            assert info.value.code == "login_in_progress"
            # Closing a site with a login open cancels the login without learning anything.
            assert (await c.call("close", site="sitex"))["closed"] is True
            assert rig.logins.windows[0].cancelled
            assert (await c.call("status", site="sitex"))["state"] == "idle"
            assert (await c.call("open", site="sitex"))["reused"] is False

    run(scenario())


def test_login_errors_become_answers(roots: sites.Roots) -> None:
    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            rig.logins.fail = login.NoDisplayError("no desktop session here")
            with pytest.raises(DaemonError) as info:
                await c.call("login", target="newsite.test")
            assert (info.value.code, info.value.message) == (
                "no_display",
                "no desktop session here",
            )
            rig.logins.fail = login.X11OnlyError("X11 reads every keystroke")
            with pytest.raises(DaemonError) as info:
                await c.call("login", target="newsite.test")
            assert info.value.code == "x11_only"
            rig.logins.fail = None
            assert (await c.call("login", target="newsite.test"))["window"] == "open"

    run(scenario())


def test_a_login_that_cannot_be_saved_says_so(roots: sites.Roots) -> None:
    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("login", target="newsite.test")
            (window,) = rig.logins.windows
            profile = roots.state / "p"
            (profile / "Default").mkdir(parents=True)
            (profile / "Default" / "History").write_bytes(b"this is not a database" * 100)
            await window.close_window([], profile)
            await eventually(lambda: rig.daemon._sites["newsite"].kind == "idle")  # noqa: SLF001
            (entry,) = (await c.call("sites"))["sites"]
            assert "could not be saved" in entry["summary"]
            assert not sites.policy_path(roots, "newsite").exists()

    run(scenario())


def test_a_login_whose_window_fails_frees_the_site(
    roots: sites.Roots, caplog: pytest.LogCaptureFixture
) -> None:
    class Broken(FakeWindow):
        async def wait(self) -> login.LoginResult:
            msg = "window crashed"
            raise RuntimeError(msg)

    async def starter(site: str, start: str, _roots: sites.Roots, finish: Any, **_: Any) -> Broken:  # noqa: ANN401
        return Broken(site, start, finish)

    async def scenario() -> None:
        async with serving(roots, login_starter=starter) as rig, await rig.connect() as c:
            await c.call("login", target="newsite.test")
            await eventually(lambda: rig.daemon._sites["newsite"].kind == "idle")  # noqa: SLF001

    run(scenario())
    assert "login for newsite failed" in caplog.text


def test_sites_lists_policies_with_their_live_state(roots: sites.Roots) -> None:
    add_site(roots, "alpha")
    add_site(roots, "beta", allow=("beta.test", "cdn.beta.test"))
    (sites.policy_path(roots, "alpha").parent / "BAD NAME.json").write_text("{}", encoding="utf-8")
    (sites.policy_path(roots, "alpha").parent / "broken.json").write_text("{", encoding="utf-8")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="beta")
            listing = (await c.call("sites"))["sites"]
            assert [(e["site"], e["state"]) for e in listing] == [
                ("alpha", "idle"),
                ("beta", "session"),
                ("broken", "idle"),
            ]
            by_name = {e["site"]: e for e in listing}
            assert by_name["beta"]["allow"] == ["beta.test", "cdn.beta.test"]
            assert by_name["broken"]["allow"] == []
            assert by_name["broken"]["start"] == ""

    run(scenario())


def test_sites_with_no_policy_directory(roots: sites.Roots) -> None:
    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            assert await c.call("sites") == {"sites": []}

    run(scenario())


# -- the wire ------------------------------------------------------------------------------


def test_bad_lines_get_error_answers_and_the_connection_survives(roots: sites.Roots) -> None:
    async def scenario() -> None:
        async with serving(roots) as rig:
            reader, writer = await raw(rig.path)
            for line, code in [
                (b"not json\n", "bad_request"),
                (b"\n", "bad_request"),
                (b'{"id": 9}\n', "bad_request"),
                (b'{"id": 10, "op": "frobnicate"}\n', "unknown_op"),
            ]:
                writer.write(line)
                answer = json.loads(await reader.readline())
                assert answer["ok"] is False
                assert answer["error"]["code"] == code
            assert answer["id"] == 10
            writer.write(b'{"id": "s", "op": "sites"}\n')
            assert json.loads(await reader.readline()) == {
                "id": "s",
                "ok": True,
                "result": {"sites": []},
            }
            writer.close()
            await writer.wait_closed()

    run(scenario())


def test_an_oversized_line_is_refused_and_the_connection_closed(roots: sites.Roots) -> None:
    async def scenario() -> None:
        async with serving(roots) as rig:
            reader, writer = await raw(rig.path)
            writer.write(b'{"op": "sites", "args": {"x": "' + b"a" * (client.MAX_LINE_BYTES + 10))
            await writer.drain()
            answer = json.loads(await reader.readline())
            assert answer["error"]["code"] == "request_too_large"
            assert await reader.read() == b""
            writer.close()
            # The daemon is fine.
            async with await rig.connect() as c:
                assert await c.call("sites") == {"sites": []}

    run(scenario())


def test_a_half_written_request_at_eof_is_dropped(roots: sites.Roots) -> None:
    async def scenario() -> None:
        async with serving(roots) as rig:
            reader, writer = await raw(rig.path)
            writer.write(b'{"op": "sites"')
            writer.write_eof()
            assert await reader.read() == b""
            writer.close()

    run(scenario())


def test_a_client_that_leaves_mid_call_does_no_harm(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig:
            rig.factory.delay = 0.3
            reader, writer = await raw(rig.path)
            writer.write(b'{"id": 1, "op": "open", "args": {"site": "sitex"}}\n')
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            del reader
            await eventually(lambda: bool(rig.factory.made))
            async with await rig.connect() as c:
                joined = await c.call("open", site="sitex")
                assert joined["reused"] is True
                assert len(rig.factory.made) == 1

    run(scenario())


def test_an_unexpected_error_is_internal_and_logged(
    roots: sites.Roots, caplog: pytest.LogCaptureFixture
) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            rig.factory.fail = RuntimeError("secret detail")
            with pytest.raises(DaemonError) as info:
                await c.call("open", site="sitex")
            assert info.value.code == "internal"
            assert "secret" not in info.value.message
            assert (await c.call("sites"))["sites"][0]["state"] == "idle"

    run(scenario())
    assert "request failed: open" in caplog.text


def test_connections_from_other_users_are_dropped_unread(roots: sites.Roots) -> None:
    async def scenario() -> None:
        async with serving(roots, peer_uid=lambda _s: os.getuid() + 1) as rig:
            reader, writer = await raw(rig.path)
            writer.write(b'{"id": 1, "op": "sites"}\n')
            # Closed without a word; unread data makes that an end-of-file or a reset.
            with contextlib.suppress(ConnectionResetError):
                assert await reader.read() == b""
            writer.close()

    run(scenario())


def test_the_socket_is_private(roots: sites.Roots) -> None:
    async def scenario() -> None:
        async with serving(roots) as rig:
            assert stat.S_ISSOCK(rig.path.stat().st_mode)
            assert stat.S_IMODE(rig.path.stat().st_mode) == 0o600
            assert stat.S_IMODE(rig.path.parent.stat().st_mode) == 0o700

    run(scenario())


# -- starting and stopping -----------------------------------------------------------------


def test_a_second_daemon_does_not_take_over_the_socket(roots: sites.Roots) -> None:
    async def scenario() -> None:
        async with serving(roots) as rig:
            other = daemon.Daemon(roots)
            with pytest.raises(daemon.AlreadyRunningError, match="already running"):
                await other.start()
            assert await client.is_running(rig.path)
            async with await rig.connect() as c:
                assert await c.call("sites") == {"sites": []}

    run(scenario())


def test_daemons_starting_together_leave_exactly_one_owner(roots: sites.Roots) -> None:
    async def scenario() -> None:
        first, second = daemon.Daemon(roots), daemon.Daemon(roots)
        outcomes = await asyncio.gather(first.start(), second.start(), return_exceptions=True)
        try:
            failures = [o for o in outcomes if isinstance(o, daemon.AlreadyRunningError)]
            assert len(failures) == 1
            assert sum(o is None for o in outcomes) == 1
            assert await client.is_running(client.socket_path(roots))
        finally:
            await first.shutdown()
            await second.shutdown()
        # The lock goes with the winner, so the path can be taken again.
        third = daemon.Daemon(roots)
        await third.start()
        await third.shutdown()

    run(scenario())


def test_a_listener_that_holds_the_path_is_left_alone(roots: sites.Roots) -> None:
    """A socket systemd holds has no lock behind it; whatever answers there must stay."""

    async def scenario() -> None:
        path = client.socket_path(roots)
        daemon.make_private_dirs(path.parent)
        accepted: list[int] = []

        async def stand_in(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            accepted.append(1)
            writer.close()

        holder = await asyncio.start_unix_server(stand_in, path=str(path))
        inode = path.stat().st_ino
        try:
            with pytest.raises(daemon.AlreadyRunningError, match="already running"):
                await daemon.Daemon(roots).start()
            assert path.stat().st_ino == inode
            await eventually(
                lambda: bool(accepted)
            )  # the probe did connect, which is what wakes the systemd service
            async with await client.Client.connect(path) as c:
                with pytest.raises(DaemonError):
                    await c.call("sites")
        finally:
            holder.close()
            await holder.wait_closed()
        # The refused start gave its lock back.
        retry = daemon.Daemon(roots)
        await retry.start()
        await retry.shutdown()

    run(scenario())


def test_a_failed_bind_gives_the_lock_back(roots: sites.Roots) -> None:
    async def scenario() -> None:
        path = client.socket_path(roots)
        daemon.make_private_dirs(path)  # a directory where the socket should go
        with pytest.raises(OSError, match="in use"):
            await daemon.Daemon(roots).start()
        path.rmdir()
        retry = daemon.Daemon(roots)
        await retry.start()
        await retry.shutdown()

    run(scenario())


def test_a_stale_socket_file_is_replaced(roots: sites.Roots) -> None:
    async def scenario() -> None:
        path = client.socket_path(roots)
        daemon.make_private_dirs(path.parent)
        with socket.socket(socket.AF_UNIX) as stale:
            stale.bind(str(path))
        assert not await client.is_running(path)
        async with serving(roots) as rig:
            assert await client.is_running(rig.path)
        assert not path.exists()

    run(scenario())


def test_start_on_an_explicit_path(roots: sites.Roots, short_dir: Path) -> None:
    async def scenario() -> None:
        server = daemon.Daemon(roots)
        path = short_dir / "elsewhere" / "d.sock"
        await server.start(path)
        try:
            async with await client.Client.connect(path) as c:
                assert await c.call("sites") == {"sites": []}
        finally:
            await server.shutdown()
        assert not path.exists()

    run(scenario())


def test_start_uses_a_socket_passed_by_systemd(
    roots: sites.Roots, short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = short_dir / "passed.sock"
    monkeypatch.setenv("LISTEN_PID", str(os.getpid()))
    monkeypatch.setenv("LISTEN_FDS", "1")
    monkeypatch.setenv("LISTEN_FDNAMES", "valetkeyd")

    async def scenario() -> None:
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(path))
            listener.listen()
            monkeypatch.setattr(daemon, "activated_socket", lambda *_: listener.dup())
            server = daemon.Daemon(roots)
            await server.start()
            for name in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
                assert name not in os.environ
            async with await client.Client.connect(path) as c:
                assert await c.call("sites") == {"sites": []}
            await server.shutdown()
            # systemd owns that file, so the daemon leaves it.
            assert path.exists()

    run(scenario())


def test_shutdown_ends_sessions_and_logins(roots: sites.Roots) -> None:
    add_site(roots, "alpha")
    add_site(roots, "beta")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="alpha")
            await c.call("login", target="beta")
            path = rig.path
            await rig.daemon.shutdown()
            assert rig.factory.made[0].closed == 1
            assert rig.logins.windows[0].cancelled
            assert not path.exists()
            assert not sessions.session_paths(roots, "alpha").directory.exists()
            with pytest.raises(DaemonError) as info:
                await c.call("sites")
            assert info.value.code == "connection_lost"

    run(scenario())


def test_run_serves_until_sigterm_and_cleans_up(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> int:
        factory = Factory()
        server = daemon.Daemon(roots, session_factory=factory, login_starter=Logins())
        ready = asyncio.Event()
        task = asyncio.ensure_future(daemon.run(server, ready=ready))
        await ready.wait()
        path = client.socket_path(roots)
        async with await client.Client.connect(path) as c:
            await c.call("open", site="sitex")
            os.kill(os.getpid(), signal.SIGTERM)
            status = await task
        assert factory.made[0].closed == 1
        assert not path.exists()
        return status

    assert run(scenario()) == 0


def test_run_stops_on_sigint_too(roots: sites.Roots) -> None:
    async def scenario() -> int:
        ready = asyncio.Event()
        task = asyncio.ensure_future(daemon.run(daemon.Daemon(roots), ready=ready))
        await ready.wait()
        os.kill(os.getpid(), signal.SIGINT)
        return await task

    assert run(scenario()) == 0


def test_run_without_a_ready_event(roots: sites.Roots) -> None:
    async def scenario() -> int:
        task = asyncio.ensure_future(daemon.run(daemon.Daemon(roots)))
        await eventually(lambda: client.socket_path(roots).exists())
        os.kill(os.getpid(), signal.SIGTERM)
        return await task

    assert run(scenario()) == 0


def test_the_real_session_factory_passes_the_proxy_socket(
    roots: sites.Roots, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[Any, ...]] = []

    def fake_start(*args: Any, **kwargs: Any) -> str:  # noqa: ANN401
        seen.append((args, kwargs))
        return "session"

    monkeypatch.setattr(sessions.Session, "start", fake_start)
    assert daemon.start_session(roots, "sitex", "https://x.test/", Path("/p.sock")) == "session"  # type: ignore[comparison-overlap]
    assert seen == [((roots, "sitex", "https://x.test/"), {"proxy_socket": Path("/p.sock")})]


# -- the daemon as a process ---------------------------------------------------------------


def daemon_env(base: Path) -> dict[str, str]:
    (base / "xdg").mkdir(mode=0o700, exist_ok=True)
    return {
        "PATH": os.environ["PATH"],
        "HOME": str(base),
        "XDG_RUNTIME_DIR": str(base / "xdg"),
        "XDG_CONFIG_HOME": str(base / "cfg"),
        "XDG_STATE_HOME": str(base / "state"),
    }


def wait_for_file(path: Path, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 30
    while not path.exists():
        assert process.poll() is None, process.stderr.read() if process.stderr else b""
        assert time.monotonic() < deadline, "the daemon did not start"
        time.sleep(0.05)


def test_the_daemon_command_runs_until_sigterm(short_dir: Path) -> None:
    env = daemon_env(short_dir)
    path = short_dir / "xdg" / "valetkey" / "daemon.sock"
    process = subprocess.Popen(  # fixed argument list
        [sys.executable, "-m", "valetkey", "daemon"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        wait_for_file(path, process)

        async def ask() -> dict[str, Any]:
            async with await client.Client.connect(path) as c:
                return await c.call("sites")

        assert run(ask()) == {"sites": []}
        second = subprocess.run(  # fixed argument list
            [sys.executable, "-m", "valetkey", "daemon"],
            env=env,
            capture_output=True,
            check=False,
            timeout=60,
        )
        assert second.returncode == 1
        assert b"already running" in second.stderr
        process.send_signal(signal.SIGTERM)
        assert process.wait(30) == 0
        assert process.stdout is not None
        assert process.stdout.read() == b""
        assert not path.exists()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def test_the_daemon_command_uses_a_socket_from_systemd(short_dir: Path) -> None:
    env = daemon_env(short_dir)
    path = short_dir / "activated.sock"
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(path))
        listener.listen()
        number = listener.fileno()
        script = f"LISTEN_PID=$$ LISTEN_FDS=1 exec {sys.executable} -m valetkey daemon 3<&{number}"
        process = subprocess.Popen(  # noqa: S603  # fixed argument list
            ["/bin/sh", "-c", script],
            env=env,
            pass_fds=[number],
            stderr=subprocess.PIPE,
        )
        try:

            async def ask() -> dict[str, Any]:
                for _ in range(300):
                    with contextlib.suppress(DaemonError):
                        async with await client.Client.connect(path) as c:
                            return await c.call("sites")
                    await asyncio.sleep(0.1)
                msg = "no answer"
                raise AssertionError(msg)

            assert run(ask()) == {"sites": []}
            assert not (short_dir / "xdg" / "valetkey" / "daemon.sock").exists()
            process.send_signal(signal.SIGTERM)
            assert process.wait(30) == 0
            assert path.exists()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            if process.stderr is not None:
                process.stderr.close()


def test_a_verified_click_through_the_daemon(
    roots: sites.Roots, monkeypatch: pytest.MonkeyPatch
) -> None:
    add_site(roots)
    monkeypatch.setattr(clicks, "PRESENCE_SECONDS", 0.02)
    monkeypatch.setattr(clicks, "GRACE_SECONDS", 0.1)
    monkeypatch.setattr(clicks, "SETTLE_SECONDS", 0.2)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            session = rig.factory.made[0]
            with pytest.raises(DaemonError) as info:
                await c.call("click", site="sitex", ref="e1")
            assert info.value.code == "unknown_ref"
            await c.call("snapshot", site="sitex")

            session.on_click = lambda: session.texts.append("Saved")
            met = await c.call("click", site="sitex", ref="e1", expect={"text_appears": "Saved"})
            assert met["clicked"] == {"role": "button", "name": {"untrusted": True, "text": "Go"}}
            assert (met["outcome"], met["attempts"]) == ("met", 1)
            assert met["expect"] == {"kind": "text_appears", "text": "Saved"}
            assert met["contained"] is True
            assert met["site"] == "sitex"

            already = await c.call(
                "click", site="sitex", text="go", role="BUTTON", expect={"text_appears": "Saved"}
            )
            assert already["outcome"] == "already_true"

            session.on_click = None
            session.texts.clear()
            clicked_before = [call for call in session.calls if call[0] == "click"]
            missed = await c.call(
                "click", site="sitex", text="Go", expect={"text_appears": "Never"}
            )
            assert (missed["outcome"], missed["attempts"]) == ("not_met", 2)
            assert len([call for call in session.calls if call[0] == "click"]) == (
                len(clicked_before) + 2
            )

    run(scenario())


def test_click_refusals_carry_the_page_names_and_the_envelope(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            session = rig.factory.made[0]
            await c.call("snapshot", site="sitex")
            with pytest.raises(DaemonError) as info:
                await c.call("click", site="sitex", text="Go Home")
            assert info.value.code == "target_not_found"
            assert info.value.details["site"] == "sitex"
            assert info.value.details["contained"] is True
            assert info.value.details["candidates"] == []
            with pytest.raises(DaemonError) as info:
                await c.call("click", site="sitex", text="Go", role="link")
            assert info.value.code == "target_not_found"
            for bad in (
                {"ref": "e1", "text": "Go"},
                {},
                {"ref": "e1", "role": "button"},
                {"ref": "e1", "expect": {"text_appears": ""}},
                {"ref": "e1", "expect": {"url_changes": False}},
                {"ref": "e1", "expect": []},
            ):
                with pytest.raises(DaemonError) as info:
                    await c.call("click", site="sitex", **bad)
                assert info.value.code == "bad_request"
            assert not [call for call in session.calls if call[0] == "click"]

    run(scenario())


def test_a_reference_from_an_earlier_session_is_unknown(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            await c.call("snapshot", site="sitex")
            await c.call("close", site="sitex")
            await c.call("open", site="sitex")
            with pytest.raises(DaemonError) as info:
                await c.call("click", site="sitex", ref="e1")
            assert info.value.code == "unknown_ref"

    run(scenario())


def test_each_client_clicks_by_its_own_snapshot(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as one, await rig.connect() as two:
            await one.call("open", site="sitex")
            await one.call("snapshot", site="sitex")
            with pytest.raises(DaemonError) as info:
                await two.call("click", site="sitex", ref="e1")
            assert info.value.code == "unknown_ref"
            assert (await one.call("click", site="sitex", ref="e1"))["outcome"] == "unchecked"

    run(scenario())


def test_type_can_press_enter(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            session = rig.factory.made[0]
            plain = await c.call("type", site="sitex", ref="e1", text="a")
            sent = await c.call("type", site="sitex", ref="e1", text="b", submit=True)
            assert (plain["submitted"], sent["submitted"]) == (False, True)
            assert [call[0] for call in session.calls] == ["fill", "fill", "press_enter"]
            with pytest.raises(DaemonError) as info:
                await c.call("type", site="sitex", ref="e1", text="c", submit="yes")
            assert info.value.code == "bad_request"

    run(scenario())


def test_status_during_a_login(roots: sites.Roots) -> None:
    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("login", target="newsite.test")
            assert await c.call("status", site="newsite") == {
                "site": "newsite",
                "state": "login",
                "contained": True,
            }
            await rig.logins.windows[0].cancel()
            await eventually(lambda: rig.daemon._sites["newsite"].kind == "idle")  # noqa: SLF001

    run(scenario())


def test_two_calls_that_find_the_browser_dead_end_it_once(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as one, await rig.connect() as two:
            await one.call("open", site="sitex")
            session = rig.factory.made[0]
            session.alive = False
            state = rig.daemon._sites["sitex"]  # noqa: SLF001
            async with state.lock:  # both calls find the dead browser, then queue up
                calls = [
                    asyncio.ensure_future(one.call("snapshot", site="sitex")),
                    asyncio.ensure_future(two.call("snapshot", site="sitex")),
                ]
                await asyncio.sleep(0.3)
            results = await asyncio.gather(*calls, return_exceptions=True)
            assert [r.code for r in results if isinstance(r, DaemonError)] == [
                "session_ended",
                "session_ended",
            ]
            assert session.closed == 1

    run(scenario())


# -- integration: a real session through the daemon ----------------------------------------


_SKIP_REASON = unusable_reason("bwrap", "chromium", "agent-browser")
needs_everything = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")
PAGES = {
    "/": (
        '<title>One</title><input placeholder="Your name">'
        "<button onclick=\"document.title='clicked'\">Go</button>"
    ),
    "/two": "<title>Two</title><h1>second page</h1>",
}


@pytest.mark.integration
@needs_everything
def test_a_real_session_through_the_daemon(roots: sites.Roots) -> None:
    sites.save_policy(roots, sites.Policy("demo", "http://site.test/", ("site.test",)))

    async def scenario() -> None:
        with PageServer(PAGES) as pages:

            async def resolve(_host: str, _port: int) -> list[str]:
                return ["127.0.0.1"]

            async def connect(_address: str, _port: int) -> Any:  # noqa: ANN401
                return await asyncio.open_connection(*pages.address)

            options = {"resolver": resolve, "connector": connect, "address_check": lambda _a: None}
            server = daemon.Daemon(roots, proxy_options=options)
            await server.start()
            try:
                async with await client.Client.connect(client.socket_path(roots)) as one:
                    opened = await one.call("open", site="demo")
                    assert opened["url"] == "http://site.test/"
                    assert opened["page"]["title"] == {"untrusted": True, "text": "One"}
                    snap = await one.call("snapshot", site="demo")
                    assert set(snap["refs"].values()) == {"textbox", "button"}
                    field = next(r for r, role in snap["refs"].items() if role == "textbox")
                    await one.call("type", site="demo", ref=field, text="Ada")
                    two = await one.call("navigate", site="demo", url="http://site.test/two")
                    assert two["page"]["title"]["text"] == "Two"
                    # The browser asks for a host the policy does not allow.
                    refused: list[dict[str, Any]] = []
                    try:
                        blocked = await one.call("navigate", site="demo", url="http://other.test/")
                        refused += blocked["refused"]
                    except DaemonError as error:
                        refused += error.details.get("refused", [])
                    refused += (await one.call("status", site="demo"))["refused"]
                    assert "other.test" in {entry["host"] for entry in refused}
                    async with await client.Client.connect(client.socket_path(roots)) as other:
                        assert (await other.call("open", site="demo"))["reused"] is True
                    paths = sessions.session_paths(roots, "demo")
                    assert (await one.call("close", site="demo"))["closed"] is True
                    assert not paths.directory.exists()
                    assert not paths.driver_dir.exists()
            finally:
                await server.shutdown()

    run(scenario())
