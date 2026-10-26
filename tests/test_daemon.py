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

from valetkey import clicks, client, daemon, login, procs, sessions, sites
from valetkey.client import DaemonError
from valetkey.proxy import SeenHost

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Awaitable, Callable

type Finish = Callable[[list[SeenHost], Path], Awaitable[None]]
PDF_BYTES = b"%PDF-1.7\n1 0 obj"
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
        self.on_open: Callable[[], None] | None = None
        self.abort_with: Path | None = None
        self.attached = 0
        self.passwords = 0
        self.attach_error: Exception | None = None
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
        if self.abort_with is not None:  # the URL turned out to be an attachment
            self.abort_with.write_bytes(b"attached")
            msg = "Navigation failed: net::ERR_ABORTED"
            raise sessions.AgentBrowserError(msg)
        self.url = url
        if self.on_open is not None:
            self.on_open()
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

    def password_fields(self) -> int:
        self.calls.append(("password_fields",))
        return self.passwords

    def clear_requests(self) -> None:
        self.calls.append(("clear_requests",))

    def attachments(self) -> int:
        if self.attach_error is not None:
            raise self.attach_error
        return self.attached

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
        self.landing: str | None = None
        self.passwords = 0

    def __call__(
        self, _roots: sites.Roots, site: str, url: str, proxy_socket: Path
    ) -> daemon.BrowserSession:
        self.calls.append((site, url, proxy_socket))
        if self.during_start is not None:
            self.during_start(proxy_socket)
        time.sleep(self.delay)
        if self.fail is not None:
            raise self.fail
        session = FakeSession(self.landing or url)
        session.passwords = self.passwords
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
        "download_settle": 0,
        "poll_interval": 3600,
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
                "background_refused": [],
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
            assert [call[0] for call in session.calls if call[0] != "clear_requests"] == [
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


# -- background refusals -------------------------------------------------------------------


def test_background_refusals_after_the_startup_burst_are_reported_once_per_client(
    roots: sites.Roots,
) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots, startup_grace=0) as rig, await rig.connect() as c:
            # Chrome's burst while the session starts, before the first page is reported.

            def burst(socket_path: Path) -> None:
                for host in ("update.googleapis.com",) * 3:
                    refuse_via_proxy(socket_path, host)

            rig.factory.during_start = burst
            opened = await c.call("open", site="sitex")
            assert opened["background_refused"] == []
            assert opened["refused"] == []  # quiet ones never join the reported refusals
            assert (await c.call("snapshot", site="sitex"))["background_refused"] == []
            other = await rig.connect()
            assert (await other.call("snapshot", site="sitex"))["background_refused"] == []
            # Later, the page itself asks for some of them.
            proxy = session_socket(roots, "sitex")
            for host in ("update.googleapis.com", "update.googleapis.com", "evil.test"):
                await asyncio.to_thread(refuse_via_proxy, proxy, host)
            first = await other.call("snapshot", site="sitex")
            assert first["background_refused"] == [{"host": "update.googleapis.com", "count": 2}]
            assert [r["host"] for r in first["refused"]] == ["evil.test"]
            assert (await other.call("snapshot", site="sitex"))["background_refused"] == []
            # The first client has not been told yet, and is told once.
            told = await c.call("snapshot", site="sitex")
            assert told["background_refused"] == first["background_refused"]
            assert (await c.call("snapshot", site="sitex"))["background_refused"] == []
            await other.close()

    run(scenario())


def test_a_client_that_joins_starts_after_the_background_refusals_so_far(
    roots: sites.Roots,
) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots, startup_grace=0) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            await asyncio.to_thread(
                refuse_via_proxy, session_socket(roots, "sitex"), "update.googleapis.com"
            )
            async with await rig.connect() as late:
                joined = await late.call("open", site="sitex")
                assert joined["reused"] is True
                assert joined["background_refused"] == []
            assert (await c.call("snapshot", site="sitex"))["background_refused"] == [
                {"host": "update.googleapis.com", "count": 1}
            ]

    run(scenario())


def test_background_refusals_in_the_grace_period_are_start_up_noise(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots, startup_grace=0.4) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            proxy = session_socket(roots, "sitex")
            await asyncio.to_thread(refuse_via_proxy, proxy, "update.googleapis.com")  # a straggler
            assert (await c.call("snapshot", site="sitex"))["background_refused"] == []
            await asyncio.sleep(0.6)  # past the grace period, with nobody having asked meanwhile
            assert (await c.call("snapshot", site="sitex"))["background_refused"] == []
            await asyncio.to_thread(refuse_via_proxy, proxy, "update.googleapis.com")
            assert (await c.call("snapshot", site="sitex"))["background_refused"] == [
                {"host": "update.googleapis.com", "count": 1}
            ]

    run(scenario())


def test_an_ended_sessions_grace_timer_does_not_decide_for_its_successor(
    roots: sites.Roots,
) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots, startup_grace=0.4) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            await c.call("close", site="sitex")
            await asyncio.sleep(0.2)
            await c.call("open", site="sitex")  # its own grace period ends 0.4 s from now
            await asyncio.sleep(0.3)  # the first session's timer has fired by now
            proxy = session_socket(roots, "sitex")
            await asyncio.to_thread(refuse_via_proxy, proxy, "update.googleapis.com")
            assert (await c.call("snapshot", site="sitex"))["background_refused"] == []
            await asyncio.sleep(0.4)
            await asyncio.to_thread(refuse_via_proxy, proxy, "update.googleapis.com")
            assert (await c.call("snapshot", site="sitex"))["background_refused"] == [
                {"host": "update.googleapis.com", "count": 1}
            ]

    run(scenario())


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
                    "excluded": [],
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
            assert policy.login_pages == ()  # this history has no form submissions to learn from
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


def test_a_daemon_started_by_systemd_holds_the_lock_next_to_its_socket(
    roots: sites.Roots, short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = short_dir / "passed.sock"

    async def scenario() -> None:
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(path))
            listener.listen()
            monkeypatch.setattr(daemon, "activated_socket", lambda *_: listener.dup())
            assert client.daemon_holds_lock(path) is False
            server = daemon.Daemon(roots)
            await server.start()
            assert client.daemon_holds_lock(path) is True
            # A second one on the same socket gives up at once, and closes what it was handed.
            second = daemon.Daemon(roots)
            with pytest.raises(daemon.AlreadyRunningError, match="already running"):
                await second.start()
            assert client.daemon_holds_lock(path) is True
            await server.shutdown()
            assert client.daemon_holds_lock(path) is False
            assert path.exists()  # the service manager's socket stays

    run(scenario())


def test_an_activated_daemon_without_a_socket_name_uses_the_path_it_was_given(
    roots: sites.Roots, short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = short_dir / "given.sock"

    async def scenario() -> None:
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind("")  # an unnamed socket: nothing to name the lock after
            listener.listen()
            monkeypatch.setattr(daemon, "activated_socket", lambda *_: listener.dup())
            server = daemon.Daemon(roots)
            await server.start(path)
            assert client.daemon_holds_lock(path) is True
            await server.shutdown()

    run(scenario())


def test_an_activated_daemon_releases_the_lock_if_it_cannot_serve(
    roots: sites.Roots, short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = short_dir / "passed.sock"

    async def broken(*_args: object, **_kwargs: object) -> None:
        raise OSError

    async def scenario() -> None:
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(path))
            listener.listen()
            monkeypatch.setattr(daemon, "activated_socket", lambda *_: listener.dup())
            monkeypatch.setattr(daemon.asyncio, "start_unix_server", broken)
            with pytest.raises(OSError):  # noqa: PT011 - the error itself is the point
                await daemon.Daemon(roots).start()
            assert client.daemon_holds_lock(path) is False

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
    assert seen == [
        (
            (roots, "sitex", "https://x.test/"),
            {"proxy_socket": Path("/p.sock"), "watch_browser": True},
        )
    ]


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


def add_login_site(roots: sites.Roots, *pages: str) -> None:
    sites.save_policy(
        roots,
        sites.Policy("sitex", "https://sitex.test/", ("sitex.test",), login_pages=pages),
    )


def test_a_start_url_that_ends_on_a_recorded_login_page_means_the_login_expired(
    roots: sites.Roots,
) -> None:
    add_login_site(roots, "sitex.test/login")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            rig.factory.landing = "https://sitex.test/login?next=%2F"
            result = await c.call("open", site="sitex")
            assert result["login_expired"] is True
            assert "has expired" in result["message"]
            assert "sitex" in result["message"]
            assert result["url"] == "https://sitex.test/login?next=%2F"
            assert result["site"] == "sitex"
            # The useless session is gone, so logging in again is not blocked by it.
            assert rig.factory.made[0].closed == 1
            assert (await c.call("status", site="sitex"))["state"] == "idle"
            assert (await c.call("login", target="sitex"))["window"] == "open"

    run(scenario())


def test_a_redirect_to_a_password_page_means_the_login_expired(roots: sites.Roots) -> None:
    add_login_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            rig.factory.landing = "https://sso.sitex.test/enter"
            rig.factory.passwords = 1
            result = await c.call("open", site="sitex")
            assert result["login_expired"] is True
            assert "password field" in result["message"]
            assert (await c.call("status", site="sitex"))["state"] == "idle"

    run(scenario())


def test_a_working_login_is_never_reported_as_expired(roots: sites.Roots) -> None:
    add_login_site(roots, "sitex.test/login")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            # A redirect inside the site to a normal page.
            rig.factory.landing = "https://sitex.test/welcome"
            normal = await c.call("open", site="sitex")
            assert "login_expired" not in normal
            assert (await c.call("status", site="sitex"))["state"] == "session"
            await c.call("close", site="sitex")
            # No redirect at all, on a start page that has a login box.
            rig.factory.landing = None
            rig.factory.passwords = 1
            public = await c.call("open", site="sitex")
            assert "login_expired" not in public
            assert "password_fields" not in [call[0] for call in rig.factory.made[1].calls]
            # Joining a running session checks nothing.
            rig.factory.made[1].url = "https://sitex.test/login"
            async with await rig.connect() as other:
                joined = await other.call("open", site="sitex")
            assert joined["reused"] is True
            assert "login_expired" not in joined

    run(scenario())


def test_a_login_records_where_forms_were_submitted_from(roots: sites.Roots) -> None:
    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("login", target="https://newsite.test/")
            (window,) = rig.logins.windows
            profile = roots.state / "profile"
            (profile / "Default").mkdir(parents=True)
            database = sqlite3.connect(profile / "Default" / "History")
            database.executescript(
                "CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT);"
                "CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER,"
                " from_visit INTEGER, transition INTEGER);"
            )
            steps = [
                ("https://newsite.test/", 1, None),
                ("https://newsite.test/login", 1, 1),
                ("https://newsite.test/app", 7, 2),
            ]
            for number, (url, transition, origin) in enumerate(steps, start=1):
                database.execute("INSERT INTO urls VALUES (?, ?)", (number, url))
                database.execute(
                    "INSERT INTO visits VALUES (?, ?, ?, ?, ?)",
                    (number, number, number, origin, transition),
                )
            database.commit()
            database.close()
            await window.close_window([SeenHost("newsite.test", 3)], profile)
            await eventually(lambda: rig.daemon._sites["newsite"].kind == "idle")  # noqa: SLF001
            assert sites.load_policy(roots, "newsite").login_pages == ("newsite.test/login",)

    run(scenario())


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


def put(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def downloads_dir(roots: sites.Roots, site: str = "sitex") -> Path:
    path = sites.downloads_path(roots, site)
    daemon.make_private_dirs(path)
    sessions.session_paths(roots, site).incoming_dir.mkdir(exist_ok=True)
    return path


def incoming_dir(roots: sites.Roots, site: str = "sitex") -> Path:
    return sessions.session_paths(roots, site).incoming_dir


def test_a_click_reports_the_files_it_downloaded(roots: sites.Roots) -> None:
    add_site(roots)
    folder = downloads_dir(roots)
    (folder / "old.txt").write_text("old", encoding="utf-8")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            session = rig.factory.made[0]
            await c.call("snapshot", site="sitex")
            session.on_click = lambda: put(incoming_dir(roots) / "invoice.pdf", b"%PDF-1.7 body")
            first = await c.call("click", site="sitex", ref="e1")
            assert first["downloads"] == {
                "new": [
                    {
                        "path": {"untrusted": True, "text": str(folder / "invoice.pdf")},
                        "size": 13,
                        "mime": "application/pdf",
                    }
                ],
                "in_progress": [],
                "unsaved": 0,
            }
            assert (folder / "invoice.pdf").read_bytes() == b"%PDF-1.7 body"
            # Told once.
            session.on_click = None
            second = await c.call("click", site="sitex", ref="e1")
            assert second["downloads"] == {"new": [], "in_progress": [], "unsaved": 0}

    run(scenario())


def test_a_navigation_reports_downloads_and_late_files_show_up_on_the_next_call(
    roots: sites.Roots,
) -> None:
    add_site(roots)
    folder = downloads_dir(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            session = rig.factory.made[0]
            session.on_open = lambda: put(folder / "export.csv", b"a,b\n")
            nav = await c.call("navigate", site="sitex", url="https://sitex.test/export")
            assert [e["mime"] for e in nav["downloads"]["new"]] == ["text/plain"]
            session.on_open = None
            # A download that finished between calls is reported by the next one.
            (folder / "slow.bin").write_bytes(b"\x00\x01 binary")
            later = await c.call("navigate", site="sitex", url="https://sitex.test/other")
            assert [e["mime"] for e in later["downloads"]["new"]] == ["application/octet-stream"]

    run(scenario())


def test_a_navigation_that_became_a_download_is_reported_as_one(roots: sites.Roots) -> None:
    add_site(roots)
    folder = downloads_dir(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            session = rig.factory.made[0]
            session.abort_with = folder / "report.bin"
            result = await c.call("navigate", site="sitex", url="https://sitex.test/export")
            assert result["download_only"] is True
            assert result["page"] == {"title": {"untrusted": True, "text": ""}}
            assert [e["path"]["text"] for e in result["downloads"]["new"]] == [
                str(folder / "report.bin")
            ]
            assert result["site"] == "sitex"
            assert result["refused"] == []

    run(scenario())


def test_an_aborted_navigation_without_a_download_is_still_an_error(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            session = rig.factory.made[0]
            session.fail = sessions.AgentBrowserError("Navigation failed: net::ERR_ABORTED")
            with pytest.raises(DaemonError) as info:
                await c.call("navigate", site="sitex", url="https://sitex.test/x")
            assert "ERR_ABORTED" in info.value.message
            session.fail = sessions.AgentBrowserError("Navigation failed: net::ERR_TIMED_OUT")
            with pytest.raises(DaemonError) as info:
                await c.call("navigate", site="sitex", url="https://sitex.test/x")
            assert "ERR_TIMED_OUT" in info.value.message
            await c.call("close", site="sitex")
            with pytest.raises(DaemonError) as info:
                await c.call("navigate", site="sitex", url="https://sitex.test/x")
            assert info.value.code == "no_session"

    run(scenario())


def test_a_download_that_started_but_saved_nothing_is_reported_as_unsaved(
    roots: sites.Roots,
) -> None:
    add_site(roots)
    downloads_dir(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            session = rig.factory.made[0]
            await c.call("snapshot", site="sitex")
            session.attached = 1  # a response said "attachment", and no file arrived
            result = await c.call("click", site="sitex", ref="e1")
            assert result["downloads"] == {"new": [], "in_progress": [], "unsaved": 1}
            nav = await c.call("navigate", site="sitex", url="https://sitex.test/x")
            assert nav["downloads"]["unsaved"] == 1
            session.attached = 0
            quiet = await c.call("click", site="sitex", ref="e1")
            assert quiet["downloads"]["unsaved"] == 0

    run(scenario())


def test_counting_attachments_never_fails_the_call(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            state = rig.daemon._sites["sitex"]  # noqa: SLF001
            session = rig.factory.made[0]
            assert await rig.daemon._attachments(state) == 0  # noqa: SLF001
            session.attached = 3
            assert await rig.daemon._attachments(state) == 3  # noqa: SLF001

            session.attach_error = sessions.AgentBrowserError("gone")
            assert await rig.daemon._attachments(state) == 0  # noqa: SLF001
            await c.call("close", site="sitex")
            assert await rig.daemon._attachments(state) == 0  # noqa: SLF001

    run(scenario())


def test_a_navigation_that_aborted_with_an_unsaved_download_says_so(roots: sites.Roots) -> None:
    add_site(roots)
    downloads_dir(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            session = rig.factory.made[0]
            session.fail = sessions.AgentBrowserError("Navigation failed: net::ERR_ABORTED")
            session.attached = 1
            result = await c.call("navigate", site="sitex", url="https://sitex.test/long-name")
            assert result["download_only"] is True
            assert result["downloads"] == {"new": [], "in_progress": [], "unsaved": 1}

    run(scenario())


def test_downloads_finished_in_the_incoming_folder_are_filed_and_never_overwrite(
    roots: sites.Roots,
) -> None:
    add_site(roots)
    folder = downloads_dir(roots)
    incoming = incoming_dir(roots)
    (folder / "report.txt").write_text("the first one", encoding="utf-8")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            session = rig.factory.made[0]
            await c.call("snapshot", site="sitex")
            session.on_click = lambda: put(incoming / "report.txt", b"the second one")
            result = await c.call("click", site="sitex", ref="e1")
            assert [Path(e["path"]["text"]).name for e in result["downloads"]["new"]] == [
                "report (2).txt"
            ]
            assert (folder / "report.txt").read_text(encoding="utf-8") == "the first one"
            assert (folder / "report (2).txt").read_bytes() == b"the second one"
            assert list(incoming.iterdir()) == []

    run(scenario())


def test_closing_a_site_keeps_what_finished_after_the_last_call(roots: sites.Roots) -> None:
    add_site(roots)
    folder = downloads_dir(roots)
    incoming = incoming_dir(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            put(incoming / "late.bin", b"\x00\x01 finished after the last call")
            put(incoming / "half.bin.crdownload", b"partial")
            await c.call("close", site="sitex")
            assert (folder / "late.bin").exists()
            assert not (folder / "half.bin").exists()

    run(scenario())


def test_running_downloads_are_reported_as_in_progress(roots: sites.Roots) -> None:
    add_site(roots)
    folder = downloads_dir(roots)

    async def scenario() -> None:
        async with serving(roots, download_wait=0.1) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            await c.call("snapshot", site="sitex")
            rig.factory.made[0].on_click = lambda: put(
                incoming_dir(roots) / "big.bin.crdownload", b"x" * 5
            )
            result = await c.call("click", site="sitex", ref="e1")
            assert result["downloads"]["new"] == []
            (progress,) = result["downloads"]["in_progress"]
            assert progress["path"]["text"] == str(folder / "big.bin")
            assert progress["size"] == 5
            listing = await c.call("downloads", site="sitex")
            assert listing["files"] == []
            assert len(listing["in_progress"]) == 1

    run(scenario())


def test_the_downloads_op_lists_the_folder_and_marks_what_is_new_to_this_client(
    roots: sites.Roots,
) -> None:
    add_site(roots)
    folder = downloads_dir(roots)
    (folder / "before.txt").write_text("before", encoding="utf-8")
    outside = folder.parent / "secret.txt"
    outside.write_text("secret", encoding="utf-8")
    (folder / "link.txt").symlink_to(outside)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as one, await rig.connect() as two:
            first = await one.call("downloads", site="sitex")
            assert [(f["path"]["text"], f["new"]) for f in first["files"]] == [
                (str(folder / "before.txt"), False)
            ]
            (folder / "after.txt").write_bytes(PDF_BYTES)
            second = await one.call("downloads", site="sitex")
            assert [
                (Path(f["path"]["text"]).name, f["new"], f["mime"]) for f in second["files"]
            ] == [
                ("after.txt", True, "application/pdf"),
                ("before.txt", False, "text/plain"),
            ]
            again = await one.call("downloads", site="sitex")
            assert not any(f["new"] for f in again["files"])
            # Another client starts from what is there when it first asks.
            other = await two.call("downloads", site="sitex")
            assert not any(f["new"] for f in other["files"])
            assert "secret" not in str(second)

    run(scenario())


def test_the_downloads_op_on_a_site_with_no_folder(roots: sites.Roots) -> None:
    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            assert await c.call("downloads", site="never") == {
                "site": "never",
                "files": [],
                "in_progress": [],
            }
            with pytest.raises(DaemonError) as info:
                await c.call("downloads", site="../x")
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


# -- what is running: status, watch, liveness, announcements --------------------------------


async def drain(stream: AsyncGenerator[dict[str, Any]]) -> None:
    async for _ in stream:
        pass


async def next_event(stream: AsyncGenerator[dict[str, Any]]) -> dict[str, Any]:
    return await asyncio.wait_for(anext(stream), 10)


def test_status_without_a_site_says_what_is_running(roots: sites.Roots) -> None:
    add_site(roots, "sitex")
    add_site(roots, "another")
    add_site(roots, "idle")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            assert await c.call("status") == {"sessions": [], "logins": []}
            await c.call("open", site="sitex")
            await c.call("login", target="another")
            assert await c.call("status") == {
                "sessions": [
                    {
                        "site": "sitex",
                        "since": "2026-10-27T12:00:00Z",
                        "contained": True,
                        "host": "sitex.test",
                    }
                ],
                "logins": [{"site": "another", "since": "2026-10-27T12:00:00Z"}],
            }
            await c.call("close", site="sitex")
            assert (await c.call("status"))["sessions"] == []

    run(scenario())


def test_status_names_the_host_and_never_the_address(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            await c.call(
                "navigate", site="sitex", url="https://sitex.test/account?token=secret#frag"
            )
            answer = await c.call("status")
            assert answer["sessions"][0]["host"] == "sitex.test"
            assert "secret" not in json.dumps(answer)
            assert "account" not in json.dumps(answer)

    run(scenario())


def test_a_page_without_a_host_has_none() -> None:
    assert daemon._host_of("about:blank") is None  # noqa: SLF001
    assert daemon._host_of("data:text/html,hi") is None  # noqa: SLF001
    assert daemon._host_of("http://bad_host/") is None  # noqa: SLF001
    assert daemon._host_of("https://App.Sitex.test:8443/x?y=1") == "app.sitex.test"  # noqa: SLF001


def test_watch_sends_a_snapshot_and_then_every_change(roots: sites.Roots) -> None:
    add_site(roots, "sitex")
    add_site(roots, "another")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c, await rig.connect() as w:
            await c.call("open", site="sitex")
            stream = w.watch()
            snapshot = await next_event(stream)
            assert snapshot["event"] == "snapshot"
            assert snapshot["at"] == "2026-10-27T12:00:00Z"
            assert [s["site"] for s in snapshot["sessions"]] == ["sitex"]
            assert snapshot["logins"] == []
            at = "2026-10-27T12:00:00Z"
            await c.call("close", site="sitex")
            assert await next_event(stream) == {
                "event": "session_ended", "site": "sitex", "at": at,
            }  # fmt: skip
            await c.call("open", site="sitex")
            assert (await next_event(stream))["event"] == "session_started"
            await c.call("login", target="another")
            assert await next_event(stream) == {
                "event": "login_opened", "site": "another", "at": at,
            }  # fmt: skip
            await c.call("close", site="another")
            assert (await next_event(stream))["event"] == "login_closed"
            await stream.aclose()

    run(scenario())


def test_watch_is_removed_when_the_client_leaves(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c, await rig.connect() as w:
            stream = w.watch()
            await next_event(stream)
            assert len(rig.daemon._watchers) == 1  # noqa: SLF001
            await stream.aclose()
            await w.close()
            await eventually(lambda: not rig.daemon._watchers)  # noqa: SLF001
            await c.call("open", site="sitex")  # nobody is told; nothing fails

    run(scenario())


def test_every_watcher_gets_every_event(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with (
            serving(roots) as rig,
            await rig.connect() as c,
            await rig.connect() as w1,
            await rig.connect() as w2,
        ):
            streams = [w1.watch(), w2.watch()]
            for stream in streams:
                await next_event(stream)
            await c.call("open", site="sitex")
            for stream in streams:
                assert (await next_event(stream))["event"] == "session_started"
                await stream.aclose()

    run(scenario())


def test_a_watcher_that_falls_too_far_behind_is_disconnected(
    roots: sites.Roots, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(daemon, "WATCH_QUEUE", 2)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as w:
            stream = w.watch()
            await next_event(stream)
            for _ in range(3):  # no await between them: the stream cannot keep up
                rig.daemon._emit("session_started", "sitex")  # noqa: SLF001
            with pytest.raises(DaemonError) as info:
                await drain(stream)
            assert info.value.code == "connection_lost"
            assert not rig.daemon._watchers  # noqa: SLF001

    run(scenario())


def test_a_session_whose_browser_died_is_ended_and_reported(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots, poll_interval=0.02) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            first = rig.factory.made[0]
            async with await rig.connect() as w:
                stream = w.watch()
                assert len((await next_event(stream))["sessions"]) == 1
                first.alive = False
                event = await next_event(stream)
                assert (event["event"], event["site"]) == ("session_ended", "sitex")
                await stream.aclose()
            assert first.closed == 1
            assert (await c.call("status"))["sessions"] == []
            assert (await c.call("status", site="sitex"))["state"] == "idle"
            reopened = await c.call("open", site="sitex")
            assert reopened["reused"] is False

    run(scenario())


def test_a_healthy_session_is_left_alone_by_the_liveness_check(
    roots: sites.Roots, monkeypatch: pytest.MonkeyPatch
) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots, poll_interval=0.01) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            checks: list[int] = []
            session = rig.factory.made[0]
            original = session.is_alive

            def counted() -> bool:
                checks.append(1)
                return original()

            monkeypatch.setattr(session, "is_alive", counted)
            await eventually(lambda: len(checks) >= 3)
            assert session.closed == 0
            assert len((await c.call("status"))["sessions"]) == 1

    run(scenario())


def test_a_login_window_is_left_alone_by_the_liveness_check(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots, poll_interval=0.01) as rig, await rig.connect() as c:
            await c.call("login", target="sitex")
            await asyncio.sleep(0.1)
            assert (await c.call("status"))["logins"][0]["site"] == "sitex"

    run(scenario())


def test_a_failing_liveness_check_is_logged_and_the_next_one_runs(
    roots: sites.Roots, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots, poll_interval=0.02) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            first = rig.factory.made[0]

            def broken() -> bool:
                message = "no process table"
                raise OSError(message)

            monkeypatch.setattr(first, "is_alive", broken)
            await eventually(lambda: "checking the sitex session failed" in caplog.text)
            monkeypatch.setattr(first, "is_alive", lambda: False)
            await eventually(lambda: first.closed == 1)

    run(scenario())


def test_a_started_session_is_announced_once(roots: sites.Roots, announcements: list[str]) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            await c.call("open", site="sitex")  # joins the running session
            await eventually(lambda: announcements == ["sitex"])
            await c.call("close", site="sitex")
            await c.call("open", site="sitex")
            await eventually(lambda: announcements == ["sitex", "sitex"])

    run(scenario())


def test_a_failing_announcement_does_not_fail_the_open(
    roots: sites.Roots, caplog: pytest.LogCaptureFixture
) -> None:
    add_site(roots)

    async def broken(_site: str) -> None:
        message = "no bus"
        raise RuntimeError(message)

    async def scenario() -> None:
        async with serving(roots, announcer=broken) as rig, await rig.connect() as c:
            assert (await c.call("open", site="sitex"))["reused"] is False
            await eventually(lambda: "announcing the sitex session failed" in caplog.text)

    run(scenario())


class FakeNotifier:
    """Stands in for the ``notify-send`` process."""

    def __init__(self, *, hang: bool = False, status: int = 0) -> None:
        self.hang = hang
        self.status = status
        self.killed = False
        self._released = asyncio.Event()

    async def wait(self) -> int:
        if self.hang and not self.killed:
            await self._released.wait()
        return self.status

    def kill(self) -> None:
        self.killed = True
        self._released.set()


def test_announce_runs_notify_send_with_only_the_site_name(
    real_announce: Callable[..., Awaitable[None]],
) -> None:
    calls: list[tuple[Any, ...]] = []

    async def spawn(*args: Any, **kwargs: Any) -> FakeNotifier:  # noqa: ANN401
        calls.append((args, kwargs))
        return FakeNotifier()

    run(real_announce("sitex", which=lambda _name: "/usr/bin/notify-send", spawn=spawn))
    ((args, kwargs),) = calls
    assert args == (
        "/usr/bin/notify-send",
        "--app-name=valetkey",
        "--",
        "valetkey: a browser session for sitex started",
    )
    assert kwargs["stdin"] == kwargs["stdout"] == kwargs["stderr"] == asyncio.subprocess.DEVNULL


def test_announce_is_skipped_without_notify_send(
    real_announce: Callable[..., Awaitable[None]],
) -> None:
    async def spawn(*_args: Any, **_kwargs: Any) -> FakeNotifier:  # noqa: ANN401
        message = "must not run"
        raise AssertionError(message)

    run(real_announce("sitex", which=lambda _name: None, spawn=spawn))


def test_announce_logs_a_program_that_cannot_run(
    real_announce: Callable[..., Awaitable[None]], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("INFO", logger="valetkey.daemon")

    async def spawn(*_args: Any, **_kwargs: Any) -> FakeNotifier:  # noqa: ANN401
        raise PermissionError

    run(real_announce("sitex", which=lambda _name: "/x", spawn=spawn))
    assert "notify-send could not start" in caplog.text


def test_announce_logs_a_notification_that_failed(
    real_announce: Callable[..., Awaitable[None]], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("INFO", logger="valetkey.daemon")

    async def spawn(*_args: Any, **_kwargs: Any) -> FakeNotifier:  # noqa: ANN401
        return FakeNotifier(status=1)

    run(real_announce("sitex", which=lambda _name: "/x", spawn=spawn))
    assert "notify-send exited with status 1, so no notification was shown" in caplog.text


def test_announce_logs_nothing_when_the_notification_was_shown_or_skipped(
    real_announce: Callable[..., Awaitable[None]], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("INFO", logger="valetkey.daemon")

    async def spawn(*_args: Any, **_kwargs: Any) -> FakeNotifier:  # noqa: ANN401
        return FakeNotifier()

    run(real_announce("sitex", which=lambda _name: "/x", spawn=spawn))
    run(real_announce("sitex", which=lambda _name: None, spawn=spawn))
    assert caplog.text == ""


def test_announce_kills_a_notification_that_hangs(
    real_announce: Callable[..., Awaitable[None]],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("INFO", logger="valetkey.daemon")
    monkeypatch.setattr(daemon, "NOTIFY_TIMEOUT", 0.05)
    notifier = FakeNotifier(hang=True)

    async def spawn(*_args: Any, **_kwargs: Any) -> FakeNotifier:  # noqa: ANN401
        return notifier

    run(real_announce("sitex", which=lambda _name: "/x", spawn=spawn))
    assert notifier.killed
    assert "notify-send did not finish in 0.05 seconds and was stopped" in caplog.text


def test_the_daemon_keeps_nothing_running_after_shutdown(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> daemon.Daemon:
        async with serving(roots, poll_interval=0.01) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            return rig.daemon

    server = run(scenario())
    assert server._monitor is not None  # noqa: SLF001
    assert server._monitor.cancelled()  # noqa: SLF001
    assert not server._background  # noqa: SLF001


def process_ids(profile: Path, *, program: str) -> list[int]:
    """The host's processes named ``program`` that have ``profile`` in their arguments."""
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        arguments = raw.decode(errors="replace").split("\0")
        if Path(arguments[0]).name == program and any(str(profile) in a for a in arguments):
            found.append(int(entry.name))
    return found


@pytest.mark.integration
@needs_everything
def test_a_killed_browser_or_holder_is_reported_within_two_seconds(roots: sites.Roots) -> None:
    sites.save_policy(roots, sites.Policy("demo", "http://site.test/", ("site.test",)))
    profile = sites.profile_path(roots, "demo")

    async def killed(
        stream: AsyncGenerator[dict[str, Any]], pid: int
    ) -> tuple[dict[str, Any], float]:
        started = time.monotonic()
        os.kill(pid, signal.SIGKILL)
        event = await next_event(stream)
        return event, time.monotonic() - started

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
                path = client.socket_path(roots)
                async with (
                    await client.Client.connect(path) as one,
                    await client.Client.connect(path) as watcher,
                ):
                    stream = watcher.watch()
                    assert (await next_event(stream))["sessions"] == []
                    for victim, label in (("chromium", "Chrome"), ("bwrap", "the holder")):
                        opened = await one.call("open", site="demo")
                        assert opened["reused"] is False, label  # a fresh session, every time
                        assert (await next_event(stream))["event"] == "session_started"
                        (entry,) = (await one.call("status"))["sessions"]
                        assert entry["host"] == "site.test"
                        pids = process_ids(profile, program=victim)
                        assert pids, f"no {victim} process found for {label}"
                        event, seconds = await killed(stream, min(pids))
                        assert (event["event"], event["site"]) == ("session_ended", "demo"), label
                        assert seconds < 2.0, f"{label}: {seconds:.2f}s"
                        assert (await one.call("status"))["sessions"] == []
                        # The session was torn down, not only reported: nothing of it is left.
                        paths = sessions.session_paths(roots, "demo")
                        assert not paths.directory.exists(), label
                        assert not paths.driver_dir.exists(), label
                        assert process_ids(profile, program="bwrap") == [], label
                        assert process_ids(profile, program="chromium") == [], label
                        assert not any(  # so `valetkey forget` would not call the profile in use
                            procs.uses_path(arguments, profile)
                            for arguments in procs.command_lines()
                        ), label
                    await stream.aclose()
            finally:
                await server.shutdown()

    run(scenario())
    assert process_ids(profile, program="chromium") == []


def test_the_liveness_check_does_not_end_a_session_opened_since(roots: sites.Roots) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            state = rig.daemon._state("sitex")  # noqa: SLF001
            current = rig.factory.made[0]
            await rig.daemon._end_if_current(state, FakeSession())  # noqa: SLF001
            assert (current.closed, state.kind) == (0, "session")
            await rig.daemon._end_if_current(state, current)  # noqa: SLF001
            assert (current.closed, state.kind) == (1, "idle")

    run(scenario())
