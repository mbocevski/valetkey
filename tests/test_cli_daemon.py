# SPDX-License-Identifier: Apache-2.0
"""The commands that change a site (allow, deny, forget) when a daemon is running."""

import asyncio
import fcntl
import io
import json
import os
import socket
import sys
import threading
import time
from typing import TYPE_CHECKING, Any, Self

import pytest
import test_daemon
from environment import unusable_reason
from proxy_stub import PageServer

from valetkey import cli, client, daemon, sites
from valetkey.cli import main

if TYPE_CHECKING:
    from pathlib import Path


class FakeDaemon:
    """Holds the daemon's lock, listens on its socket and answers from a table of handlers.

    A handler gets the request's arguments and returns the result, or ``(code, message)`` for
    an error answer, or ``None`` to never answer.
    """

    def __init__(self, runtime: Path, handlers: dict[str, Any]) -> None:
        self.socket_path = runtime / "valetkey" / client.SOCKET_NAME
        self.handlers = handlers
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._stop: asyncio.Event | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._lock_fd = -1

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while line := await reader.readline():
            request = json.loads(line)
            self.calls.append((request["op"], request["args"]))
            outcome = self.handlers[request["op"]](request["args"])
            if outcome is None:
                continue
            if isinstance(outcome, tuple):
                code, message = outcome
                answer: dict[str, Any] = {
                    "id": request["id"],
                    "ok": False,
                    "error": {"code": code, "message": message},
                }
            else:
                answer = {"id": request["id"], "ok": True, "result": outcome}
            writer.write(json.dumps(answer).encode() + b"\n")
            await writer.drain()
        writer.close()

    async def _serve(self) -> None:
        self._stop = asyncio.Event()
        server = await asyncio.start_unix_server(self._handle, path=str(self.socket_path))
        self._ready.set()
        await self._stop.wait()
        server.close()
        server.close_clients()
        await server.wait_closed()

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._serve())

    def __enter__(self) -> Self:
        self.socket_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._lock_fd = os.open(client.lock_path(self.socket_path), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self._thread.start()
        assert self._ready.wait(10)
        return self

    def __exit__(self, *_: object) -> None:
        stop = self._stop
        assert stop is not None
        self._loop.call_soon_threadsafe(stop.set)
        self._thread.join(10)
        self._loop.close()
        os.close(self._lock_fd)

    @property
    def ops(self) -> list[str]:
        return [op for op, _ in self.calls]


@pytest.fixture
def roots(short_dir: Path, monkeypatch: pytest.MonkeyPatch) -> sites.Roots:
    (short_dir / "run").mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(short_dir / "run"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(short_dir / "cfg"))
    monkeypatch.setenv("XDG_STATE_HOME", str(short_dir / "state"))
    monkeypatch.setenv("HOME", str(short_dir))
    return sites.roots_from_env()


def make_site(roots: sites.Roots, name: str = "sitex") -> list[Path]:
    sites.save_policy(roots, sites.Policy(name, f"https://{name}.test/", (f"{name}.test",)))
    profile = sites.ensure_profile(roots, name)
    downloads = sites.ensure_downloads(roots, name)
    (profile / "Cookies").write_text("x", encoding="utf-8")
    return [sites.policy_path(roots, name), profile, downloads]


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    status = main(list(argv))
    captured = capsys.readouterr()
    return status, captured.out, captured.err


def listing(state: str, site: str = "sitex") -> Any:  # noqa: ANN401 - a handler
    return lambda _args: {"sites": [{"site": site, "state": state}]}


# -- finding the daemon without starting it ------------------------------------------------


def test_the_daemon_is_looked_for_without_connecting(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    """A socket nobody holds the lock for is not a daemon: connecting could start one."""
    make_site(roots)
    path = client.socket_path(roots)
    path.parent.mkdir(mode=0o700, parents=True)
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(path))
        listener.listen()
        listener.settimeout(0.3)
        status, out, err = run(capsys, "allow", "sitex", "other.test")
        assert (status, out, err) == (0, "sitex: other.test is allowed.\n", "")
        with pytest.raises(TimeoutError):  # nobody connected
            listener.accept()


def test_a_lock_without_a_listener_is_not_an_error(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots)
    path = client.socket_path(roots)
    path.parent.mkdir(mode=0o700, parents=True)
    descriptor = os.open(client.lock_path(path), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    try:
        assert run(capsys, "allow", "sitex", "other.test") == (
            0,
            "sitex: other.test is allowed.\n",
            "",
        )
    finally:
        os.close(descriptor)


def test_without_a_runtime_directory_nothing_is_asked(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    make_site(roots)
    monkeypatch.delenv("XDG_RUNTIME_DIR")
    assert run(capsys, "allow", "sitex", "other.test")[0] == 0


# -- allow and deny -------------------------------------------------------------------------


def test_allow_tells_the_daemon_and_says_so_for_a_live_session(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots)
    reload = {"reload_policy": lambda args: {"site": args["site"], "live": True}}
    with FakeDaemon(client.socket_path(roots).parent.parent, reload) as fake:
        status, out, err = run(capsys, "allow", "sitex", "other.test")
    assert (status, err) == (0, "")
    assert out == "sitex: other.test is allowed.\nsitex: applied to the running session.\n"
    assert fake.calls == [("reload_policy", {"site": "sitex"})]
    assert "other.test" in sites.load_policy(roots, "sitex").allow


def test_deny_tells_the_daemon_too(roots: sites.Roots, capsys: pytest.CaptureFixture[str]) -> None:
    make_site(roots)
    reload = {"reload_policy": lambda _args: {"live": True}}
    with FakeDaemon(client.socket_path(roots).parent.parent, reload) as fake:
        status, out, _ = run(capsys, "deny", "sitex", "sitex.test")
    assert status == 0
    assert (
        out == "sitex: sitex.test is no longer allowed.\n"
        "sitex: sitex.test is denied, so a login will not allow it again.\n"
        "sitex: applied to the running session.\n"
    )
    assert fake.ops == ["reload_policy"]


def test_allow_says_nothing_extra_when_no_session_is_live(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots)
    reload = {"reload_policy": lambda _args: {"live": False}}
    with FakeDaemon(client.socket_path(roots).parent.parent, reload):
        assert run(capsys, "allow", "sitex", "other.test") == (
            0,
            "sitex: other.test is allowed.\n",
            "",
        )


def test_a_daemon_error_is_a_warning_and_the_change_stands(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots)
    bad = {"reload_policy": lambda _args: ("bad_policy", "the policy file is not valid")}
    with FakeDaemon(client.socket_path(roots).parent.parent, bad):
        status, out, err = run(capsys, "allow", "sitex", "other.test")
    assert status == 0
    assert out == "sitex: other.test is allowed.\n"
    assert "the change is saved, but the running daemon did not apply it" in err
    assert "the policy file is not valid" in err
    assert "other.test" in sites.load_policy(roots, "sitex").allow


def test_a_daemon_that_does_not_answer_is_a_warning(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    make_site(roots)
    monkeypatch.setattr(cli, "ANSWER_TIMEOUT", 0.3)
    silent = {"reload_policy": lambda _args: None}
    with FakeDaemon(client.socket_path(roots).parent.parent, silent):
        started = time.monotonic()
        status, _, err = run(capsys, "deny", "sitex", "sitex.test")
        waited = time.monotonic() - started
    assert status == 0
    assert waited < 5
    assert "did not answer within 0.3 seconds" in err
    assert "sitex.test" not in sites.load_policy(roots, "sitex").allow


def test_an_invalid_policy_file_still_fails_before_the_daemon_is_asked(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots)
    sites.policy_path(roots, "sitex").write_text("{", encoding="utf-8")
    with FakeDaemon(client.socket_path(roots).parent.parent, {}) as fake:
        status, _, err = run(capsys, "allow", "sitex", "other.test")
    assert status == 1
    assert err.startswith("valetkey:")
    assert fake.calls == []


def test_a_daemon_that_ends_between_the_lock_and_the_connection_is_not_running(
    roots: sites.Roots,
) -> None:
    path = client.socket_path(roots)
    path.parent.mkdir(mode=0o700, parents=True)
    descriptor = os.open(client.lock_path(path), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    try:
        assert cli._ask_daemon(roots, "sites") is None  # noqa: SLF001 - the race this guards
    finally:
        os.close(descriptor)


# -- forget ---------------------------------------------------------------------------------


class Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_forget_closes_the_session_before_deleting(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    targets = make_site(roots)
    seen_at_close: list[bool] = []

    def close(args: dict[str, Any]) -> dict[str, Any]:
        seen_at_close.append(all(path.exists() for path in targets))
        return {"site": args["site"], "closed": True}

    handlers = {"sites": listing("session"), "close": close}
    monkeypatch.setattr(cli, "_profile_in_use", lambda _profile: False)
    with FakeDaemon(client.socket_path(roots).parent.parent, handlers) as fake:
        status, out, err = run(capsys, "forget", "sitex", "--yes")
    assert (status, out, err) == (0, "Forgot sitex.\n", "")
    assert fake.ops == ["sites", "close"]
    assert fake.calls[1] == ("close", {"site": "sitex"})
    assert seen_at_close == [True]
    assert not any(path.exists() for path in targets)


def test_forget_asks_before_it_closes_anything(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    targets = make_site(roots)
    handlers = {"sites": listing("session"), "close": lambda _args: {}}
    monkeypatch.setattr(sys, "stdin", Terminal("n\n"))
    with FakeDaemon(client.socket_path(roots).parent.parent, handlers) as fake:
        status, out, _ = run(capsys, "forget", "sitex")
    assert status == 1
    assert "Nothing was deleted." in out
    assert fake.ops == ["sites"]
    assert all(path.exists() for path in targets)


def test_forget_without_a_terminal_refuses_before_it_closes_anything(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    make_site(roots)
    handlers = {"sites": listing("session"), "close": lambda _args: {}}
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    with FakeDaemon(client.socket_path(roots).parent.parent, handlers) as fake:
        status, _, err = run(capsys, "forget", "sitex")
    assert status == 1
    assert "add --yes" in err
    assert fake.ops == ["sites"]


def test_forget_refuses_while_a_login_window_is_open(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    targets = make_site(roots)
    handlers = {"sites": listing("login"), "close": lambda _args: {}}
    with FakeDaemon(client.socket_path(roots).parent.parent, handlers) as fake:
        status, _, err = run(capsys, "forget", "sitex", "--yes")
    assert status == 1
    assert err == "valetkey: a login window for sitex is open; close it first\n"
    assert fake.ops == ["sites"]
    assert all(path.exists() for path in targets)


def test_forget_refuses_a_browser_the_daemon_does_not_own(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The daemon has no session, but a process still has the profile open: closing is no help."""
    targets = make_site(roots)
    handlers = {"sites": listing("idle"), "close": lambda _args: {}}
    monkeypatch.setattr(cli, "_profile_in_use", lambda _profile: True)
    with FakeDaemon(client.socket_path(roots).parent.parent, handlers) as fake:
        status, _, err = run(capsys, "forget", "sitex", "--yes")
    assert status == 1
    assert "the browser for sitex is open; close that session first" in err
    assert fake.ops == ["sites"]
    assert all(path.exists() for path in targets)


def test_forget_checks_again_after_closing_and_deletes_nothing_if_a_stray_remains(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    targets = make_site(roots)
    handlers = {"sites": listing("session"), "close": lambda _args: {"closed": True}}
    monkeypatch.setattr(cli, "_profile_in_use", lambda _profile: True)
    with FakeDaemon(client.socket_path(roots).parent.parent, handlers) as fake:
        status, _, err = run(capsys, "forget", "sitex", "--yes")
    assert status == 1
    assert "a browser outside valetkey's daemon is still using sitex's profile" in err
    assert fake.ops == ["sites", "close"]
    assert all(path.exists() for path in targets)


def test_forget_for_a_site_the_daemon_does_not_list_checks_the_process_table(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    targets = make_site(roots)
    handlers = {"sites": lambda _args: {"sites": []}, "close": lambda _args: {}}
    monkeypatch.setattr(cli, "_profile_in_use", lambda _profile: False)
    with FakeDaemon(client.socket_path(roots).parent.parent, handlers) as fake:
        assert run(capsys, "forget", "sitex", "--yes")[0] == 0
    assert fake.ops == ["sites"]  # nothing to close
    assert not any(path.exists() for path in targets)


@pytest.mark.parametrize("failing", ["sites", "close"])
def test_forget_stops_when_the_daemon_fails(
    roots: sites.Roots,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    failing: str,
) -> None:
    targets = make_site(roots)
    handlers: dict[str, Any] = {"sites": listing("session"), "close": lambda _args: {}}
    handlers[failing] = lambda _args: ("internal", "it broke")
    monkeypatch.setattr(cli, "_profile_in_use", lambda _profile: False)
    with FakeDaemon(client.socket_path(roots).parent.parent, handlers):
        status, _, err = run(capsys, "forget", "sitex", "--yes")
    assert status == 1
    assert "it broke" in err
    assert all(path.exists() for path in targets)


# -- against the real daemon and a real browser ---------------------------------------------

_SKIP = unusable_reason("bwrap", "chromium", "agent-browser")
needs_everything = pytest.mark.skipif(_SKIP is not None, reason=_SKIP or "")


def local_proxy_options(upstream: tuple[str, int]) -> dict[str, Any]:
    """Proxy settings that send every connection to a local server."""

    async def resolve(_host: str, _port: int) -> list[str]:
        return ["127.0.0.1"]

    async def connect(_address: str, _port: int) -> Any:  # noqa: ANN401
        return await asyncio.open_connection(*upstream)

    return {"resolver": resolve, "connector": connect, "address_check": lambda _a: None}


class RealDaemon:
    """A daemon on a thread of its own. By default the real one, reaching a local page server."""

    def __init__(self, server: daemon.Daemon) -> None:
        self._server = server
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._stop: asyncio.Event | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    async def _serve(self) -> None:
        self._stop = asyncio.Event()
        await self._server.start()
        self._ready.set()
        await self._stop.wait()
        await self._server.shutdown()

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._serve())

    def __enter__(self) -> Self:
        self._thread.start()
        assert self._ready.wait(30)
        return self

    def __exit__(self, *_: object) -> None:
        stop = self._stop
        assert stop is not None
        self._loop.call_soon_threadsafe(stop.set)
        self._thread.join(60)
        self._loop.close()


class Connection:
    """One long-lived client connection, as an MCP adapter has.

    The daemon tells a connection about refusals made after the connection first asked, so a
    test that wants to see them keeps one connection for the whole session.
    """

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()
        self._client = self._run(client.Client.connect())

    def _run(self, work: Any) -> Any:  # noqa: ANN401 - a coroutine and what it returns
        return asyncio.run_coroutine_threadsafe(work, self._loop).result(90)

    def call(self, op: str, **args: str) -> dict[str, Any]:
        return self._run(self._client.call(op, **args))

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self._run(self._client.close())
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(10)
        self._loop.close()


def refused_hosts(answer: dict[str, Any]) -> set[str]:
    return {entry["host"] for entry in answer["refused"]}


PAGES = {
    "/": "<title>Start</title><p>hello</p>",
    "/other": "<title>Other</title><p>second site</p>",
}


@pytest.fixture
def live_roots(roots: sites.Roots) -> sites.Roots:
    sites.save_policy(roots, sites.Policy("demo", "http://site.test/", ("site.test",)))
    return roots


@pytest.mark.integration
@needs_everything
def test_allow_and_deny_change_a_running_session_at_once(
    live_roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    with (
        PageServer(PAGES) as pages,
        RealDaemon(daemon.Daemon(live_roots, proxy_options=local_proxy_options(pages.address))),
        Connection() as ask,
    ):
        assert ask.call("open", site="demo")["page"]["title"]["text"] == "Start"
        capsys.readouterr()
        other = "http://other.test/other"
        # A host the policy does not list is refused, and its page does not load.
        blocked = ask.call("navigate", site="demo", url=other)
        assert refused_hosts(blocked) == {"other.test"}
        assert blocked["page"]["title"]["text"] != "Other"
        # Allowing it takes effect for the very next navigation.
        status, out, err = run(capsys, "allow", "demo", "other.test")
        assert (status, err) == (0, "")
        assert "demo: applied to the running session." in out
        loaded = ask.call("navigate", site="demo", url=other)
        assert loaded["page"]["title"]["text"] == "Other"
        assert refused_hosts(loaded) == set()
        # Denying it takes effect just as fast.
        status, out, _ = run(capsys, "deny", "demo", "other.test")
        assert status == 0
        assert "demo: applied to the running session." in out
        again = ask.call("navigate", site="demo", url=other)
        assert refused_hosts(again) == {"other.test"}
        assert again["page"]["title"]["text"] != "Other"
        ask.call("close", site="demo")


@pytest.mark.integration
@needs_everything
def test_forget_closes_a_running_session_and_deletes_everything(
    live_roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    profile = sites.profile_path(live_roots, "demo")
    with (
        PageServer(PAGES) as pages,
        RealDaemon(daemon.Daemon(live_roots, proxy_options=local_proxy_options(pages.address))),
        Connection() as ask,
    ):
        ask.call("open", site="demo")
        assert profile.exists()
        capsys.readouterr()
        status, out, err = run(capsys, "forget", "demo", "--yes")
        assert (status, out, err) == (0, "Forgot demo.\n", "")
        assert not profile.exists()
        assert not sites.policy_path(live_roots, "demo").exists()
        assert not sites.downloads_path(live_roots, "demo").exists()
        with pytest.raises(client.DaemonError) as info:
            ask.call("snapshot", site="demo")
        assert info.value.code == "no_session"
        states = {entry["site"]: entry["state"] for entry in ask.call("sites")["sites"]}
        assert states.get("demo", "idle") == "idle"


def test_allow_reaches_a_daemon_that_systemd_started(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The daemon is handed its socket, as under systemd, and still holds the lock."""
    make_site(roots)
    path = client.socket_path(roots)
    path.parent.mkdir(mode=0o700, parents=True)
    factory = test_daemon.Factory()
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(path))
        listener.listen()
        monkeypatch.setattr(daemon, "activated_socket", lambda *_: listener.dup())
        server = daemon.Daemon(roots, session_factory=factory, startup_grace=0)
        with RealDaemon(server), Connection() as ask:
            assert client.daemon_holds_lock(path)
            ask.call("open", site="sitex")
            capsys.readouterr()
            status, out, err = run(capsys, "allow", "sitex", "other.test")
            assert (status, err) == (0, "")
            assert out == "sitex: other.test is allowed.\nsitex: applied to the running session.\n"
            ask.call("close", site="sitex")
    assert not client.daemon_holds_lock(path)


# -- the microphone -----------------------------------------------------------------------


def test_mic_turns_the_microphone_on_and_off_and_tells_a_live_session_it_is_unchanged(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots)
    reload = {"reload_policy": lambda args: {"site": args["site"], "live": True}}
    with FakeDaemon(client.socket_path(roots).parent.parent, reload) as fake:
        status, out, err = run(capsys, "mic", "sitex", "on")
        assert (status, err) == (0, "")
        assert out == (
            "sitex: the microphone is now on.\n"
            "sitex: the running session keeps its setting. Close it and open it again.\n"
        )
        assert sites.load_policy(roots, "sitex").microphone is True
        assert run(capsys, "mic", "sitex")[1] == "sitex: the microphone is on.\n"
        assert run(capsys, "mic", "sitex", "off")[1].startswith("sitex: the microphone is now off.")
        assert sites.load_policy(roots, "sitex").microphone is False
    assert fake.ops == ["reload_policy", "reload_policy"]
