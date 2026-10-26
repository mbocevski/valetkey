# SPDX-License-Identifier: Apache-2.0
import asyncio
import contextlib
import json
import logging
import os
import select
import shlex
import signal
import socket
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from environment import unusable_reason
from sway import Sway
from test_wayland import Compositor, Peer, accepting

from valetkey import login, sandbox, sites, wayland
from valetkey.proxy import SeenHost
from valetkey.wayland import decode_string

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping

NO_SESSION = "no desktop session here — log in on a machine with one, or enable remote logins"


@pytest.fixture
def short_dir() -> Iterator[Path]:
    """A short temporary directory: Unix socket paths are limited to about 100 bytes."""
    with tempfile.TemporaryDirectory(prefix="vk-") as directory:
        yield Path(directory)


def run[T](scenario: Any) -> T:  # noqa: ANN401 - any awaitable
    return asyncio.run(asyncio.wait_for(scenario, 60))


# -- finding the display -------------------------------------------------------------------


@pytest.fixture
def wayland_dir(short_dir: Path) -> Iterator[Path]:
    """A runtime directory holding a real Unix socket, named as a display is."""
    runtime = short_dir / "run"
    runtime.mkdir()
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(runtime / "wayland-9"))
        yield runtime


def never() -> Mapping[str, str]:
    msg = "the user manager should not have been asked"
    raise AssertionError(msg)


def test_parse_environment() -> None:
    text = "A=1\nWAYLAND_DISPLAY=wayland-1\nNOEQUALS\n=orphan\nQUOTED=$'a b'\nEMPTY=\nX=a=b\n"
    assert login.parse_environment(text) == {
        "A": "1",
        "WAYLAND_DISPLAY": "wayland-1",
        "QUOTED": "a b",
        "EMPTY": "",
        "X": "a=b",
    }


def test_systemd_user_environment_parses_the_command_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[list[str]] = []

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, "WAYLAND_DISPLAY=wayland-1\n", "")

    monkeypatch.setattr(login.subprocess, "run", fake_run)
    assert login.systemd_user_environment() == {"WAYLAND_DISPLAY": "wayland-1"}
    assert seen == [["systemctl", "--user", "show-environment"]]


@pytest.mark.parametrize(
    "error",
    [
        FileNotFoundError("systemctl"),
        subprocess.CalledProcessError(1, "systemctl"),
        subprocess.TimeoutExpired("systemctl", 5),
    ],
)
def test_systemd_user_environment_is_empty_when_unreadable(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    def fake_run(*_: object, **__: object) -> None:
        raise error

    monkeypatch.setattr(login.subprocess, "run", fake_run)
    assert login.systemd_user_environment() == {}


def test_find_uses_the_process_environment_first(wayland_dir: Path) -> None:
    env = {"WAYLAND_DISPLAY": "wayland-9", "XDG_RUNTIME_DIR": str(wayland_dir)}
    assert login.find_wayland_socket(env, never) == wayland_dir / "wayland-9"


def test_find_accepts_an_absolute_display(wayland_dir: Path) -> None:
    env = {"WAYLAND_DISPLAY": str(wayland_dir / "wayland-9")}
    assert login.find_wayland_socket(env, never) == wayland_dir / "wayland-9"


def test_find_fills_missing_variables_from_the_user_manager(wayland_dir: Path) -> None:
    calls: list[int] = []

    def user_environment() -> dict[str, str]:
        calls.append(1)
        return {"WAYLAND_DISPLAY": "wayland-9", "XDG_RUNTIME_DIR": "/not/used"}

    env = {"XDG_RUNTIME_DIR": str(wayland_dir)}
    assert login.find_wayland_socket(env, user_environment) == wayland_dir / "wayland-9"
    assert calls == [1]
    env = {}
    user = {"WAYLAND_DISPLAY": "wayland-9", "XDG_RUNTIME_DIR": str(wayland_dir)}
    assert login.find_wayland_socket(env, lambda: user) == wayland_dir / "wayland-9"


def test_find_reads_the_process_environment_by_default(
    monkeypatch: pytest.MonkeyPatch, wayland_dir: Path
) -> None:
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-9")
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(wayland_dir))
    assert login.find_wayland_socket() == wayland_dir / "wayland-9"


def test_wayland_wins_over_x11(wayland_dir: Path) -> None:
    env = {"WAYLAND_DISPLAY": "wayland-9", "XDG_RUNTIME_DIR": str(wayland_dir), "DISPLAY": ":0"}
    assert login.find_wayland_socket(env, never) == wayland_dir / "wayland-9"


@pytest.mark.parametrize(
    "env",
    [{"DISPLAY": ":0"}, {"DISPLAY": ":0", "XDG_RUNTIME_DIR": "/run/user/1"}],
)
def test_x11_only_is_refused_with_the_reason(env: dict[str, str]) -> None:
    with pytest.raises(login.X11OnlyError, match="read every keystroke and the whole screen"):
        login.find_wayland_socket(env, dict)


def test_x11_only_in_the_user_manager_is_refused() -> None:
    with pytest.raises(login.X11OnlyError):
        login.find_wayland_socket({}, lambda: {"DISPLAY": ":1"})


def test_no_display_at_all() -> None:
    with pytest.raises(login.NoDisplayError) as info:
        login.find_wayland_socket({}, dict)
    assert str(info.value) == NO_SESSION
    assert isinstance(info.value, login.DisplayError)


def test_a_relative_display_needs_a_runtime_dir() -> None:
    with pytest.raises(login.NoDisplayError, match="cannot place WAYLAND_DISPLAY"):
        login.find_wayland_socket({"WAYLAND_DISPLAY": "wayland-1"}, dict)
    with pytest.raises(login.NoDisplayError, match="cannot place"):
        login.find_wayland_socket(
            {"WAYLAND_DISPLAY": "wayland-1", "XDG_RUNTIME_DIR": "relative/dir"}, dict
        )


def test_a_relative_display_may_not_climb_out_of_the_runtime_dir(wayland_dir: Path) -> None:
    env = {"WAYLAND_DISPLAY": "../run/wayland-9", "XDG_RUNTIME_DIR": str(wayland_dir)}
    with pytest.raises(login.NoDisplayError, match="cannot place"):
        login.find_wayland_socket(env, never)


def test_a_missing_socket_is_refused(short_dir: Path) -> None:
    env = {"WAYLAND_DISPLAY": "wayland-1", "XDG_RUNTIME_DIR": str(short_dir)}
    with pytest.raises(login.NoDisplayError) as info:
        login.find_wayland_socket(env, never)
    assert str(info.value).startswith(NO_SESSION)
    assert "is not a socket" in str(info.value)


def test_a_file_that_is_not_a_socket_is_refused(short_dir: Path) -> None:
    (short_dir / "wayland-1").write_text("", encoding="utf-8")
    env = {"WAYLAND_DISPLAY": "wayland-1", "XDG_RUNTIME_DIR": str(short_dir)}
    with pytest.raises(login.NoDisplayError, match="is not a socket"):
        login.find_wayland_socket(env, never)


# -- commands ------------------------------------------------------------------------------


def test_chromium_command_is_a_visible_contained_wayland_window(tmp_path: Path) -> None:
    command = login.chromium_command(tmp_path / "prof", "https://sitex.com/login", 156)
    assert command[0] == "chromium"
    assert command[-1] == "https://sitex.com/login"
    assert "--ozone-platform=wayland" in command
    assert f"--user-data-dir={tmp_path / 'prof'}" in command
    assert f"--proxy-server=http://{sandbox.PROXY_ADDRESS}" in command
    assert set(sandbox.chrome_flags(156)) <= set(command)
    for flag in command:
        assert not flag.startswith(
            ("--headless", "--remote-debugging", "--app", "--kiosk", "--start-fullscreen")
        ), flag
    assert command.count("https://sitex.com/login") == 1


def test_holder_command_starts_the_bridge_waits_then_replaces_itself_with_the_browser(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "a b'c"
    browser = ["chromium", "--flag=a b", "https://x.test/?a=1&b=2"]
    bridge = ["python", "-m", "valetkey.nsbridge", "--connect", "/run/it's here/p.sock"]
    command = login.holder_command(browser, bridge, profile)
    assert command[:2] == ["/usr/bin/sh", "-c"]
    lines = command[2].split("\n")
    assert shlex.split(lines[0]) == ["rm", "-f", f"{profile}/Singleton*"]
    assert lines[1].endswith(" &")
    assert shlex.split(lines[1][:-2]) == bridge
    wait = "\n".join(lines[2:-1])
    assert wait.startswith(f"{shlex.quote(login.sys.executable)} -I -c ")
    assert wait.endswith(" || exit 1")
    assert shlex.split(lines[-1]) == ["exec", *browser]


def test_holder_script_waits_for_the_forwarder_port() -> None:
    assert "3128" in login._WAIT_FOR_BRIDGE  # noqa: SLF001 - the port must match the sandbox's
    assert sandbox.PROXY_ADDRESS.endswith(":3128")


@pytest.mark.parametrize(
    ("value", "url"),
    [
        ("sitex.com", "https://sitex.com"),
        ("  sitex.com/login ", "https://sitex.com/login"),
        ("https://sitex.com/x?y=1", "https://sitex.com/x?y=1"),
        ("http://sitex.com:8080/", "http://sitex.com:8080/"),
    ],
)
def test_normalize_start_url(value: str, url: str) -> None:
    assert login.normalize_start_url(value) == url


@pytest.mark.parametrize("value", ["", "ftp://sitex.com/", "file:///etc/passwd", "https://", "a b"])
def test_normalize_start_url_rejects_other_things(value: str) -> None:
    with pytest.raises(ValueError, match=r"host|http"):
        login.normalize_start_url(value)


# -- the run, with a stand-in for the sandbox ----------------------------------------------


class Upstream:
    """A local server that answers every request on any port with a small page."""

    def __init__(self) -> None:
        self.requests: list[str] = []
        self.port = 0

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        with contextlib.suppress(OSError, asyncio.IncompleteReadError):
            head = (await reader.readuntil(b"\r\n\r\n")).decode("latin-1")
            self.requests.append(head)
            body = b"<html><head><title>login page</title></head><body>hello</body></html>"
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode()
                + body
            )
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

        return {
            "resolver": resolve,
            "connector": connect,
            "address_check": lambda _address: None,
        }


class FakeSandbox:
    """Stands in for ``sandbox.start``: records what it was given and runs a plain process."""

    def __init__(self, argv: list[str] | None = None, delay: float = 0) -> None:
        self.argv = argv or ["sleep", "60"]
        self.delay = delay
        self.boxes: list[sandbox.Sandbox] = []
        self.commands: list[list[str]] = []
        self.threads: list[str] = []
        self.processes: list[subprocess.Popen[bytes]] = []

    def __call__(self, box: sandbox.Sandbox, command: list[str]) -> subprocess.Popen[bytes]:
        time.sleep(self.delay)
        self.boxes.append(box)
        self.commands.append(command)
        process = subprocess.Popen(self.argv)  # noqa: S603  # fixed argument list
        self.processes.append(process)
        return process


@pytest.fixture
def roots(short_dir: Path) -> sites.Roots:
    runtime = short_dir / "run"
    runtime.mkdir(mode=0o700)
    return sites.Roots(short_dir / "cfg", short_dir / "state", runtime)


def login_dir(roots: sites.Roots, site: str = "sitex") -> Path:
    assert roots.runtime is not None
    return roots.runtime / "valetkey" / "logins" / site


async def eventually(check: Callable[[], bool], limit: float = 20) -> None:
    deadline = time.monotonic() + limit
    while not check():
        assert time.monotonic() < deadline, "timed out"
        await asyncio.sleep(0.05)


async def connect_through(proxy_socket: Path, target: str) -> None:
    reader, writer = await asyncio.open_unix_connection(proxy_socket)
    try:
        writer.write(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        await reader.readuntil(b"\r\n\r\n")
    finally:
        writer.close()
        await writer.wait_closed()


def start(
    roots: sites.Roots,
    fake: FakeSandbox,
    finish: Any,  # noqa: ANN401 - any of the callables finish accepts
    upstream: Upstream,
    **options: Any,  # noqa: ANN401 - forwarded to start_login
) -> Any:  # noqa: ANN401 - a coroutine
    settings: dict[str, Any] = {
        "wayland_socket": Path("/run/user/1000/wayland-0"),
        "chrome_major": 156,
        "launcher": fake,
        "proxy_options": upstream.proxy_options(),
        "restrict": lambda *_: None,  # never reach a real compositor from a unit test
    } | options
    return login.start_login("sitex", "sitex.com", roots, finish, **settings)


def test_closing_the_window_cleans_up_then_calls_finish_with_what_was_seen(
    roots: sites.Roots,
) -> None:
    calls: list[tuple[list[SeenHost], Path, bool, bool]] = []
    fake = FakeSandbox()

    def finish(seen: list[SeenHost], profile: Path) -> None:
        calls.append((seen, profile, login_dir(roots).exists(), handle.running))

    async def scenario() -> login.LoginResult:
        nonlocal handle
        async with Upstream().serving() as upstream:
            handle = await start(roots, fake, finish, upstream)
            assert handle.running
            proxy_socket = login_dir(roots) / "proxy.sock"
            await connect_through(proxy_socket, "sitex.com:443")
            await connect_through(proxy_socket, "login.okta.test:443")
            await connect_through(proxy_socket, "sitex.com:443")
            await connect_through(proxy_socket, "update.googleapis.com:443")
            fake.processes[0].terminate()  # the person closes the window
            return await handle.wait()

    handle: Any = None
    result = run(scenario())
    profile = sites.profile_path(roots, "sitex")
    seen = [
        SeenHost("sitex.com", 2),
        SeenHost("login.okta.test", 1),
        SeenHost("update.googleapis.com", 1),
    ]
    assert result.cancelled is False
    assert result.profile_dir == profile
    assert result.exit_code == -signal.SIGTERM
    # Background hosts are not noted as seen; the other three are.
    assert [h.host for h in result.seen_hosts] == [h.host for h in seen[:2]]
    assert result.seen_hosts == seen[:2]
    assert calls == [(seen[:2], profile, False, True)]
    assert not login_dir(roots).exists()
    assert not handle.running


def test_the_login_proxy_lets_a_host_reach_only_the_listed_private_range(
    roots: sites.Roots,
) -> None:
    results: list[tuple[str, str]] = []
    fake = FakeSandbox()

    def finish(_seen: list[SeenHost], _profile: Path) -> None:
        return None

    async def scenario() -> login.LoginResult:
        answers = {
            "in.corp.test": "10.20.1.5",
            "out.corp.test": "10.99.0.1",
            "meta.test": "169.254.169.254",
        }
        async with Upstream().serving() as upstream:

            async def resolve(host: str, _port: int) -> list[str]:
                return [answers[host]]

            options = upstream.proxy_options() | {"resolver": resolve}
            del options["address_check"]
            handle = await start(
                roots,
                fake,
                finish,
                upstream,
                proxy_options=options,
                private_networks=["10.20.1.0/24"],
            )
            proxy_socket = login_dir(roots) / "proxy.sock"
            for host in answers:
                reader, writer = await asyncio.open_unix_connection(proxy_socket)
                writer.write(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
                results.append((host, (await reader.readline()).split()[1].decode()))
                writer.close()
            fake.processes[0].terminate()
            return await handle.wait()

    result = run(scenario())
    assert results == [("in.corp.test", "200"), ("out.corp.test", "403"), ("meta.test", "403")]
    assert result.private_refused == ("out.corp.test", "meta.test")
    assert [h.host for h in result.seen_hosts] == ["in.corp.test"]


def test_a_login_with_no_private_refusals_reports_none(roots: sites.Roots) -> None:
    fake = FakeSandbox(["true"])

    async def scenario() -> login.LoginResult:
        async with Upstream().serving() as upstream:
            handle = await start(roots, fake, lambda *_: None, upstream)
            return await handle.wait()

    assert run(scenario()).private_refused == ()


def test_the_browser_is_started_in_a_private_sandbox_with_the_display(roots: sites.Roots) -> None:
    fake = FakeSandbox(["true"])
    modes: dict[str, int] = {}
    policies: list[str] = []

    def finish(_seen: list[SeenHost], _profile: Path) -> None:
        return None

    class Watching(FakeSandbox):
        def __call__(self, box: sandbox.Sandbox, command: list[str]) -> subprocess.Popen[bytes]:
            for name, path in {
                "profile": box.profile_dir,
                "login": box.proxy_socket.parent,
            }.items():
                modes[name] = stat.S_IMODE(path.stat().st_mode)
            assert box.policy_dir is not None
            policies.append((box.policy_dir / "managed" / "valetkey.json").read_text())
            return super().__call__(box, command)

    fake = Watching(["true"])

    async def scenario() -> None:
        async with Upstream().serving() as upstream:
            handle = await start(roots, fake, finish, upstream)
            await handle.wait()

    run(scenario())
    (box,) = fake.boxes
    assert modes == {"profile": 0o700, "login": 0o700}
    assert box.writable_dirs == ()  # a login window gets no folder to save downloads in
    assert box.wayland_socket == Path("/run/user/1000/wayland-0")
    assert box.profile_dir == sites.profile_path(roots, "sitex")
    assert box.proxy_socket == login_dir(roots) / "proxy.sock"
    assert box.runtime_dir == roots.runtime
    assert box.log_file == roots.runtime / "valetkey" / "logins" / "sitex.log"
    assert box.shared_dir is None
    assert json.loads(policies[0]) == sandbox.CHROME_POLICY
    (command,) = fake.commands
    assert command[:2] == ["/usr/bin/sh", "-c"]
    assert f"--user-data-dir={box.profile_dir}" in command[2]
    assert "https://sitex.com" in command[2]
    assert "--ozone-platform=wayland" in command[2]
    assert "--headless" not in command[2]
    assert "remote-debugging" not in command[2]


def test_cancel_ends_the_login_without_calling_finish(roots: sites.Roots) -> None:
    finished: list[object] = []
    fake = FakeSandbox()

    async def scenario() -> tuple[login.LoginResult, login.LoginResult]:
        async with Upstream().serving() as upstream:
            handle = await start(roots, fake, lambda *args: finished.append(args), upstream)
            await connect_through(login_dir(roots) / "proxy.sock", "sitex.com:443")
            first = await handle.cancel()
            assert not handle.running
            return first, await handle.cancel()

    first, second = run(scenario())
    assert first == second
    assert first.cancelled is True
    assert first.seen_hosts == [SeenHost("sitex.com", 1)]
    assert finished == []
    assert fake.processes[0].poll() is not None
    assert not login_dir(roots).exists()


def test_cancel_kills_a_sandbox_that_ignores_the_first_signal(
    roots: sites.Roots, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(login, "STOP_GRACE_SECONDS", 0.3)
    fake = FakeSandbox(["sh", "-c", "trap '' TERM; echo ready; while :; do sleep 0.1; done"])

    async def scenario() -> login.LoginResult:
        async with Upstream().serving() as upstream:
            handle = await start(roots, fake, lambda *_: None, upstream)
            await asyncio.sleep(0.5)
            return await handle.cancel()

    result = run(scenario())
    assert result.exit_code == -signal.SIGKILL
    assert result.cancelled


def test_finish_may_be_async_and_run_login_waits(roots: sites.Roots) -> None:
    finished: list[Path] = []

    async def finish(_seen: list[SeenHost], profile: Path) -> None:
        await asyncio.sleep(0)
        finished.append(profile)

    async def scenario() -> login.LoginResult:
        async with Upstream().serving() as upstream:
            return await login.run_login(
                "sitex",
                "https://sitex.com/",
                roots,
                finish,
                wayland_socket=Path("/x/wayland-0"),
                chrome_major=156,
                launcher=FakeSandbox(["true"]),
                proxy_options=upstream.proxy_options(),
            )

    result = run(scenario())
    assert finished == [result.profile_dir]
    assert result.exit_code == 0


def test_an_error_in_finish_is_raised_by_wait_after_cleanup(roots: sites.Roots) -> None:
    def finish(_seen: list[SeenHost], _profile: Path) -> None:
        msg = "classifier failed"
        raise RuntimeError(msg)

    async def scenario() -> None:
        async with Upstream().serving() as upstream:
            handle = await start(roots, FakeSandbox(["true"]), finish, upstream)
            with pytest.raises(RuntimeError, match="classifier failed"):
                await handle.wait()
            assert not login_dir(roots).exists()

    run(scenario())


def test_waiting_can_be_cancelled_without_ending_the_login(roots: sites.Roots) -> None:
    fake = FakeSandbox()

    async def scenario() -> None:
        async with Upstream().serving() as upstream:
            handle = await start(roots, fake, lambda *_: None, upstream)
            waiter = asyncio.ensure_future(handle.wait())
            await asyncio.sleep(0.1)
            waiter.cancel()
            with pytest.raises(asyncio.CancelledError):
                await waiter
            assert handle.running
            assert fake.processes[0].poll() is None
            await handle.cancel()

    run(scenario())


def test_a_sandbox_that_fails_to_start_leaves_nothing_behind(roots: sites.Roots) -> None:
    def broken(_box: sandbox.Sandbox, _command: list[str]) -> subprocess.Popen[bytes]:
        msg = "bwrap is not installed"
        raise FileNotFoundError(msg)

    async def scenario() -> None:
        async with Upstream().serving() as upstream:
            with pytest.raises(FileNotFoundError, match="bwrap"):
                await start(roots, FakeSandbox(), lambda *_: None, upstream, launcher=broken)

    run(scenario())
    assert not login_dir(roots).exists()


def test_abandoning_the_start_ends_a_sandbox_that_starts_late(roots: sites.Roots) -> None:
    fake = FakeSandbox(delay=0.5)

    async def scenario() -> None:
        async with Upstream().serving() as upstream:
            task = asyncio.ensure_future(start(roots, fake, lambda *_: None, upstream))
            await asyncio.sleep(0.2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await eventually(lambda: bool(fake.processes) and fake.processes[0].poll() is not None)

    run(scenario())
    assert not login_dir(roots).exists()


def test_the_display_and_version_are_found_when_not_given(
    roots: sites.Roots, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(login, "find_wayland_socket", lambda: Path("/run/user/1/wayland-3"))
    monkeypatch.setattr(sandbox, "installed_chrome_major", lambda: 150)
    fake = FakeSandbox(["true"])

    async def scenario() -> None:
        async with Upstream().serving() as upstream:
            handle = await login.start_login(
                "sitex",
                "sitex.com",
                roots,
                lambda *_: None,
                launcher=fake,
                proxy_options=upstream.proxy_options(),
            )
            await handle.wait()

    run(scenario())
    assert fake.boxes[0].wayland_socket == Path("/run/user/1/wayland-3")
    assert any("Chrome/150." in part for part in fake.commands[0])


def test_no_display_means_no_login(roots: sites.Roots, monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse() -> Path:
        raise login.NoDisplayError(NO_SESSION)

    monkeypatch.setattr(login, "find_wayland_socket", refuse)
    fake = FakeSandbox()

    async def scenario() -> None:
        with pytest.raises(login.NoDisplayError, match="no desktop session"):
            await login.start_login("sitex", "sitex.com", roots, lambda *_: None, launcher=fake)

    run(scenario())
    assert fake.boxes == []
    assert not login_dir(roots).exists()
    assert not sites.profile_path(roots, "sitex").exists()


def test_bad_arguments_fail_before_anything_is_created(roots: sites.Roots) -> None:
    async def scenario() -> None:
        with pytest.raises(ValueError, match="invalid site name"):
            await login.start_login("../x", "sitex.com", roots, lambda *_: None)
        with pytest.raises(ValueError, match="http"):
            await login.start_login("sitex", "ftp://sitex.com", roots, lambda *_: None)
        no_runtime = sites.Roots(roots.config, roots.state, None)
        with pytest.raises(sites.RuntimeDirUnavailableError):
            await login.start_login(
                "sitex",
                "sitex.com",
                no_runtime,
                lambda *_: None,
                wayland_socket=Path("/x/wayland-0"),
                chrome_major=1,
            )

    run(scenario())
    assert not sites.profile_path(roots, "sitex").exists()


# -- the restricted display ----------------------------------------------------------------


class Restriction:
    """Stands in for ``restrict_display``: makes a context that records how it was closed."""

    def __init__(self) -> None:
        self.calls: list[tuple[Path, Path, str]] = []
        self.context: wayland.SecurityContext | None = None
        self.watch = -1

    def __call__(self, compositor: Path, directory: Path, site: str) -> wayland.SecurityContext:
        self.calls.append((compositor, directory, site))
        path = directory / login.DISPLAY_NAME
        path.touch()
        self.watch, write_end = os.pipe()
        self.context = wayland.SecurityContext(path, write_end)
        return self.context

    def hung_up(self) -> bool:
        """Whether the descriptor the compositor watches has hung up."""
        poller = select.poll()
        poller.register(self.watch, select.POLLIN)
        return bool(poller.poll(0))

    def finish(self) -> None:
        os.close(self.watch)


def test_the_window_gets_the_restricted_display_until_the_login_ends(roots: sites.Roots) -> None:
    restriction = Restriction()
    fake = FakeSandbox(["true"])
    seen: dict[str, Any] = {}

    class Watching(FakeSandbox):
        def __call__(self, box: sandbox.Sandbox, command: list[str]) -> subprocess.Popen[bytes]:
            seen["socket"] = box.wayland_socket
            seen["quiet"] = not restriction.hung_up()
            seen["exists"] = box.wayland_socket is not None and box.wayland_socket.exists()
            return super().__call__(box, command)

    fake = Watching(["true"])

    async def scenario() -> None:
        async with Upstream().serving() as upstream:
            handle = await start(roots, fake, lambda *_: None, upstream, restrict=restriction)
            await handle.wait()

    try:
        run(scenario())
        compositor = Path("/run/user/1000/wayland-0")
        assert restriction.calls == [(compositor, login_dir(roots), "sitex")]
        assert seen["socket"] == login_dir(roots) / login.DISPLAY_NAME
        assert seen["socket"] != compositor
        assert seen["quiet"] is True  # the compositor keeps serving it while the window runs
        assert seen["exists"] is True
        assert restriction.hung_up()  # and is told to stop when the login is over
        assert not login_dir(roots).exists()
    finally:
        restriction.finish()


def test_cancelling_a_login_ends_the_restricted_display(roots: sites.Roots) -> None:
    restriction = Restriction()
    fake = FakeSandbox()

    async def scenario() -> None:
        async with Upstream().serving() as upstream:
            handle = await start(roots, fake, lambda *_: None, upstream, restrict=restriction)
            assert not restriction.hung_up()
            await handle.cancel()

    try:
        run(scenario())
        assert restriction.hung_up()
        assert not login_dir(roots).exists()
    finally:
        restriction.finish()


def test_a_login_that_fails_to_start_closes_its_restricted_display(roots: sites.Roots) -> None:
    restriction = Restriction()

    def broken(_box: sandbox.Sandbox, _command: list[str]) -> subprocess.Popen[bytes]:
        message = "bwrap is missing"
        raise OSError(message)

    async def scenario() -> None:
        async with Upstream().serving() as upstream:
            with pytest.raises(OSError, match="bwrap is missing"):
                await start(
                    roots,
                    FakeSandbox(),
                    lambda *_: None,
                    upstream,
                    restrict=restriction,
                    launcher=broken,
                )

    try:
        run(scenario())
        assert restriction.hung_up()
        assert not login_dir(roots).exists()
    finally:
        restriction.finish()


def test_without_a_restricted_display_the_window_gets_the_compositors(roots: sites.Roots) -> None:
    fake = FakeSandbox(["true"])

    async def scenario() -> None:
        async with Upstream().serving() as upstream:
            handle = await start(roots, fake, lambda *_: None, upstream)
            await handle.wait()

    run(scenario())
    assert fake.boxes[0].wayland_socket == Path("/run/user/1000/wayland-0")


def test_restrict_display_registers_the_site_as_the_instance(short_dir: Path) -> None:
    compositor = short_dir / "wayland-0"
    directory = short_dir / "login"
    directory.mkdir(mode=0o700)
    seen: dict[str, Any] = {}

    def script(peer: Peer) -> None:
        seen.update(accepting(peer))

    with Compositor(compositor, script):
        context = login.restrict_display(compositor, directory, "sitex")
        assert context is not None
        assert context.path == directory / "wayland-login"
        assert context.path.is_socket()
        context.close()
    names = [decode_string(r.payload, 0)[0] for r in seen["strings"]]
    assert names == ["valetkey", "valetkey-login", "sitex"]


def test_a_compositor_without_the_manager_is_warned_about_once_and_the_login_goes_on(
    short_dir: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(login, "_warned", set())
    directory = short_dir / "login"
    directory.mkdir(mode=0o700)
    for round_ in range(2):
        compositor = short_dir / f"wayland-{round_}"
        with (
            Compositor(compositor, lambda peer: peer.handshake({"wl_compositor": 6})),
            caplog.at_level(logging.WARNING, logger="valetkey.login"),
        ):
            assert login.restrict_display(compositor, directory, "sitex") is None
    warnings = [r.message for r in caplog.records if "no security-context support" in r.message]
    assert warnings == [login.UNRESTRICTED]  # one, for two logins
    assert list(directory.iterdir()) == []


def test_any_other_trouble_with_the_compositor_is_warned_about_each_time(
    short_dir: Path, caplog: pytest.LogCaptureFixture
) -> None:
    directory = short_dir / "login"
    directory.mkdir(mode=0o700)
    with caplog.at_level(logging.WARNING, logger="valetkey.login"):
        for _ in range(2):
            assert login.restrict_display(short_dir / "nothing-here", directory, "sitex") is None
    assert len([r for r in caplog.records if "could not restrict" in r.message]) == 2
    assert "cannot connect" in caplog.text


# -- integration: a real window in a private sway -----------------------------------------


_SKIP_REASON = unusable_reason("bwrap", "chromium", "sway", "swaymsg")
integration = pytest.mark.integration
needs_desktop = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")


@pytest.fixture
def sway(short_dir: Path) -> Iterator[Sway]:
    runtime = short_dir / "sway"
    runtime.mkdir(mode=0o700)
    desktop = Sway(runtime)
    try:
        desktop.start()
        yield desktop
    finally:
        desktop.stop()


async def chromium_windows(desktop: Sway) -> list[dict[str, Any]]:
    return [w for w in await desktop.windows() if w["app_id"] == "chromium"]


def leftover_sandboxes(profile: Path) -> list[str]:
    result = subprocess.run(  # noqa: S603  # fixed argument list
        ["pgrep", "-af", f"bwrap.*{profile}"],  # noqa: S607  # resolved from PATH
        capture_output=True,
        text=True,
        check=False,
    )
    return [line for line in result.stdout.splitlines() if "pgrep" not in line]


@integration
@needs_desktop
def test_a_login_window_opens_records_the_host_and_ends_when_closed(
    sway: Sway, roots: sites.Roots
) -> None:
    finished: list[tuple[list[SeenHost], Path]] = []

    async def scenario() -> None:
        async with Upstream().serving() as upstream:
            handle = await login.start_login(
                "sitex",
                "http://login.test/",
                roots,
                lambda seen, profile: finished.append((seen, profile)),
                wayland_socket=sway.display,
                proxy_options=upstream.proxy_options(),
            )
            windows: list[dict[str, Any]] = []
            deadline = time.monotonic() + 40
            while not windows or not upstream.requests:
                assert time.monotonic() < deadline, (windows, upstream.requests, sway_log(roots))
                windows = await chromium_windows(sway)
                await asyncio.sleep(0.2)
            assert upstream.requests[0].startswith("GET / HTTP/1.1\r\nHost: login.test\r\n")
            assert handle.running
            # The compositor knows the window as a sandboxed client of this site's login.
            (node,) = windows
            assert node["sandbox_engine"] == "valetkey"
            assert node["sandbox_app_id"] == "valetkey-login"
            assert node["sandbox_instance_id"] == "sitex"
            await asyncio.to_thread(assert_display_is_restricted, sway, login_dir(roots))
            await sway.msg("[app_id=chromium]", "kill")
            result = await asyncio.wait_for(handle.wait(), 30)
            assert result.cancelled is False
            assert not handle.running
            assert await chromium_windows(sway) == []

    run(scenario())
    ((seen, profile),) = finished
    assert profile == sites.profile_path(roots, "sitex")
    assert [h.host for h in seen] == ["login.test"]
    assert not login_dir(roots).exists()
    assert leftover_sandboxes(profile) == []
    # The profile Chrome wrote stays: it holds the login.
    assert any(profile.iterdir())


def assert_display_is_restricted(desktop: Sway, directory: Path) -> None:
    """Capture and virtual typing fail through the login's socket, and work through sway's."""
    restricted = directory / login.DISPLAY_NAME
    assert restricted.is_socket()

    def tool(argv: list[str], display: Path) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": os.environ["PATH"],
            "XDG_RUNTIME_DIR": str(desktop.runtime),
            "WAYLAND_DISPLAY": str(display),
        }
        return subprocess.run(  # noqa: S603  # fixed argument list
            argv, env=env, capture_output=True, text=True, check=False, timeout=30
        )

    shot = directory.parent / "shot.png"
    for argv in (["grim", str(shot)], ["wtype", "x"]):
        refused = tool(argv, restricted)
        assert refused.returncode != 0, argv
        assert "support" in refused.stderr, refused.stderr
    assert not shot.exists()
    # The same tools work on the compositor's own socket, so it is the socket that refuses.
    assert tool(["grim", str(shot)], desktop.display).returncode == 0
    shot.unlink()


def sway_log(roots: sites.Roots) -> str:
    assert roots.runtime is not None
    path = roots.runtime / "valetkey" / "logins" / "sitex.log"
    return path.read_text(errors="replace")[-3000:] if path.exists() else "(no log)"


@integration
@needs_desktop
def test_cancelling_a_login_closes_the_window_and_cleans_up(sway: Sway, roots: sites.Roots) -> None:
    finished: list[object] = []

    async def scenario() -> None:
        async with Upstream().serving() as upstream:
            handle = await login.start_login(
                "sitex",
                "http://login.test/",
                roots,
                lambda *args: finished.append(args),
                wayland_socket=sway.display,
                proxy_options=upstream.proxy_options(),
            )
            deadline = time.monotonic() + 40
            while not await chromium_windows(sway):
                assert time.monotonic() < deadline, sway_log(roots)
                await asyncio.sleep(0.2)
            result = await handle.cancel()
            assert result.cancelled
            assert not handle.running
            await asyncio.sleep(0.3)
            assert await chromium_windows(sway) == []

    run(scenario())
    assert finished == []
    assert not login_dir(roots).exists()
    assert leftover_sandboxes(sites.profile_path(roots, "sitex")) == []
