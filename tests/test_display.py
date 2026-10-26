# SPDX-License-Identifier: Apache-2.0
import asyncio
import contextlib
import socket
import stat
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

import valetkey
from valetkey import display, sites

if TYPE_CHECKING:
    from collections.abc import Awaitable


def run[T](scenario: Awaitable[T]) -> T:
    return asyncio.run(asyncio.wait_for(scenario, 30))


@pytest.fixture
def roots(short_dir: Path) -> sites.Roots:
    (short_dir / "r").mkdir(mode=0o700)
    return sites.Roots(short_dir / "c", short_dir / "s", short_dir / "r")


@pytest.fixture
def viewer(short_dir: Path) -> Path:
    directory = short_dir / "viewer"
    directory.mkdir()
    (directory / "vnc.html").write_text("<html>viewer</html>", encoding="utf-8")
    return directory


# -- pure pieces ---------------------------------------------------------------------------


def test_the_ssh_line_forwards_the_port_to_the_host() -> None:
    assert display.ssh_command(4242, "box.example") == "ssh -L 4242:localhost:4242 box.example"
    assert display.ssh_command(4242).startswith("ssh -L 4242:localhost:4242 ")


def test_the_ssh_line_names_a_host_even_when_the_machine_has_no_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(display.platform, "node", lambda: "")
    assert display.ssh_command(1) == "ssh -L 1:localhost:1 HOST"


def test_wayvnc_speaks_plain_rfb_on_a_unix_socket_and_never_a_websocket() -> None:
    command = display.wayvnc_command(Path("/run/x/vnc.sock"))
    assert command == ["wayvnc", "--output", "HEADLESS-1", "unix:/run/x/vnc.sock"]
    assert not {"-w", "--websocket"} & set(command)
    assert not any(part.startswith(("ws:", "ws-unix:", "tcp:")) for part in command)


def test_sway_runs_from_a_config_of_its_own() -> None:
    assert display.sway_command(Path("/run/x/sway.conf")) == [
        "sway",
        "--config",
        "/run/x/sway.conf",
    ]


def test_the_environment_of_the_display_has_only_what_it_needs(tmp_path: Path) -> None:
    env = display.display_environment(tmp_path)
    assert env["XDG_RUNTIME_DIR"] == env["HOME"] == str(tmp_path)
    assert env["WLR_BACKENDS"] == "headless"
    assert "WAYLAND_DISPLAY" not in env
    assert set(env) == {
        "PATH",
        "HOME",
        "XDG_RUNTIME_DIR",
        "WLR_BACKENDS",
        "WLR_LIBINPUT_NO_DEVICES",
        "WLR_RENDERER",
    }
    assert display.display_environment(tmp_path, "wayland-1")["WAYLAND_DISPLAY"] == "wayland-1"


def test_the_viewer_files_are_found_next_to_the_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = tmp_path / "valetkey"
    package.mkdir()
    monkeypatch.setattr(valetkey, "__file__", str(package / "__init__.py"))
    with pytest.raises(display.RemoteDisplayError, match=r"just novnc"):
        display.novnc_root()
    (package / "novnc").mkdir()
    (package / "novnc" / "vnc.html").write_text("x", encoding="utf-8")
    assert display.novnc_root() == package / "novnc"


def test_the_directory_of_a_display_is_private_and_starts_empty(roots: sites.Roots) -> None:
    first = display._prepare(roots, "sitex")  # noqa: SLF001
    (first / "stale").write_text("left by an earlier display", encoding="utf-8")
    again = display._prepare(roots, "sitex")  # noqa: SLF001
    assert again == first == sites.runtime_path(roots) / "displays" / "sitex"
    assert list(again.iterdir()) == []
    assert stat.S_IMODE(again.stat().st_mode) == 0o700
    assert stat.S_IMODE(again.parent.stat().st_mode) == 0o700
    with pytest.raises(ValueError, match="invalid site name"):
        display._prepare(roots, "../evil")  # noqa: SLF001


# -- child processes -----------------------------------------------------------------------


def process(tmp_path: Path, *argv: str) -> display._Process:
    return display._Process("test", argv, {"PATH": "/usr/bin:/bin"}, tmp_path / "test.log")  # noqa: SLF001


def test_a_process_runs_and_stops_on_sigterm(tmp_path: Path) -> None:
    async def scenario() -> None:
        child = process(tmp_path, "sleep", "30")
        await child.start()
        assert child.running()
        await child.stop()
        assert not child.running()
        assert child.exited is not None
        assert child.exited.result() == -15
        await child.stop()  # safe to repeat

    run(scenario())


def test_a_process_that_ignores_sigterm_is_killed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(display, "STOP_GRACE", 0.1)

    async def scenario() -> None:
        child = process(tmp_path, "sh", "-c", "trap '' TERM; echo ready; sleep 30")
        await child.start()
        for _ in range(100):
            if child.log_tail():
                break
            await asyncio.sleep(0.02)
        await child.stop()
        assert child.exited is not None
        assert child.exited.result() == -9

    run(scenario())


def test_a_process_that_cannot_start_is_a_display_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(display.shutil, "which", lambda _name: None)

    async def scenario() -> None:
        child = process(tmp_path, str(tmp_path / "no-such-program"))
        with pytest.raises(display.RemoteDisplayError, match="cannot start test"):
            await child.start()
        assert not child.running()

    run(scenario())


def test_a_process_without_setpriv_still_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(display.shutil, "which", lambda _name: None)

    async def scenario() -> None:
        child = process(tmp_path, "sleep", "30")
        await child.start()
        assert child.process is not None
        exe = await asyncio.to_thread(Path(f"/proc/{child.process.pid}/exe").resolve)
        assert exe.name == "sleep"
        await child.stop()

    run(scenario())


def test_a_process_is_wrapped_so_it_gets_sigterm_when_its_parent_thread_ends(
    tmp_path: Path,
) -> None:
    """With setpriv present, the program is run by ``setpriv --pdeathsig TERM``, which execs it."""

    async def scenario() -> list[bytes]:
        child = process(tmp_path, "sleep", "30")
        await child.start()
        assert child.process is not None
        path = Path(f"/proc/{child.process.pid}/cmdline")
        arguments: list[bytes] = []
        for _ in range(200):
            arguments = path.read_bytes().split(b"\0")  # noqa: ASYNC240 - a read of /proc
            if arguments[0] == b"sleep":
                break
            await asyncio.sleep(0.01)
        await child.stop()
        return arguments

    assert run(scenario())[:2] == [b"sleep", b"30"]
    assert display.shutil.which("setpriv") is not None


def test_log_tail_is_empty_without_a_log(tmp_path: Path) -> None:
    assert process(tmp_path, "true").log_tail() == ""


# -- starting a whole display, with the processes faked ------------------------------------


class FakeProcess:
    """Stands in for sway and wayvnc: makes the files each one provides."""

    instances: list[FakeProcess] = []  # noqa: RUF012 - reset by the fixture
    behaviour: dict[str, str] = {}  # noqa: RUF012 - set by each test

    def __init__(self, name: str, argv: list[str], env: dict[str, str], log: Path) -> None:
        self.name, self.argv, self.env, self.log = name, argv, env, log
        self.stopped = False
        self.started = False
        self._alive = False
        self._socket: socket.socket | None = None
        FakeProcess.instances.append(self)

    async def start(self) -> None:
        mode = self.behaviour.get(self.name, "ok")
        if mode == "cannot":
            message = f"cannot start {self.name}"
            raise display.RemoteDisplayError(message)
        self._alive = mode != "exits"
        if mode == "exits":
            self.log.write_text(f"{self.name} says: no GPU", encoding="utf-8")
        if mode != "ok":
            self.started = True
            return
        self.started = True
        if self.name == "sway":
            (self.log.parent / "wayland-1").write_text("", encoding="utf-8")
        else:
            self._socket = socket.socket(socket.AF_UNIX)
            self._socket.bind(self.argv[-1].removeprefix("unix:"))

    def running(self) -> bool:
        return self._alive

    def log_tail(self) -> str:
        return self.log.read_text(encoding="utf-8") if self.log.exists() else ""

    async def stop(self) -> None:
        self.stopped = True
        self._alive = False
        if self._socket is not None:
            self._socket.close()


@pytest.fixture
def fakes(monkeypatch: pytest.MonkeyPatch) -> type[FakeProcess]:
    FakeProcess.instances = []
    FakeProcess.behaviour = {}
    monkeypatch.setattr(display, "_Process", FakeProcess)
    monkeypatch.setattr(display.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(display, "_wayvnc_version_output", lambda _program: "wayvnc: v0.10.2\n")
    monkeypatch.setattr(display, "START_TIMEOUT", 0.3)
    return FakeProcess


def test_a_display_comes_up_with_a_link_that_works(
    roots: sites.Roots, viewer: Path, fakes: type[FakeProcess]
) -> None:
    async def scenario() -> None:
        shown = await display.start_display(roots, "sitex", novnc=viewer)
        directory = sites.runtime_path(roots) / "displays" / "sitex"
        assert shown.directory == directory
        assert shown.wayland_socket == directory / "wayland-1"
        assert shown.url == shown.gateway.url
        assert shown.port == shown.gateway.port > 0
        assert display.describe(shown) == {
            "url": shown.url,
            "port": shown.port,
            "ssh": display.ssh_command(shown.port),
        }
        config = await asyncio.to_thread((directory / "sway.conf").read_text, encoding="utf-8")
        assert config == "output HEADLESS-1 resolution 1280x800\n"
        sway, vnc = fakes.instances
        assert sway.argv == display.sway_command(directory / "sway.conf")
        assert sway.env["XDG_RUNTIME_DIR"] == str(directory)
        assert vnc.env["WAYLAND_DISPLAY"] == "wayland-1"
        assert vnc.argv == display.wayvnc_command(directory / "vnc.sock")
        await shown.close()
        assert all(p.stopped for p in fakes.instances)
        assert not await asyncio.to_thread(directory.exists)
        await shown.close()  # safe to repeat
        reader_error: OSError | None = None
        try:
            await asyncio.open_connection("127.0.0.1", shown.port)
        except OSError as error:
            reader_error = error
        assert reader_error is not None  # nothing listens any more

    run(scenario())


def test_a_display_needs_sway_and_wayvnc_and_the_viewer(
    roots: sites.Roots, viewer: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def scenario() -> None:
        monkeypatch.setattr(display.shutil, "which", lambda name: None if name == "wayvnc" else "x")
        with pytest.raises(display.RemoteDisplayError, match="needs wayvnc"):
            await display.start_display(roots, "sitex", novnc=viewer)
        monkeypatch.setattr(display.shutil, "which", lambda name: None if name == "sway" else "x")
        with pytest.raises(display.RemoteDisplayError, match="needs sway"):
            await display.start_display(roots, "sitex", novnc=viewer)
        monkeypatch.setattr(display.shutil, "which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr(display, "_wayvnc_version_output", lambda _program: "wayvnc: 0.8.0\n")
        with pytest.raises(display.RemoteDisplayError, match=r"wayvnc 0\.8 is too old"):
            await display.start_display(roots, "sitex", novnc=viewer)
        monkeypatch.setattr(valetkey, "__file__", str(tmp_path / "valetkey" / "__init__.py"))
        with pytest.raises(display.RemoteDisplayError, match="noVNC viewer is not installed"):
            await display.start_display(roots, "sitex")
        assert not await asyncio.to_thread((sites.runtime_path(roots) / "displays").exists)

    run(scenario())


@pytest.mark.parametrize(
    ("behaviour", "message"),
    [
        ({"sway": "exits"}, "sway exited before a display: sway says: no GPU"),
        ({"sway": "idle"}, "sway did not provide a display in 0.3 seconds"),
        ({"wayvnc": "exits"}, "wayvnc exited before its socket: wayvnc says: no GPU"),
        ({"wayvnc": "idle"}, "wayvnc did not provide its socket in 0.3 seconds"),
        ({"sway": "cannot"}, "cannot start sway"),
        ({"wayvnc": "cannot"}, "cannot start wayvnc"),
    ],
)
def test_a_display_that_does_not_come_up_leaves_nothing_behind(
    roots: sites.Roots,
    viewer: Path,
    fakes: type[FakeProcess],
    behaviour: dict[str, str],
    message: str,
) -> None:
    fakes.behaviour = behaviour

    async def scenario() -> None:
        with pytest.raises(display.RemoteDisplayError, match=message):
            await display.start_display(roots, "sitex", novnc=viewer)
        assert not await asyncio.to_thread(
            (sites.runtime_path(roots) / "displays" / "sitex").exists
        )
        assert all(p.stopped for p in fakes.instances if p.started)

    run(scenario())


def test_what_was_started_is_stopped_when_a_later_step_fails(
    roots: sites.Roots, viewer: Path, fakes: type[FakeProcess]
) -> None:
    fakes.behaviour = {"wayvnc": "exits"}

    async def scenario() -> None:
        with contextlib.suppress(display.RemoteDisplayError):
            await display.start_display(roots, "sitex", novnc=viewer)
        sway = fakes.instances[0]
        assert sway.name == "sway"
        assert sway.stopped

    run(scenario())


def _unused(*_args: Any) -> None:  # noqa: ANN401 - keeps the Any import for the fake's signature
    return None


@pytest.mark.parametrize(
    ("output", "problem"),
    [
        ("wayvnc: v0.10.2-bb83745 (makepkg)\nneatvnc: v1.0.3\n", None),
        ("wayvnc: 0.9.0\n", None),
        ("wayvnc: v1.0.0\n", None),
        ("wayvnc: v0.8.0\n", "wayvnc 0.8 is too old; a login from a browser needs 0.9 or newer"),
        ("", "cannot read the version of wayvnc"),
        ("no idea", "cannot read the version of wayvnc"),
    ],
)
def test_only_a_wayvnc_that_listens_on_a_unix_socket_is_accepted(
    output: str, problem: str | None
) -> None:
    assert display.wayvnc_problem(output) == problem


def test_the_wayvnc_version_comes_from_running_it(tmp_path: Path) -> None:
    script = tmp_path / "wayvnc"
    script.write_text("#!/bin/sh\necho 'wayvnc: v0.9.1'\n", encoding="utf-8")
    script.chmod(0o755)
    assert display.wayvnc_problem(display._wayvnc_version_output(str(script))) is None  # noqa: SLF001
    assert display._wayvnc_version_output(str(tmp_path / "missing")) == ""  # noqa: SLF001
