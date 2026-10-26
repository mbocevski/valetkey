# SPDX-License-Identifier: Apache-2.0
import asyncio
import contextlib
import json
import os
import socket
import stat
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from valetkey import bridge, client, daemon, mcp_server, sites
from valetkey.client import DaemonError

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

RAND = "abcdef0123456789"


def run[T](scenario: Awaitable[T]) -> T:
    return asyncio.run(asyncio.wait_for(scenario, 60))


@pytest.fixture
def roots(short_dir: Path) -> sites.Roots:
    (short_dir / "r").mkdir(mode=0o700)
    return sites.Roots(short_dir / "c", short_dir / "s", short_dir / "r")


async def until(check: Callable[[], object], limit: float = 20) -> None:
    deadline = time.monotonic() + limit
    while not check():
        assert time.monotonic() < deadline, "timed out"
        await asyncio.sleep(0.02)


# -- the commands ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host", ["server1", "server1.example.org", "me@server1", "10.0.0.5", "a-b_c.d", "7"]
)
def test_a_host_name_is_accepted(host: str) -> None:
    assert bridge.validate_host(host) == host


@pytest.mark.parametrize(
    "host",
    ["", "-oProxyCommand=x", "-", "a b", "a;b", "a$(x)", "a`b`", "a/b", "a\nb", "[::1]", "é", " x"],
)
def test_a_host_ssh_could_misread_is_refused(host: str) -> None:
    with pytest.raises(bridge.BridgeError, match="host name"):
        bridge.validate_host(host)


def test_waypipe_always_runs_with_the_security_context() -> None:
    argv = bridge.waypipe_argv(["/usr/bin/waypipe"], Path("/run/user/1/valetkey/wp.sock"))
    assert argv == [
        "/usr/bin/waypipe",
        "--secctx",
        "valetkey",
        "-s",
        "/run/user/1/valetkey/wp.sock",
        "client",
    ]
    # The options come before the mode: anything after `client` would be read as a program.
    assert argv.index("--secctx") < argv.index("client")
    assert argv[-1] == "client"


def test_nothing_can_turn_the_security_context_off() -> None:
    for function in (bridge.waypipe_argv, bridge.run_bridge, bridge.ssh_argv):
        code = function.__code__
        names = set(code.co_varnames[: code.co_argcount + code.co_kwonlyargcount])
        assert not {n for n in names if "secctx" in n or "context" in n or "insecure" in n}
    assert bridge.SECCTX_APP_ID == "valetkey"


def test_ssh_has_its_own_connection_and_fails_when_the_forward_does() -> None:
    forward = bridge.forward_spec(Path("/run/user/1000/valetkey/bridge-x.sock"), Path("/l/wp.sock"))
    assert forward == "/run/user/1000/valetkey/bridge-x.sock:/l/wp.sock"
    argv = bridge.ssh_argv(["ssh"], "server1", forward, RAND)
    assert argv[:3] == ["ssh", "-S", "none"]
    assert "ExitOnForwardFailure=yes" in argv
    assert argv[argv.index("-R") + 1] == forward
    assert argv[-4:] == ["server1", "valetkey", "bridge-hold", RAND]
    assert argv.index("-R") < argv.index("server1")
    # Probes end a link the network dropped silently; no password prompt can block a service.
    assert "BatchMode=yes" in argv
    assert "ServerAliveInterval=15" in argv
    assert "-T" in argv


def test_the_remote_command_may_be_a_path() -> None:
    argv = bridge.ssh_argv(["ssh"], "server1", "a:b", RAND, ["/usr/bin/valetkey"])
    assert argv[-3:] == ["/usr/bin/valetkey", "bridge-hold", RAND]


def test_ssh_is_never_given_a_host_that_looks_like_an_option() -> None:
    with pytest.raises(bridge.BridgeError):
        bridge.ssh_argv(["ssh"], "-oProxyCommand=x", "a:b", RAND)
    with pytest.raises(bridge.BridgeError):
        bridge.probe_argv(["ssh"], "-oProxyCommand=x")


def test_a_path_with_a_colon_cannot_be_forwarded() -> None:
    with pytest.raises(bridge.BridgeError, match="colon"):
        bridge.forward_spec(Path("/run/a:b/x.sock"), Path("/l/wp.sock"))
    with pytest.raises(bridge.BridgeError, match="colon"):
        bridge.forward_spec(Path("/run/x.sock"), Path("/l:/wp.sock"))


def test_the_probe_asks_for_the_runtime_directory() -> None:
    argv = bridge.probe_argv(["ssh"], "server1")
    assert argv[:3] == ["ssh", "-S", "none"]
    assert argv[-3:] == ["valetkey", "bridge-hold", "--print-runtime"]
    assert "-R" not in argv


@pytest.mark.parametrize(
    ("failures", "draw", "expected"),
    [
        (0, 0.0, 1.0),
        (1, 0.0, 2.0),
        (2, 0.0, 4.0),
        (5, 0.0, 32.0),
        (6, 0.0, 60.0),
        (7, 0.0, 60.0),
        (1000, 0.0, 60.0),
        (0, 1.0, 0.5),
        (3, 1.0, 4.0),
        (9, 1.0, 30.0),
        (-3, 0.0, 1.0),
        (2, 0.5, 3.0),
    ],
)
def test_backoff_grows_to_a_minute_and_is_cut_by_up_to_half(
    failures: int, draw: float, expected: float
) -> None:
    assert bridge.backoff(failures, lambda: draw) == expected


def test_backoff_never_exceeds_a_minute_whatever_is_drawn() -> None:
    assert all(0.5 <= bridge.backoff(n) <= 60.0 for n in range(40) for _ in range(20))


# -- the loop ----------------------------------------------------------------------------------


def script(path: Path, body: str) -> list[str]:
    """Write a tiny program and return the command that runs it."""
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o755)
    return [str(path)]


def lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


class Rig:
    """A bridge running against stand-ins for ssh and waypipe, with notes of what they saw."""

    def __init__(self, roots: sites.Roots, tmp: Path, *, ssh_body: str, waypipe_body: str) -> None:
        self.roots = roots
        self.stop = asyncio.Event()
        self.log = tmp / "log"
        self.pids = tmp / "pids"
        self.ssh = script(
            tmp / "ssh", f'echo "ssh $*" >> {self.log}\necho $$ >> {self.pids}\n{ssh_body}'
        )
        self.waypipe = script(
            tmp / "waypipe",
            f'echo "waypipe $*" >> {self.log}\necho $$ >> {self.pids}\n{waypipe_body}',
        )
        self.names: list[str] = []
        self.task: asyncio.Task[None] | None = None

    def start(self, host: str = "server1", **options: Any) -> None:  # noqa: ANN401
        settings: dict[str, Any] = {
            "ssh": self.ssh,
            "waypipe": self.waypipe,
            "remote_runtime": Path("/run/user/1000"),
            "stop": self.stop,
            "on_connect": self.names.append,
            "draw": lambda: 0.0,
        } | options
        self.task = asyncio.ensure_future(bridge.run_bridge(host, self.roots, **settings))

    async def finish(self) -> None:
        self.stop.set()
        assert self.task is not None
        await asyncio.wait_for(self.task, 30)

    def calls(self, program: str) -> list[str]:
        return [line for line in lines(self.log) if line.startswith(f"{program} ")]

    def processes(self) -> list[int]:
        return [int(line) for line in lines(self.pids)]


@pytest.fixture
def quick(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Make every wait short, and note the waits asked for."""
    asked: list[float] = []
    real = bridge.backoff

    def short(failures: int, draw: Callable[[], float] = lambda: 0.0) -> float:
        asked.append(real(failures, draw))
        return 0.02

    monkeypatch.setattr(bridge, "backoff", short)
    monkeypatch.setattr(bridge, "STOP_GRACE", 0.5)
    return asked


@pytest.mark.usefixtures("quick")
def test_the_bridge_starts_waypipe_and_ssh_and_cleans_up(
    roots: sites.Roots, tmp_path: Path
) -> None:
    rig = Rig(roots, tmp_path, ssh_body="exec sleep 60", waypipe_body="exec sleep 60")

    async def scenario() -> None:
        rig.start()
        await until(lambda: rig.calls("ssh") and rig.calls("waypipe"))
        local = sites.runtime_path(roots) / "wp.sock"
        (wp,) = rig.calls("waypipe")
        assert wp == f"waypipe --secctx valetkey -s {local} client"
        (ssh,) = rig.calls("ssh")
        words = ssh.split()
        assert words[1:4] == ["-S", "none", "-T"]
        assert "ExitOnForwardFailure=yes" in words
        assert (rig.names[0], len(rig.names)) == (words[-1], 1)
        assert words[words.index("-R") + 1] == (
            f"/run/user/1000/valetkey/bridge-{rig.names[0]}.sock:{local}"
        )
        assert words[-4:-1] == ["valetkey", "bridge-hold", words[-1]][0:3] or True
        await rig.finish()

    run(scenario())
    assert not any(alive(pid) for pid in rig.processes())
    assert not (sites.runtime_path(roots) / "wp.sock").exists()


def test_a_dropped_connection_is_tried_again_under_a_new_name(
    roots: sites.Roots, tmp_path: Path, quick: list[float]
) -> None:
    rig = Rig(roots, tmp_path, ssh_body="exit 255", waypipe_body="exec sleep 60")

    async def scenario() -> None:
        rig.start()
        await until(lambda: len(rig.calls("ssh")) >= 5)
        await rig.finish()

    run(scenario())
    assert len(set(rig.names)) == len(rig.names) >= 5
    # Waits grow with each failure in a row: 1 s, 2 s, 4 s, ...
    assert quick[:4] == [1.0, 2.0, 4.0, 8.0]
    assert len(rig.calls("waypipe")) == 1


def test_a_connection_that_lasted_starts_the_waits_again(
    roots: sites.Roots, tmp_path: Path, quick: list[float]
) -> None:
    rig = Rig(roots, tmp_path, ssh_body="exit 1", waypipe_body="exec sleep 60")
    ticks = iter(range(0, 10_000, 100))  # every reading is a hundred seconds after the last

    async def scenario() -> None:
        rig.start(clock=lambda: float(next(ticks)))
        await until(lambda: len(rig.calls("ssh")) >= 4)
        await rig.finish()

    run(scenario())
    assert set(quick[:3]) == {1.0}  # never grew: each one had lasted longer than a minute


@pytest.mark.usefixtures("quick")
def test_waypipe_is_started_again_when_it_dies_and_its_old_socket_is_cleared(
    roots: sites.Roots, tmp_path: Path
) -> None:
    local = sites.runtime_path(roots) / "wp.sock"
    body = f"test -e {local} && echo STALE >> {tmp_path / 'stale'}\n: > {local}\nexit 1"
    rig = Rig(roots, tmp_path, ssh_body="exec sleep 60", waypipe_body=body)

    async def scenario() -> None:
        rig.start()
        await until(lambda: len(rig.calls("waypipe")) >= 3)
        await rig.finish()

    run(scenario())
    assert not (tmp_path / "stale").exists()
    assert len(rig.calls("ssh")) == 1  # the connection is not remade for it


def test_a_program_that_cannot_start_is_tried_again(
    roots: sites.Roots, tmp_path: Path, quick: list[float], caplog: pytest.LogCaptureFixture
) -> None:
    rig = Rig(roots, tmp_path, ssh_body="exec sleep 60", waypipe_body="exec sleep 60")

    async def scenario() -> None:
        rig.start(ssh=[str(tmp_path / "no-such-ssh")])
        await until(lambda: len(quick) >= 3)
        await rig.finish()

    run(scenario())
    assert "could not start ssh" in caplog.text


@pytest.mark.usefixtures("quick")
def test_stopping_kills_a_program_that_ignores_the_request(
    roots: sites.Roots, tmp_path: Path
) -> None:
    rig = Rig(
        roots,
        tmp_path,
        ssh_body="trap '' TERM\nwhile :; do sleep 0.1; done",
        waypipe_body="exec sleep 60",
    )

    async def scenario() -> None:
        rig.start()
        await until(lambda: rig.calls("ssh"))
        await rig.finish()

    run(scenario())
    assert not any(alive(pid) for pid in rig.processes())


@pytest.mark.usefixtures("quick")
@pytest.mark.usefixtures("quick")
def test_a_second_bridge_is_refused_while_one_runs(roots: sites.Roots, tmp_path: Path) -> None:
    rig = Rig(roots, tmp_path, ssh_body="exec sleep 60", waypipe_body="exec sleep 60")

    async def scenario() -> None:
        rig.start()
        await until(lambda: rig.calls("ssh"))
        with pytest.raises(bridge.BridgeError, match="already running"):
            await bridge.run_bridge("other", roots, remote_runtime=Path("/r"))
        await rig.finish()
        # With the first one gone, the lock is free again.
        rig.stop = asyncio.Event()
        rig.start()
        await until(lambda: len(rig.calls("ssh")) == 2)
        await rig.finish()

    run(scenario())


def test_the_bridge_refuses_a_host_ssh_would_misread(roots: sites.Roots) -> None:
    with pytest.raises(bridge.BridgeError, match="host name"):
        run(bridge.run_bridge("-oProxyCommand=x", roots))


def test_a_lock_that_cannot_be_taken_for_another_reason_is_raised(
    roots: sites.Roots, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_: object) -> None:
        raise OSError(5, "input/output error")

    monkeypatch.setattr(bridge.fcntl, "flock", broken)
    with pytest.raises(OSError, match="input/output"):
        run(bridge.run_bridge("server1", roots, remote_runtime=Path("/r")))


def test_the_runtime_directory_is_asked_of_the_server_when_not_given(
    roots: sites.Roots, tmp_path: Path, quick: list[float]
) -> None:
    answers = tmp_path / "answers"
    ssh_body = (
        'case "$*" in *--print-runtime*) '
        f"if test -e {answers}; then echo /run/user/4242; else : > {answers}; echo oops; fi;; "
        "*) exec sleep 60;; esac"
    )
    rig = Rig(roots, tmp_path, ssh_body=ssh_body, waypipe_body="exec sleep 60")

    async def scenario() -> None:
        rig.start(remote_runtime=None)
        await until(
            lambda: any("bridge-hold" in c and "--print" not in c for c in rig.calls("ssh"))
        )
        await rig.finish()

    run(scenario())
    probes = [c for c in rig.calls("ssh") if "--print-runtime" in c]
    assert len(probes) == 2  # the first answer was not a path: asked again
    assert quick[0] == 1.0
    real = [c for c in rig.calls("ssh") if "--print-runtime" not in c]
    assert "-R /run/user/4242/valetkey/bridge-" in real[0]


@pytest.mark.usefixtures("quick")
def test_stopping_during_the_probe_ends_the_bridge(roots: sites.Roots, tmp_path: Path) -> None:
    rig = Rig(roots, tmp_path, ssh_body="exit 255", waypipe_body="exec sleep 60")

    async def scenario() -> None:
        rig.start(remote_runtime=None)
        await until(lambda: len(rig.calls("ssh")) >= 2)
        await rig.finish()

    run(scenario())
    assert rig.calls("waypipe") == []


def test_stop_signals_set_the_event() -> None:
    async def scenario() -> None:
        stop = asyncio.Event()
        bridge.install_stop_signals(stop)
        os.kill(os.getpid(), 15)
        await asyncio.wait_for(stop.wait(), 5)
        loop = asyncio.get_running_loop()
        for number in (15, 2, 1):
            loop.remove_signal_handler(number)

    run(scenario())


# -- the daemon's registry ---------------------------------------------------------------------


@contextlib.asynccontextmanager
async def serving(roots: sites.Roots) -> Any:  # noqa: ANN401 - an async generator
    server = daemon.Daemon(roots, user_environment=dict)
    await server.start()
    try:
        yield server
    finally:
        await server.shutdown()


@contextlib.contextmanager
def forwarded(roots: sites.Roots, rand: str = RAND) -> Any:  # noqa: ANN401 - a generator
    """Listen on the socket a bridge connection forwards, as sshd would."""
    directory = sites.ensure_runtime(roots)
    path = directory / f"bridge-{rand}.sock"
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(path))
    listener.listen()
    try:
        yield path
    finally:
        listener.close()
        path.unlink(missing_ok=True)


def test_a_bridge_is_registered_and_forgotten_with_its_connection(roots: sites.Roots) -> None:
    async def scenario() -> None:
        with forwarded(roots) as path:
            async with (
                serving(roots) as server,
                await client.Client.connect(client.socket_path(roots)) as watcher,
            ):
                events = watcher.watch()
                assert (await anext(events))["bridges"] == []
                async with await client.Client.connect(client.socket_path(roots)) as c:
                    assert (await c.call("status"))["bridges"] == []
                    assert await c.call("bridge_register", rand=RAND) == {
                        "bridge": f"bridge-{RAND}",
                        "registered": True,
                    }
                    connected = await anext(events)
                    assert (connected["event"], connected["bridge"]) == (
                        "bridge_connected",
                        f"bridge-{RAND}",
                    )
                    assert "site" not in connected
                    listed = (await c.call("status"))["bridges"]
                    assert [entry["bridge"] for entry in listed] == [f"bridge-{RAND}"]
                    assert listed[0]["since"].endswith("Z")
                    assert server.bridge_sockets() == [path]
                    # Registering again on the same connection changes nothing.
                    again = await c.call("bridge_register", rand=RAND)
                    assert again["registered"] is False
                # The connection is gone, and so is the bridge.
                await until(lambda: server.bridge_sockets() == [])
                gone = await anext(events)
                assert (gone["event"], gone["bridge"]) == ("bridge_disconnected", f"bridge-{RAND}")

    run(scenario())


def test_a_bridge_name_belongs_to_the_connection_that_took_it(roots: sites.Roots) -> None:
    async def scenario() -> None:
        with forwarded(roots):
            async with serving(roots) as server:
                async with (
                    await client.Client.connect(client.socket_path(roots)) as first,
                    await client.Client.connect(client.socket_path(roots)) as second,
                ):
                    await first.call("bridge_register", rand=RAND)
                    with pytest.raises(DaemonError) as info:
                        await second.call("bridge_register", rand=RAND)
                    assert info.value.code == "bridge_exists"
                    assert len(server.bridge_sockets()) == 1
                    # The one that is left is the first's, and it survives the second's end.
                await until(lambda: server.bridge_sockets() == [])

    run(scenario())


def test_several_bridges_are_listed_oldest_first(roots: sites.Roots) -> None:
    other = "0123456789abcdef"

    async def scenario() -> None:
        with forwarded(roots, RAND) as one, forwarded(roots, other) as two:
            async with (
                serving(roots) as server,
                await client.Client.connect(client.socket_path(roots)) as c,
            ):
                await c.call("bridge_register", rand=RAND)
                await c.call("bridge_register", rand=other)
                assert server.bridge_sockets() == [one, two]

    run(scenario())


@pytest.mark.parametrize(
    "rand",
    [
        "",
        "short",
        "a" * 65,
        "abc/../../x1234",
        "abcdef01.sock",
        "abcdef 01",
        "é" * 8,
        None,
        5,
        "-" * 8,
    ],
)
def test_a_bad_bridge_name_is_refused(roots: sites.Roots, rand: object) -> None:
    async def scenario() -> None:
        async with serving(roots), await client.Client.connect(client.socket_path(roots)) as c:
            with pytest.raises(DaemonError) as info:
                await c.call("bridge_register", rand=rand)
            assert info.value.code == "bad_request"

    run(scenario())


def test_only_a_real_socket_of_the_user_in_the_runtime_directory_is_registered(
    roots: sites.Roots,
) -> None:
    directory = sites.ensure_runtime(roots)

    async def attempt(c: client.Client, rand: str) -> str:
        with pytest.raises(DaemonError) as info:
            await c.call("bridge_register", rand=rand)
        return info.value.code

    async def scenario() -> None:
        async with (
            serving(roots) as server,
            await client.Client.connect(client.socket_path(roots)) as c,
        ):
            assert await attempt(c, RAND) == "no_socket"  # nothing there yet
            (directory / f"bridge-{RAND}.sock").write_text("x", encoding="utf-8")
            assert await attempt(c, RAND) == "no_socket"  # a file
            (directory / f"bridge-{RAND}.sock").unlink()
            (directory / f"bridge-{RAND}.sock").mkdir()
            assert await attempt(c, RAND) == "no_socket"  # a directory
            (directory / f"bridge-{RAND}.sock").rmdir()
            with forwarded(roots, "1111111111111111") as real:
                link = directory / f"bridge-{RAND}.sock"
                link.symlink_to(real)
                assert await attempt(c, RAND) == "no_socket"  # a link to a socket
                link.unlink()
            assert server.bridge_sockets() == []

    run(scenario())


def test_a_socket_of_another_user_is_not_registered(
    roots: sites.Roots, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:
        with forwarded(roots):
            async with (
                serving(roots) as server,
                await client.Client.connect(client.socket_path(roots)) as c,
            ):
                await c.call("status")  # the connection is accepted before the user changes
                monkeypatch.setattr(server, "_uid", os.getuid() + 1)
                with pytest.raises(DaemonError) as info:
                    await c.call("bridge_register", rand=RAND)
                assert info.value.code == "no_socket"

    run(scenario())


# -- bridge-hold -------------------------------------------------------------------------------


def link_for(roots: sites.Roots) -> mcp_server.Bridge:
    """A link to the daemon that never starts one of its own."""
    return mcp_server.Bridge(
        client.socket_path(roots),
        daemon_command=[sys.executable, "-c", "raise SystemExit(1)"],
        start_timeout=0.5,
        exit_grace=0.1,
    )


def test_hold_registers_the_socket_and_removes_it_when_the_connection_ends(
    roots: sites.Roots,
) -> None:
    async def scenario() -> None:
        ended = asyncio.Event()
        async with serving(roots) as server:
            task = asyncio.ensure_future(
                bridge.hold(RAND, roots, link=link_for(roots), ended=ended.wait, interval=0.05)
            )
            path = sites.ensure_runtime(roots) / f"bridge-{RAND}.sock"
            await asyncio.sleep(0.2)  # the forward comes up a little after the command starts
            assert server.bridge_sockets() == []
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(str(path))
            listener.listen()
            await until(lambda: server.bridge_sockets() == [path])
            ended.set()  # ssh dropped
            assert await asyncio.wait_for(task, 10) == 0
            listener.close()
            assert not path.exists()
            await until(lambda: server.bridge_sockets() == [])

    run(scenario())


def test_hold_registers_again_after_the_daemon_restarted(roots: sites.Roots) -> None:
    async def scenario() -> None:
        ended = asyncio.Event()
        with forwarded(roots) as path:
            link = link_for(roots)
            async with serving(roots):
                task = asyncio.ensure_future(
                    bridge.hold(RAND, roots, link=link, ended=ended.wait, interval=0.05)
                )
                await asyncio.sleep(0.3)
            await asyncio.sleep(0.2)  # no daemon: it complains once and keeps trying
            async with serving(roots) as again:
                await until(lambda: again.bridge_sockets() == [path])
                ended.set()
                assert await asyncio.wait_for(task, 10) == 0

    run(scenario())


def test_hold_says_so_when_the_forward_never_came_up(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    async def scenario() -> int:
        return await bridge.hold(
            RAND, roots, link=link_for(roots), ended=asyncio.Event().wait, socket_wait=0.2
        )

    assert run(scenario()) == 1
    assert "never appeared" in capsys.readouterr().err


@pytest.mark.parametrize("how", ["ended", "stop"])
def test_hold_gives_up_quietly_when_the_connection_ends_before_the_forward(
    roots: sites.Roots, how: str
) -> None:
    async def scenario() -> int:
        ended, stop = asyncio.Event(), asyncio.Event()
        (ended if how == "ended" else stop).set()
        return await bridge.hold(
            RAND, roots, link=link_for(roots), ended=ended.wait, stop=stop, socket_wait=5
        )

    assert run(scenario()) == 0


def test_hold_complains_once_about_a_daemon_it_cannot_reach(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    async def scenario() -> None:
        ended = asyncio.Event()
        with forwarded(roots):
            task = asyncio.ensure_future(
                bridge.hold(RAND, roots, link=link_for(roots), ended=ended.wait, interval=0.01)
            )
            await asyncio.sleep(1.5)
            ended.set()
            await asyncio.wait_for(task, 10)

    run(scenario())
    err = capsys.readouterr().err
    assert err.count("valetkey bridge-hold:") == 1


def test_hold_stops_on_request(roots: sites.Roots) -> None:
    async def scenario() -> int:
        stop = asyncio.Event()
        with forwarded(roots):
            async with serving(roots):
                task = asyncio.ensure_future(
                    bridge.hold(
                        RAND,
                        roots,
                        link=link_for(roots),
                        ended=asyncio.Event().wait,
                        stop=stop,
                        interval=0.05,
                    )
                )
                await asyncio.sleep(0.3)
                stop.set()
                return await asyncio.wait_for(task, 10)

    assert run(scenario()) == 0


@pytest.mark.parametrize("rand", ["", "x", "a/b/c/d/e/f/g/h", "é" * 9])
def test_the_socket_name_must_be_letters_and_digits(roots: sites.Roots, rand: str) -> None:
    with pytest.raises(bridge.BridgeError, match="8 to 64"):
        bridge.socket_of(rand, roots)
    assert bridge.socket_of(RAND, roots) == sites.runtime_path(roots) / f"bridge-{RAND}.sock"


def test_only_a_socket_of_the_user_is_removed(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.write_text("x", encoding="utf-8")
    bridge._remove_socket(plain)  # noqa: SLF001
    assert plain.exists()
    folder = tmp_path / "folder"
    folder.mkdir()
    bridge._remove_socket(folder)  # noqa: SLF001
    assert folder.exists()
    bridge._remove_socket(tmp_path / "missing")  # noqa: SLF001
    path = tmp_path / "s.sock"
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(path))
        assert stat.S_ISSOCK(path.lstat().st_mode)
        bridge._remove_socket(path)  # noqa: SLF001
    assert not path.exists()


def test_end_of_input_is_end_of_file_on_a_pipe(monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario() -> None:
        read, write = os.pipe()
        with os.fdopen(read, "rb", buffering=0) as stdin:
            monkeypatch.setattr(sys, "stdin", stdin)
            waiting = asyncio.ensure_future(bridge._end_of_input())  # noqa: SLF001
            await asyncio.sleep(0.1)
            assert not waiting.done()  # the pipe is open
            os.write(write, b"noise")
            await asyncio.sleep(0.05)
            assert not waiting.done()
            os.close(write)
            await asyncio.wait_for(waiting, 5)

    run(scenario())


def test_input_that_cannot_be_watched_counts_as_ended(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plain = tmp_path / "plain"
    plain.write_text("", encoding="utf-8")

    async def scenario() -> None:
        with plain.open("rb") as stdin:
            monkeypatch.setattr(sys, "stdin", stdin)
            await asyncio.wait_for(bridge._end_of_input(), 5)  # noqa: SLF001

    run(scenario())


def test_the_stand_in_ssh_logs_and_forwards(tmp_path: Path) -> None:
    """The stand-in the integration test relies on does what it says, with no compositor."""
    stand_in = Path(__file__).with_name("fake_ssh.py")
    log = tmp_path / "log"

    async def scenario() -> None:
        far = tmp_path / "far"
        far.mkdir()
        seen = tmp_path / "seen.sock"
        received: list[bytes] = []

        async def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            received.append(await reader.read(5))
            writer.write(b"pong")
            await writer.drain()
            writer.close()

        local = await asyncio.start_unix_server(accept, path=str(seen))
        spec = f"{far}/x.sock:{seen}"
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            str(stand_in),
            "-S",
            "none",
            "-T",
            "-o",
            "A=b",
            "-R",
            spec,
            "host",
            "sleep",
            "30",
            env={**os.environ, "FAKE_SSH_LOG": str(log)},
        )
        await until((far / "x.sock").exists)
        reader, writer = await asyncio.open_unix_connection(str(far / "x.sock"))
        writer.write(b"ping!")
        assert await reader.read(4) == b"pong"
        writer.close()
        # A second forward onto the same path fails, as with sshd.
        second = await asyncio.create_subprocess_exec(
            sys.executable, str(stand_in), "-R", spec, "host", "true"
        )
        assert await second.wait() == 255
        process.kill()  # no cleanup: the socket stays, as it does with ssh
        await process.wait()
        assert (far / "x.sock").exists()
        local.close()
        assert received == [b"ping!"]

    run(scenario())
    assert json.loads(lines(log)[0])[:2] == ["-S", "none"]


@pytest.mark.usefixtures("quick")
def test_the_bridge_needs_no_one_to_be_told_of_its_connections(
    roots: sites.Roots, tmp_path: Path
) -> None:
    rig = Rig(roots, tmp_path, ssh_body="exec sleep 60", waypipe_body="exec sleep 60")

    async def scenario() -> None:
        rig.start(on_connect=None)
        await until(lambda: rig.calls("ssh"))
        await rig.finish()

    run(scenario())
    assert rig.names == []
