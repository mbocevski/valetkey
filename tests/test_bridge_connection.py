# SPDX-License-Identifier: Apache-2.0
"""The bridge stays connected: the remote ``bridge-hold`` must not see its input end at once.

``ssh -T`` hands its own standard input to the remote command. ``valetkey bridge-hold`` takes the
end of that input for the link dropping, so a bridge whose ssh reads ``/dev/null`` was dropped
the moment it connected, and started over in a loop. The stand-in ``tests/fake_ssh.py`` passes
its input on the same way, and one test here runs a real ``ssh`` against a private ``sshd`` on
the loopback, with every key, configuration and known-hosts file under the test's temporary
directory. Nothing under ``~/.ssh`` is read or written, and no agent is used.
"""

import asyncio
import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from valetkey import bridge, daemon, sites

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

FAKE_SSH = Path(__file__).with_name("fake_ssh.py")
HOLD_SECONDS = 10
"""How long the bridge must stay listed on the server."""


def run[T](scenario: Any, seconds: float = 120) -> T:  # noqa: ANN401 - any awaitable
    return asyncio.run(asyncio.wait_for(scenario, seconds))


async def until(check: Callable[[], object], limit: float = 30) -> None:
    deadline = time.monotonic() + limit
    while not check():
        assert time.monotonic() < deadline, "timed out"
        await asyncio.sleep(0.05)


# -- what the bridge gives its programs as input ---------------------------------------------


def test_the_bridge_gives_its_programs_an_input_that_stays_open() -> None:
    async def scenario() -> None:
        run_state = bridge._Run(  # noqa: SLF001
            asyncio.Event(), dict(os.environ), time.monotonic, lambda: 0.0, set()
        )
        # A program that reads its input to the end and then says so by exiting with 7.
        reader = [sys.executable, "-c", "import sys; sys.stdin.buffer.read(); sys.exit(7)"]
        process = await bridge._spawn(run_state, reader)  # noqa: SLF001
        await asyncio.sleep(0.5)
        assert process.returncode is None  # /dev/null would have ended it by now
        assert process.stdin is not None
        process.stdin.close()
        assert await asyncio.wait_for(process.wait(), 10) == 7

    run(scenario())


def test_the_stand_in_ssh_ends_the_commands_input_when_its_own_ends() -> None:
    command = [sys.executable, str(FAKE_SSH), "-T", "host", "cat >/dev/null; exit 3"]
    ended = subprocess.run(  # noqa: S603  # the test's own stand-in
        command, stdin=subprocess.DEVNULL, capture_output=True, timeout=30, check=False
    )
    assert ended.returncode == 3  # /dev/null reached the command at once
    with subprocess.Popen(  # noqa: S603
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as held:
        time.sleep(1)
        assert held.poll() is None  # an open input keeps the command waiting
        assert held.stdin is not None
        held.stdin.close()
        assert held.wait(timeout=30) == 3


# -- a bridge held through ssh ---------------------------------------------------------------


async def hold_a_bridge(
    ssh: list[str], ssh_env: dict[str, str], laptop: sites.Roots, server: sites.Roots, tmp: Path
) -> None:
    """Run a bridge through ``ssh`` to a daemon on ``server`` and see that it stays registered."""
    sites.ensure_runtime(server)
    waypipe = tmp / "waypipe"
    waypipe.write_text("#!/bin/sh\nexec sleep 300\n", encoding="utf-8")
    waypipe.chmod(0o755)
    names: list[str] = []
    stop = asyncio.Event()
    async with serving(server) as registry:
        task = asyncio.ensure_future(
            bridge.run_bridge(
                "server1",
                laptop,
                ssh=ssh,
                waypipe=[str(waypipe)],
                valetkey=[sys.executable, "-m", "valetkey"],
                remote_runtime=server.runtime,
                environ=ssh_env,
                stop=stop,
                on_connect=names.append,
                draw=lambda: 0.0,
            )
        )
        try:
            await until(registry.logins.bridge_sockets, 60)
            (socket_path,) = registry.logins.bridge_sockets()
            deadline = time.monotonic() + HOLD_SECONDS
            while time.monotonic() < deadline:
                # Still the same bridge, never dropped and made again.
                assert registry.logins.bridge_sockets() == [socket_path]
                assert len(names) == 1
                assert not task.done()
                await asyncio.sleep(0.25)
        finally:
            stop.set()
            await asyncio.wait_for(task, 30)
        await until(
            lambda: registry.logins.bridge_sockets() == []
        )  # and it is forgotten when it ends


@contextlib.asynccontextmanager
async def serving(roots: sites.Roots) -> Any:  # noqa: ANN401 - an async generator
    server = daemon.Daemon(roots, user_environment=dict)
    await server.start()
    try:
        yield server
    finally:
        await server.shutdown()


def test_a_bridge_stays_listed_through_the_stand_in_ssh(short_dir: Path) -> None:
    (short_dir / "lap").mkdir(mode=0o700)
    (short_dir / "srv").mkdir(mode=0o700)
    laptop = sites.Roots(short_dir / "lc", short_dir / "ls", short_dir / "lap")
    server = sites.Roots(short_dir / "sc", short_dir / "ss", short_dir / "srv")
    base = {"PATH": os.environ["PATH"], "HOME": str(short_dir)}
    remote_env = base | {"XDG_RUNTIME_DIR": str(server.runtime)}
    ssh_env = base | {
        "XDG_RUNTIME_DIR": str(laptop.runtime),
        "FAKE_SSH_REMOTE_ENV": json.dumps(remote_env),
    }
    run(hold_a_bridge([sys.executable, str(FAKE_SSH)], ssh_env, laptop, server, short_dir))


# -- a real ssh, against a private sshd --------------------------------------------------------

_SKIP = next(
    (
        f"{name} is not installed"
        for name in ("sshd", "ssh", "ssh-keygen")
        if not shutil.which(name)
    ),
    None,
)
needs_sshd = pytest.mark.skipif(_SKIP is not None, reason=_SKIP or "")


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.fixture
def private_sshd(short_dir: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """A running ``sshd`` on a loopback port, and the ssh configuration that reaches it.

    Its host key, the one authorized key, its configuration, the client's key and known hosts are
    all under ``short_dir``. Yields the path of the ssh configuration file.
    """
    del tmp_path_factory
    ssh_dir = short_dir / "ssh"
    ssh_dir.mkdir(mode=0o700)
    keygen = shutil.which("ssh-keygen") or "ssh-keygen"
    for name in ("host", "id"):
        subprocess.run(  # noqa: S603  # fixed arguments
            [
                keygen,
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                f"vk-{name}",
                "-f",
                str(ssh_dir / name),
            ],
            check=True,
            timeout=60,
        )
    shutil.copy(ssh_dir / "id.pub", ssh_dir / "authorized_keys")
    port = free_port()
    server_runtime = short_dir / "srv"
    server_runtime.mkdir(mode=0o700, exist_ok=True)
    settings = {
        "XDG_RUNTIME_DIR": str(server_runtime),
        "XDG_CONFIG_HOME": str(short_dir / "sc"),
        "XDG_STATE_HOME": str(short_dir / "ss"),
        "PATH": os.environ["PATH"],
    }
    (ssh_dir / "sshd_config").write_text(
        "\n".join(
            [
                f"Port {port}",
                "ListenAddress 127.0.0.1",
                f"HostKey {ssh_dir / 'host'}",
                f"PidFile {ssh_dir / 'sshd.pid'}",
                f"AuthorizedKeysFile {ssh_dir / 'authorized_keys'}",
                "PasswordAuthentication no",
                "KbdInteractiveAuthentication no",
                "UsePAM no",
                "StrictModes no",
                "AllowStreamLocalForwarding yes",
                "LogLevel ERROR",
                "SetEnv " + " ".join(f"{key}={value}" for key, value in settings.items()),
                "",
            ]
        ),
        encoding="utf-8",
    )
    (ssh_dir / "known_hosts").write_text(
        f"[127.0.0.1]:{port} {' '.join((ssh_dir / 'host.pub').read_text().split()[:2])}\n",
        encoding="utf-8",
    )
    (ssh_dir / "ssh_config").write_text(
        "\n".join(
            [
                "Host server1",
                "  HostName 127.0.0.1",
                f"  Port {port}",
                f"  User {os.environ.get('USER') or Path.home().name}",
                f"  IdentityFile {ssh_dir / 'id'}",
                "  IdentitiesOnly yes",
                "  IdentityAgent none",
                f"  UserKnownHostsFile {ssh_dir / 'known_hosts'}",
                "  GlobalKnownHostsFile /dev/null",
                "  StrictHostKeyChecking yes",
                "  BatchMode yes",
                "",
            ]
        ),
        encoding="utf-8",
    )
    log = (ssh_dir / "sshd.log").open("wb")
    sshd = subprocess.Popen(  # noqa: S603  # fixed arguments
        [shutil.which("sshd") or "sshd", "-D", "-e", "-f", str(ssh_dir / "sshd_config")],
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + 30
        while True:
            assert sshd.poll() is None, (ssh_dir / "sshd.log").read_text()
            with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), 1):
                break
            assert time.monotonic() < deadline, "sshd did not listen"
            time.sleep(0.1)
        yield ssh_dir / "ssh_config"
    finally:
        sshd.terminate()
        try:
            sshd.wait(timeout=10)
        except subprocess.TimeoutExpired:
            sshd.kill()
            sshd.wait()
        log.close()


@pytest.mark.integration
@needs_sshd
def test_a_bridge_stays_listed_through_a_real_ssh(short_dir: Path, private_sshd: Path) -> None:
    (short_dir / "lap").mkdir(mode=0o700)
    laptop = sites.Roots(short_dir / "lc", short_dir / "ls", short_dir / "lap")
    server = sites.Roots(short_dir / "sc", short_dir / "ss", short_dir / "srv")
    # No agent, and no HOME to find a configuration in: ssh is told its configuration file.
    ssh_env = {"PATH": os.environ["PATH"], "HOME": str(short_dir)}
    run(
        hold_a_bridge(
            [shutil.which("ssh") or "ssh", "-F", str(private_sshd)],
            ssh_env,
            laptop,
            server,
            short_dir,
        ),
        180,
    )
