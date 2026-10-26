# SPDX-License-Identifier: Apache-2.0
"""A private display for one login, shown to a person in any web browser.

When valetkeyd runs on a machine nobody sits at, a login window has no screen to open on. This
module makes one: a headless sway in a runtime directory of its own, shared as plain VNC on a unix
socket by wayvnc, and viewed through :mod:`valetkey.gateway`, which serves noVNC on a loopback
port. The login's Chromium is the only client the compositor ever has, and its address bar is
visible, so a person can see where they are signing in. The viewer sees nothing else on the
machine, because nothing else is on this display.

wayvnc is started without ``-w``: wayvnc 0.10.2 with neatvnc 1.0.3 crashes on a WebSocket client,
so it speaks plain RFB to the gateway, which owns the one TCP socket and the WebSocket.

Everything here ends together. :meth:`Display.close` stops the gateway, wayvnc and sway and removes
the directory, and it runs when the login's browser exits or the daemon stops. The processes are
also started so that they die with the daemon, in case it is killed.
"""

import asyncio
import contextlib
import os
import platform
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import valetkey
from valetkey import login, sites
from valetkey.gateway import LIFETIME, Gateway

if TYPE_CHECKING:
    from collections.abc import Sequence

STOP_GRACE = 5.0
"""Seconds a process gets after SIGTERM before SIGKILL."""
START_TIMEOUT = 20.0
"""Seconds to wait for the compositor and the VNC server to come up."""
OUTPUT = "HEADLESS-1"
RESOLUTION = "1280x800"
NOVNC_DIRECTORY = "novnc"
MIN_WAYVNC = (0, 9)
"""The oldest wayvnc that can listen on a unix socket."""
_WAYVNC_VERSION = re.compile(r"wayvnc:\s*v?(\d+)\.(\d+)")
"""Where the pinned noVNC files live, next to this module (see ``tools/fetch_novnc.py``)."""
_DISPLAYS = "displays"


class RemoteDisplayError(login.DisplayError):
    """The private display could not be started."""


def novnc_root() -> Path:
    """Return the directory that holds the pinned noVNC files.

    Raises:
        RemoteDisplayError: when they are not installed, with the command that installs them.

    """
    root = Path(valetkey.__file__).resolve().parent / NOVNC_DIRECTORY
    if not (root / "vnc.html").is_file():
        message = (
            "the noVNC viewer is not installed; run `just novnc` in a checkout and install again, "
            "or install the package, which includes it"
        )
        raise RemoteDisplayError(message)
    return root


def wayvnc_problem(version_output: str) -> str | None:
    """Say why the wayvnc that printed ``version_output`` cannot be used, or ``None`` if it can."""
    match = _WAYVNC_VERSION.search(version_output)
    if match is None:
        return "cannot read the version of wayvnc"
    version = (int(match.group(1)), int(match.group(2)))
    if version < MIN_WAYVNC:
        found = ".".join(map(str, version))
        wanted = ".".join(map(str, MIN_WAYVNC))
        return f"wayvnc {found} is too old; a login from a browser needs {wanted} or newer"
    return None


def _wayvnc_version_output(program: str) -> str:
    """Run ``program --version``; empty when it cannot be run."""
    try:
        result = subprocess.run(  # noqa: S603  # fixed argument list
            [program, "--version"], capture_output=True, text=True, check=False, timeout=10
        )
    except OSError, subprocess.SubprocessError:
        return ""
    return result.stdout + result.stderr


def ssh_command(port: int, host: str | None = None) -> str:
    """Return the ``ssh -L`` line a remote person runs so that the link works on their machine."""
    name = host or platform.node() or "HOST"
    return f"ssh -L {port}:localhost:{port} {name}"


class _Process:
    """A child process started from a thread of its own, so that it dies with the daemon.

    ``PR_SET_PDEATHSIG`` (set here with ``setpriv --pdeathsig``) fires when the *thread* that
    started the child ends, so a pool thread would end it at an arbitrary time. This thread does
    nothing but wait for the child.
    """

    def __init__(self, name: str, argv: Sequence[str], env: dict[str, str], log: Path) -> None:
        self.name = name
        self.argv = list(argv)
        self.env = env
        self.log = log
        self.process: subprocess.Popen[bytes] | None = None
        self.exited: asyncio.Future[int] | None = None

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        started: asyncio.Future[None] = loop.create_future()
        self.exited = loop.create_future()
        exited = self.exited
        argv = self.argv
        if (setpriv := shutil.which("setpriv")) is not None:
            argv = [setpriv, "--pdeathsig", "TERM", "--", *argv]

        def hold() -> None:
            try:
                with self.log.open("ab") as log:
                    self.process = subprocess.Popen(  # noqa: S603 - a fixed argument list
                        argv,
                        env=self.env,
                        stdin=subprocess.DEVNULL,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                    )
            except OSError as error:
                loop.call_soon_threadsafe(started.set_exception, error)
                return
            loop.call_soon_threadsafe(started.set_result, None)
            status = self.process.wait()
            loop.call_soon_threadsafe(exited.set_result, status)

        threading.Thread(target=hold, name=f"valetkey-{self.name}", daemon=True).start()
        try:
            await started
        except OSError as error:
            message = f"cannot start {self.name}: {error}"
            raise RemoteDisplayError(message) from error

    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def log_tail(self, size: int = 600) -> str:
        with contextlib.suppress(OSError):
            return self.log.read_text(errors="replace")[-size:].strip()
        return ""

    async def stop(self) -> None:
        """End the process: SIGTERM, then SIGKILL after :data:`STOP_GRACE`. Safe to repeat."""
        process, exited = self.process, self.exited
        if process is None or exited is None or process.poll() is not None:
            return
        with contextlib.suppress(ProcessLookupError):
            process.terminate()
        try:
            await asyncio.wait_for(asyncio.shield(exited), STOP_GRACE)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            await exited


@dataclass(slots=True)
class Display:
    """A running private display. Get one from :func:`start_display`."""

    directory: Path
    wayland_socket: Path
    gateway: Gateway
    _processes: list[_Process]
    _closed: bool = False

    @property
    def url(self) -> str:
        """The link a person opens."""
        return self.gateway.url

    @property
    def port(self) -> int:
        """The loopback port the gateway listens on."""
        return self.gateway.port

    async def close(self) -> None:
        """Stop the gateway, wayvnc and sway and remove the directory. Safe to repeat."""
        if self._closed:
            return
        self._closed = True
        await self.gateway.close()
        for process in reversed(self._processes):
            await process.stop()
        await asyncio.to_thread(shutil.rmtree, self.directory, ignore_errors=True)


def sway_command(config: Path) -> list[str]:
    """Return the compositor's command line."""
    return ["sway", "--config", str(config)]


def wayvnc_command(vnc_socket: Path) -> list[str]:
    """Return wayvnc's command line: plain RFB on a unix socket, never a WebSocket."""
    return ["wayvnc", "--output", OUTPUT, f"unix:{vnc_socket}"]


def display_environment(directory: Path, wayland_name: str | None = None) -> dict[str, str]:
    """Return the environment of a process that runs on the private display."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin"),
        "HOME": str(directory),
        "XDG_RUNTIME_DIR": str(directory),
        "WLR_BACKENDS": "headless",
        "WLR_LIBINPUT_NO_DEVICES": "1",
        "WLR_RENDERER": "pixman",
    }
    if wayland_name is not None:
        env["WAYLAND_DISPLAY"] = wayland_name
    return env


async def _wait_for(
    path_ready: Any,  # noqa: ANN401 - a callable returning bool
    process: _Process,
    what: str,
) -> None:
    deadline = asyncio.get_running_loop().time() + START_TIMEOUT
    while not path_ready():
        if not process.running():
            message = f"{process.name} exited before {what}: {process.log_tail()}"
            raise RemoteDisplayError(message)
        if asyncio.get_running_loop().time() > deadline:
            message = f"{process.name} did not provide {what} in {START_TIMEOUT:g} seconds"
            raise RemoteDisplayError(message)
        await asyncio.sleep(0.05)


async def start_display(
    roots: sites.Roots,
    site: str,
    *,
    novnc: Path | None = None,
    lifetime: float = LIFETIME,
) -> Display:
    """Start a private display for ``site``'s login and return it once the link works.

    The keyword argument is the directory of viewer files (default: :func:`novnc_root`). The
    directory of the display is ``$XDG_RUNTIME_DIR/valetkey/displays/SITE`` (mode 0700), emptied
    first.

    Raises:
        RemoteDisplayError: when the viewer files, sway or wayvnc are missing, or one of them
            does not come up. Whatever was started is stopped again.

    """
    viewer = novnc or novnc_root()
    for program in ("sway", "wayvnc"):
        if shutil.which(program) is None:
            message = f"a login from a browser needs {program}, which is not installed"
            raise RemoteDisplayError(message)
    problem = wayvnc_problem(await asyncio.to_thread(_wayvnc_version_output, "wayvnc"))
    if problem is not None:
        raise RemoteDisplayError(problem)
    directory = await asyncio.to_thread(_prepare, roots, site)
    config = directory / "sway.conf"
    config.write_text(f"output {OUTPUT} resolution {RESOLUTION}\n", encoding="utf-8")
    vnc_socket = directory / "vnc.sock"
    sway = _Process(
        "sway", sway_command(config), display_environment(directory), directory / "sway.log"
    )
    started: list[_Process] = []
    gateway = Gateway(vnc_socket, viewer, lifetime=lifetime)
    try:
        await sway.start()
        started.append(sway)
        await _wait_for(lambda: bool(list(directory.glob("wayland-*[0-9]"))), sway, "a display")
        wayland = next(iter(sorted(directory.glob("wayland-*[0-9]"))))
        vnc = _Process(
            "wayvnc",
            wayvnc_command(vnc_socket),
            display_environment(directory, wayland.name),
            directory / "wayvnc.log",
        )
        await vnc.start()
        started.append(vnc)
        await _wait_for(vnc_socket.is_socket, vnc, "its socket")
        await gateway.start()
    except BaseException:
        await gateway.close()
        for process in reversed(started):
            await process.stop()
        await asyncio.to_thread(shutil.rmtree, directory, ignore_errors=True)
        raise
    return Display(directory, wayland, gateway, started)


def _prepare(roots: sites.Roots, site: str) -> Path:
    """Create the empty ``0700`` directory of ``site``'s display."""
    sites.validate_site_name(site)
    sites.ensure_runtime(roots)
    directory = sites.runtime_path(roots) / _DISPLAYS
    directory.mkdir(mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    directory /= site
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    return directory


def describe(display: Display) -> dict[str, Any]:
    """Return what the daemon tells a client: the link, the port and the ``ssh -L`` line."""
    return {"url": display.url, "port": display.port, "ssh": ssh_command(display.port)}
