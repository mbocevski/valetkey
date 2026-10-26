# SPDX-License-Identifier: Apache-2.0
"""Log in to a site in a real browser window, then hand over what the browser reached.

A login opens a normal, visible Chromium window on the person's own Wayland screen. The window
runs in the same network namespace as every other session (see :mod:`valetkey.sandbox`), with
the proxy in record mode: it lets every host through and notes which ones the page used. The
person signs in, second factor included, and closes the window. Closing the window ends the
login, and the hosts the proxy saw go to a callback, for the classifier to work on.

Chromium is started directly and never with a debugging port, so nothing outside the window
can watch a password being typed. A browser window on a display can read what it is shown, so
the display is checked first: Wayland keeps clients apart, and X11 does not, so valetkey refuses
to open a login window on an X11-only session.

Use :func:`start_login` (or :func:`run_login`, which also waits) from an asyncio program. Nothing
blocks the event loop: the sandbox is started and waited on in a thread of its own, and file
work and subprocess calls run in worker threads.
"""

import asyncio
import contextlib
import inspect
import logging
import os
import shlex
import shutil
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlsplit

from valetkey import sandbox, sites, wayland
from valetkey.proxy import PRIVATE_ADDRESS, Mode, Proxy, SeenHost

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping, Sequence

logger = logging.getLogger(__name__)

NO_SESSION = "no desktop session here — log in on a machine with one, or enable remote logins"
X11_ONLY = (
    "only an X11 session is available here. An X11 client can read every keystroke and the "
    "whole screen, so valetkey refuses to open a login window on X11. Log in from a Wayland "
    "session instead, or enable remote logins"
)
CHROMIUM = "chromium"
"""Chromium's name inside the sandbox, where ``PATH`` is ``/usr/bin``."""
BRIDGE_WAIT_SECONDS = 15
STOP_GRACE_SECONDS = 5.0

type Finish = Callable[[list[SeenHost], Path], Awaitable[None] | None]
type Restrict = Callable[[Path, Path, str], wayland.SecurityContext | None]
type Launcher = Callable[[sandbox.Sandbox, list[str]], subprocess.Popen[bytes]]

_WAIT_FOR_BRIDGE = f"""
import socket, sys, time
address = ("127.0.0.1", {sandbox.PROXY_ADDRESS.rpartition(":")[2]})
for _ in range({BRIDGE_WAIT_SECONDS * 10}):
    try:
        socket.create_connection(address, 1).close()
        sys.exit(0)
    except OSError:
        time.sleep(0.1)
sys.exit("the forwarder never started listening")
"""


# -- finding the display -------------------------------------------------------------------


class DisplayError(RuntimeError):
    """There is no display a login window may be opened on."""


class NoDisplayError(DisplayError):
    """No Wayland display was found: no desktop session, or its socket is gone."""


class X11OnlyError(DisplayError):
    """Only an X11 display exists, and valetkey does not open a login window on one."""


def parse_environment(text: str) -> dict[str, str]:
    """Parse the output of ``systemctl --user show-environment`` into a dictionary.

    Each line is ``NAME=value``. A value systemd had to quote (``$'…'``) has its quotes removed;
    lines without ``=`` are skipped.
    """
    environment: dict[str, str] = {}
    for line in text.splitlines():
        name, separator, value = line.partition("=")
        if separator and name:
            if value.startswith("$'") and value.endswith("'"):
                value = value[2:-1]
            environment[name] = value
    return environment


def systemd_user_environment(timeout: float = 5.0) -> dict[str, str]:
    """Return the environment of the systemd user manager, or an empty one when it can't be read.

    Desktop compositors export ``WAYLAND_DISPLAY`` and ``DISPLAY`` there, which a service
    started by the same manager may not have inherited.
    """
    try:
        result = subprocess.run(  # fixed argument list
            ["systemctl", "--user", "show-environment"],  # noqa: S607  # resolved from PATH
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout,
        )
    except OSError, subprocess.SubprocessError:
        return {}
    return parse_environment(result.stdout)


def find_wayland_socket(
    environ: Mapping[str, str] | None = None,
    user_environment: Callable[[], Mapping[str, str]] = systemd_user_environment,
) -> Path:
    """Return the path of the person's Wayland compositor socket.

    Each variable (``WAYLAND_DISPLAY``, ``XDG_RUNTIME_DIR``, ``DISPLAY``) is read from
    ``environ`` (default: the process environment) first and from ``user_environment()`` (the
    systemd user manager) only when it is missing there. The manager is asked at most once, and
    only when needed. The socket is ``WAYLAND_DISPLAY`` itself when that is an absolute path,
    and ``$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY`` otherwise.

    Raises:
        X11OnlyError: when there is no Wayland display but there is an X11 one.
        NoDisplayError: when there is no display at all, when ``WAYLAND_DISPLAY`` is relative
            and ``XDG_RUNTIME_DIR`` is missing, or when the socket is not there.

    """
    env = os.environ if environ is None else environ
    fallback: Mapping[str, str] | None = None

    def lookup(name: str) -> str:
        nonlocal fallback
        if value := env.get(name):
            return value
        if fallback is None:
            fallback = user_environment()
        return fallback.get(name, "")

    display = lookup("WAYLAND_DISPLAY")
    if not display:
        if lookup("DISPLAY"):
            raise X11OnlyError(X11_ONLY)
        raise NoDisplayError(NO_SESSION)
    path = Path(display)
    if not path.is_absolute():
        runtime = lookup("XDG_RUNTIME_DIR")
        if "/" in display or not Path(runtime).is_absolute():
            msg = f"{NO_SESSION} (cannot place WAYLAND_DISPLAY={display!r})"
            raise NoDisplayError(msg)
        path = Path(runtime) / display
    if not path.is_socket():
        msg = f"{NO_SESSION} ({path} is not a socket)"
        raise NoDisplayError(msg)
    return path


# -- the display the window gets -----------------------------------------------------------

DISPLAY_NAME = "wayland-login"
"""The name of the restricted socket, which is also what ``WAYLAND_DISPLAY`` is inside."""
APP_ID = "valetkey-login"
UNRESTRICTED_SHORT = (
    "the Wayland compositor has no security-context support; the login window is not restricted"
)
UNRESTRICTED = (
    "the Wayland compositor has no security-context support, so login windows are not "
    "restricted: they can use screen capture, virtual input and clipboard managers"
)
_warned: set[str] = set()


def restrict_display(
    compositor: Path, login_dir: Path, site: str
) -> wayland.SecurityContext | None:
    """Ask the compositor for a restricted socket for ``site``'s login window.

    The socket is made in ``login_dir`` and is the only display the window gets. A client that
    connects through it is refused screen capture, virtual keyboards and pointers, and clipboard
    managers, but pastes, copies and types as usual. Returns ``None`` when the compositor cannot
    do this, and the caller falls back to the compositor's own socket. A login is never refused
    for lack of it: the missing support is logged once per process, and any other failure each
    time it happens.
    """
    try:
        return wayland.create_security_context(
            compositor, login_dir / DISPLAY_NAME, app_id=APP_ID, instance_id=site
        )
    except wayland.SecurityContextUnavailableError:
        if "unavailable" not in _warned:
            _warned.add("unavailable")
            logger.warning(UNRESTRICTED)
    except wayland.WaylandError as error:
        logger.warning(
            "could not restrict the login window's display (%s); using the plain one", error
        )
    return None


def waypipe_wrapper(
    bridge: Path, display: Path, waypipe: Sequence[str] = ("waypipe",)
) -> tuple[str, ...]:
    """Return the command that runs a login sandbox as a program of ``waypipe server``.

    waypipe makes a Wayland display at ``display`` and runs its program with that display, and
    everything drawn on it is sent through the bridge's socket to the laptop's ``waypipe client``.
    The options come before ``server``, because what follows it is the program, and there is no
    ``--unlink-socket``: the socket belongs to the bridge, and removing it would leave sshd
    listening on a name nobody can reach. ``setpriv`` has the kernel end waypipe, and with it the
    sandbox, if valetkeyd dies. The window is not given a security context here: there is no
    compositor on this machine to ask, and the laptop's ``waypipe client`` already runs under
    one.
    """
    return (
        "setpriv",
        "--pdeathsig",
        "SIGTERM",
        *waypipe,
        "-s",
        str(bridge),
        "--display",
        str(display),
        "server",
        "--",
    )


# -- the browser command -------------------------------------------------------------------


def chromium_command(profile_dir: Path, start_url: str, chrome_major: int) -> list[str]:
    """Return the Chromium command line for a login window.

    The containment flags of :func:`valetkey.sandbox.chrome_flags` stay. The window is a normal
    one with an address bar and its own profile, on Wayland. There is no ``--headless``, no
    ``--app``, no kiosk mode and no remote debugging port.
    """
    return [
        CHROMIUM,
        *sandbox.chrome_flags(chrome_major),
        "--ozone-platform=wayland",
        f"--user-data-dir={profile_dir}",
        start_url,
    ]


def holder_command(browser: list[str], bridge: list[str], profile_dir: Path) -> list[str]:
    """Return the command that runs first inside the sandbox.

    It is a shell script: clear Chromium's stale profile locks (the process numbers of an
    earlier run mean nothing in a new namespace), start the forwarder in the background, wait
    until it listens, then replace the shell with the browser. The browser is then the first
    process of the namespace, so when it exits the namespace ends and takes the forwarder along.
    """
    wait = [sys.executable, "-I", "-c", _WAIT_FOR_BRIDGE]
    script = "\n".join(
        [
            f"rm -f {shlex.quote(str(profile_dir))}/Singleton*",
            f"{shlex.join(bridge)} &",
            f"{shlex.join(wait)} || exit 1",
            f"exec {shlex.join(browser)}",
        ]
    )
    return ["/usr/bin/sh", "-c", script]


def normalize_start_url(value: str) -> str:
    """Return ``value`` as an http(s) URL, adding ``https://`` to a bare host name.

    Raises:
        ValueError: when no host can be read from it or the scheme is not HTTP or HTTPS.

    """
    text = value.strip()
    if "://" not in text:
        text = f"https://{text}"
    parts = urlsplit(text)
    sites.host_of(text)
    if parts.scheme not in {"http", "https"}:
        msg = f"a login starts at an http or https URL, not {value!r}"
        raise ValueError(msg)
    return text


# -- running a login -----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LoginResult:
    """How a login ended.

    ``seen_hosts`` are the hosts the browser connected to, in the order first seen, with
    connection counts. ``exit_code`` is the sandbox's exit status. ``cancelled`` is true when
    :meth:`LoginHandle.cancel` ended the login rather than the person closing the window.
    ``private_refused`` are the hosts the proxy refused because of the private address they
    resolve to, each once: the person may want to list a range for them.
    """

    seen_hosts: list[SeenHost]
    profile_dir: Path
    exit_code: int
    cancelled: bool
    private_refused: tuple[str, ...] = ()


class LoginHandle:
    """A running login. Get one from :func:`start_login`."""

    def __init__(  # noqa: PLR0913, PLR0917 - the handle owns each of these for the login's life
        self,
        process: subprocess.Popen[bytes],
        exited: asyncio.Future[int],
        proxy: Proxy,
        directories: tuple[Path, Path],
        finish: Finish,
        context: wayland.SecurityContext | None = None,
    ) -> None:
        """Start watching ``process``. Use :func:`start_login` instead of calling this.

        ``context`` is the window's restricted display, closed when the login ends.
        """
        self._process = process
        self._exited = exited
        self._proxy = proxy
        self._login_dir, self._profile_dir = directories
        self._finish = finish
        self._context = context
        self._cancelled = False
        self._task = asyncio.ensure_future(self._supervise())

    @property
    def running(self) -> bool:
        """True until the window has closed and the cleanup has finished."""
        return not self._task.done()

    async def wait(self) -> LoginResult:
        """Wait for the person to close the window, then return how the login ended.

        By then the proxy is closed, the socket directory is gone and ``finish`` has run. An
        error raised by ``finish`` is raised here. Safe to call from several tasks and to
        cancel: it never cancels the login itself.
        """
        return await asyncio.shield(self._task)

    async def cancel(self) -> LoginResult:
        """End the login now, as if the window had been closed, but without calling ``finish``.

        The sandbox is terminated (killed if it does not stop within a few seconds). Does
        nothing extra when the login has already ended.
        """
        if self.running:
            self._cancelled = True
            with contextlib.suppress(ProcessLookupError):
                self._process.terminate()
            try:
                await asyncio.wait_for(asyncio.shield(self._exited), STOP_GRACE_SECONDS)
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    self._process.kill()
        return await self.wait()

    async def _supervise(self) -> LoginResult:
        try:
            exit_code = await self._exited
        finally:
            seen = self._proxy.seen_hosts()
            refused = self._proxy.refused_since(0)[0]
            if self._context is not None:
                await asyncio.to_thread(self._context.close)
            await self._proxy.close()
            await asyncio.to_thread(shutil.rmtree, self._login_dir, ignore_errors=True)
        private = tuple(
            dict.fromkeys(entry.host for entry in refused if entry.reason == PRIVATE_ADDRESS)
        )
        result = LoginResult(seen, self._profile_dir, exit_code, self._cancelled, private)
        if not self._cancelled:
            outcome = self._finish(seen, self._profile_dir)
            if inspect.isawaitable(outcome):
                await outcome
        return result


def _resolve[T](future: asyncio.Future[T], value: T) -> None:
    future.set_result(value)


def _fail(future: asyncio.Future[Any], error: BaseException) -> None:
    future.set_exception(error)


def _terminate_when_started(started: asyncio.Future[subprocess.Popen[bytes]]) -> None:
    if started.exception() is None:
        started.result().terminate()


@dataclass(frozen=True, slots=True)
class _Hold:
    """What the thread of one login needs to start the sandbox and report back."""

    launcher: Launcher
    box: sandbox.Sandbox
    command: list[str]
    loop: asyncio.AbstractEventLoop
    started: asyncio.Future[subprocess.Popen[bytes]]
    exited: asyncio.Future[int]

    def run(self) -> None:
        """Start the sandbox and wait for it, in one thread that lives as long as the sandbox.

        The kernel's die-with-parent rule is tied to the thread that started a child, not to the
        process: when that thread ends, the sandbox is killed. A pool thread could end or be
        reused at any time, so each login gets a thread of its own that does nothing else until
        the sandbox exits. If the whole program dies, so does the thread and so does the browser.
        """
        try:
            process = self.launcher(self.box, self.command)
        except BaseException as error:  # noqa: BLE001 - handed to the caller through the future
            self.loop.call_soon_threadsafe(_fail, self.started, error)
            return
        self.loop.call_soon_threadsafe(_resolve, self.started, process)
        self.loop.call_soon_threadsafe(_resolve, self.exited, process.wait())


async def start_login(  # noqa: PLR0913 - the injection points are the tests' way in
    site: str,
    start_url: str,
    roots: sites.Roots,
    finish: Finish,
    *,
    wayland_socket: Path | None = None,
    chrome_major: int | None = None,
    launcher: Launcher = sandbox.start,
    proxy_options: Mapping[str, Any] | None = None,
    private_networks: Sequence[str] = (),
    restrict: Restrict = restrict_display,
    bridge: Path | None = None,
    waypipe: Sequence[str] = ("waypipe",),
) -> LoginHandle:
    """Open a login window for ``site`` and return once it has been started.

    ``site`` is the site name (see :func:`valetkey.sites.validate_site_name`). The window opens
    at ``start_url``; a bare host name gets ``https://``. ``roots`` are the XDG directories to
    use, and ``roots.runtime`` must be set.

    ``finish`` is called as ``finish(seen_hosts, profile_dir)``, plain or ``async``, after the
    window has closed and everything is cleaned up. It is not called after a cancel.

    The keyword arguments are mostly for tests. ``wayland_socket`` is the compositor socket
    (default: :func:`find_wayland_socket`). ``chrome_major`` is Chromium's major version
    (default: ask ``chromium --version``). ``launcher`` starts the sandbox (default:
    :func:`valetkey.sandbox.start`). ``proxy_options`` are extra keyword arguments for
    :class:`valetkey.proxy.Proxy`, such as ``resolver``; ``quiet_hosts`` defaults to the
    browser's background hosts. ``private_networks`` are the site's listed private address
    ranges (see :func:`valetkey.sites.private_network`); the proxy lets a host resolve into them,
    and into nothing else that is private. ``restrict`` makes the window's restricted display
    (default: :func:`restrict_display`); when it returns ``None`` the window gets
    ``wayland_socket``. With ``bridge``, the socket of a connected bridge (see
    :mod:`valetkey.bridge`), the window opens on the laptop at its other end: the sandbox runs
    under ``waypipe server`` (``waypipe`` names the program), the display it binds in is
    waypipe's, and ``wayland_socket`` and ``restrict`` are not used.

    The proxy runs in record mode, which lets every host through, so its policy only has to be
    valid: it allows the start host and lists the ranges. The hosts the browser used are in the
    result instead.

    Raises:
        DisplayError: when there is no Wayland display to open a window on.
        ValueError: for a bad site name or start URL.

    """
    url = normalize_start_url(start_url)
    placeholder = sites.Policy(
        site, url, (sites.host_of(url),), private_networks=tuple(private_networks)
    )
    socket_path = None
    if bridge is None:
        socket_path = wayland_socket or await asyncio.to_thread(find_wayland_socket)
    major = chrome_major or await asyncio.to_thread(sandbox.installed_chrome_major)
    runtime = sites.runtime_path(roots)
    profile_dir, login_dir = await asyncio.to_thread(_prepare, roots, site, runtime)
    options: dict[str, Any] = {"quiet_hosts": sandbox.BACKGROUND_HOSTS} | dict(proxy_options or {})
    proxy = Proxy(placeholder, Mode.RECORD, **options)
    proxy_socket = login_dir / "proxy.sock"
    context: wayland.SecurityContext | None = None
    try:
        await proxy.start(proxy_socket)
        if socket_path is not None:
            context = await asyncio.to_thread(restrict, socket_path, login_dir, site)
        policy_dir = await asyncio.to_thread(
            sandbox.write_chrome_policy, login_dir / "chrome-policy"
        )
        box = sandbox.Sandbox(
            profile_dir=profile_dir,
            proxy_socket=proxy_socket,
            log_file=runtime / "logins" / f"{site}.log",
            runtime_dir=cast("Path", roots.runtime),
            wayland_socket=_window_display(context, socket_path, login_dir, bridge),
            policy_dir=policy_dir,
            wrapper=waypipe_wrapper(bridge, login_dir / DISPLAY_NAME, waypipe) if bridge else (),
        )
        await asyncio.to_thread(box.log_file.unlink, missing_ok=True)
        command = holder_command(
            chromium_command(profile_dir, url, major),
            sandbox.bridge_command(proxy_socket),
            profile_dir,
        )
        loop = asyncio.get_running_loop()
        started: asyncio.Future[subprocess.Popen[bytes]] = loop.create_future()
        exited: asyncio.Future[int] = loop.create_future()
        hold = _Hold(launcher, box, command, loop, started, exited)
        threading.Thread(
            target=hold.run,
            name=f"valetkey-login-{site}",
            daemon=True,
        ).start()
        process = await asyncio.shield(started)
    except BaseException:
        # Starting may still finish in its thread (when this task was cancelled): end whatever
        # it starts, because nothing would watch it.
        started.add_done_callback(_terminate_when_started)
        if context is not None:
            await asyncio.to_thread(context.close)
        await proxy.close()
        await asyncio.to_thread(shutil.rmtree, login_dir, ignore_errors=True)
        raise
    return LoginHandle(process, exited, proxy, (login_dir, profile_dir), finish, context)


def _window_display(
    context: wayland.SecurityContext | None,
    compositor: Path | None,
    login_dir: Path,
    bridge: Path | None,
) -> Path | None:
    """Return the display socket the window gets: restricted, plain, or waypipe's."""
    if bridge is not None:
        return login_dir / DISPLAY_NAME
    return context.path if context is not None else compositor


def _prepare(roots: sites.Roots, site: str, runtime: Path) -> tuple[Path, Path]:
    """Create the profile and per-login socket directories (all ``0700``)."""
    profile = sites.ensure_profile(roots, site)
    sites.ensure_runtime(roots)
    login_dir = runtime
    for part in ("logins", site):
        login_dir /= part
        login_dir.mkdir(mode=0o700, exist_ok=True)
        login_dir.chmod(0o700)
    return profile, login_dir


async def run_login(
    site: str,
    start_url: str,
    roots: sites.Roots,
    finish: Finish,
    **options: Any,  # noqa: ANN401 - forwarded to start_login
) -> LoginResult:
    """Run :func:`start_login` and wait until the window is closed."""
    handle = await start_login(site, start_url, roots, finish, **options)
    return await handle.wait()
