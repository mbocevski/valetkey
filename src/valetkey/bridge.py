# SPDX-License-Identifier: Apache-2.0
"""The waypipe bridge: login windows from a headless valetkeyd on the person's own desktop.

``valetkey bridge HOST`` runs on the laptop (see :func:`run_bridge`). It keeps two long-lived
processes: ``waypipe client``, which turns a local socket into windows on the laptop's
compositor, and an ``ssh`` that forwards a socket of the server's runtime directory to it::

    waypipe --secctx valetkey -s $XDG_RUNTIME_DIR/valetkey/wp.sock client
    ssh -S none -o ExitOnForwardFailure=yes -R <remote>/valetkey/bridge-<rand>.sock:<local> HOST
        valetkey bridge-hold <rand>

On the server, ``valetkey bridge-hold`` (see :func:`hold`) registers the forwarded socket with
valetkeyd, so that a later login can be launched through it, and removes the socket when the
connection ends. Each part exists because something broke without it:

* ``--secctx`` is always passed, and nothing here can turn it off. Without it, a forwarded
  application captured the laptop's whole screen. With it, the compositor shows the application
  only the interfaces it lists for sandboxed clients, and screen capture is not among them.
* ``-S none`` gives the bridge its own ssh connection. Through a multiplexing master, a second
  ``-R`` for a new path was silently not bound.
* The bridge owns the socket name, ``bridge-<rand>.sock``, one per ssh connection, and a launch
  never removes it: a launch that unlinked it left sshd listening on a socket nobody could reach.
  A fresh name per connection also cannot collide with the leftover of an earlier one.
* ``ExitOnForwardFailure`` makes a forward that did not come up end the connection, so the loop
  below tries again with a new name instead of holding a connection that does nothing.

**Trust.** Whoever can reach a bridge socket on the server can open windows on the laptop, so
the socket lives in the server's ``0700`` runtime directory, and valetkeyd registers only a
socket of its own user that is really there. A process of the same user on the server is
trusted, as it is everywhere in valetkey. What it can do on the laptop is limited by ``--secctx``
to what the compositor lets a sandboxed client do.
"""

import asyncio
import contextlib
import errno
import fcntl
import logging
import os
import random
import re
import secrets
import signal
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from valetkey import mcp_server, sites
from valetkey.client import DaemonError

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping, Sequence

logger = logging.getLogger(__name__)

SECCTX_APP_ID = "valetkey"
"""The application id of the security context ``waypipe`` creates for everything it forwards."""
LOCAL_SOCKET = "wp.sock"
LOCK_NAME = "bridge.lock"
MAX_BACKOFF = 60.0
"""The longest wait, in seconds, before a failed connection is tried again."""
STABLE_AFTER = 60.0
"""A connection that lasted this long was a good one: the next failure starts the waits over."""
KEEPALIVE_SECONDS = 15
"""How often ssh probes the connection. Three probes unanswered end it."""
STOP_GRACE = 5.0
"""Seconds a process gets to stop before it is killed."""
SOCKET_WAIT = 10.0
"""Seconds to wait for ``waypipe client`` to create its socket."""
PROBE_TIMEOUT = 30
"""Seconds ssh gets to connect when it only asks for the server's runtime directory."""
HOLD_WAIT = 15.0
"""Seconds ``bridge-hold`` waits for the forwarded socket to appear."""
HOLD_INTERVAL = 2.0
"""How often ``bridge-hold`` registers again, which also mends a lost connection to valetkeyd."""
NO_FORWARDING = (
    "-a",
    "-x",
    "-o",
    "ForwardAgent=no",
    "-o",
    "ForwardX11=no",
    "-o",
    "PermitLocalCommand=no",
)
"""What ssh is told on every connection so that the person's ``ssh_config`` cannot hand the server
more than the one socket: the agent, X11 and local commands are all off, and ``-R`` below is the
only forward."""
_RAND = re.compile(r"[A-Za-z0-9]{8,64}")
_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]*")


class BridgeError(Exception):
    """The bridge cannot run; the message is for the person."""


def validate_host(host: str) -> str:
    """Return ``host`` if ssh can be given it safely, or raise :class:`BridgeError`.

    It must not start with a dash, which ssh would read as an option, and may hold only the
    characters of a host name, an address (IPv4) or ``user@host``.
    """
    if not _HOST.fullmatch(host):
        msg = f"not a host name ssh can be given: {host!r}"
        raise BridgeError(msg)
    return host


def waypipe_argv(waypipe: Sequence[str], socket: Path) -> list[str]:
    """Return the command that runs ``waypipe client`` on ``socket``, with the security context."""
    return [*waypipe, "--secctx", SECCTX_APP_ID, "-s", str(socket), "client"]


def forward_spec(remote: Path, local: Path) -> str:
    """Return the ``-R`` argument that forwards ``remote`` (on the server) to ``local``.

    Raises:
        BridgeError: when a path holds a colon, which ``-R`` could not tell from its separator.

    """
    for path in (remote, local):
        if ":" in str(path):
            msg = f"{path} holds a colon, which ssh cannot forward"
            raise BridgeError(msg)
    return f"{remote}:{local}"


def ssh_argv(
    ssh: Sequence[str],
    host: str,
    forward: str,
    rand: str,
    valetkey: Sequence[str] = ("valetkey",),
) -> list[str]:
    """Return the command that forwards ``forward`` (see :func:`forward_spec`) and holds ``rand``.

    ``-S none`` and ``ExitOnForwardFailure=yes`` are not optional, see the module docstring.
    ``BatchMode`` keeps a service from waiting for a password nobody can type, and the probes
    end a connection that the network dropped without telling either end.
    """
    return [
        *ssh,
        "-S",
        "none",
        "-T",
        *NO_FORWARDING,
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ServerAliveInterval={KEEPALIVE_SECONDS}",
        "-o",
        "ServerAliveCountMax=3",
        "-R",
        forward,
        validate_host(host),
        *valetkey,
        "bridge-hold",
        rand,
    ]


def probe_argv(ssh: Sequence[str], host: str, valetkey: Sequence[str] = ("valetkey",)) -> list[str]:
    """Return the command that asks ``host`` for its runtime directory for bridges."""
    return [
        *ssh,
        "-S",
        "none",
        "-T",
        *NO_FORWARDING,
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={PROBE_TIMEOUT}",
        validate_host(host),
        *valetkey,
        "bridge-hold",
        "--print-runtime",
    ]


def backoff(failures: int, draw: Callable[[], float] = random.random) -> float:
    """Return how long to wait after ``failures`` failures in a row: 1 s, doubling, up to 60 s.

    The wait is cut by a random share, up to half, so that bridges that lost the same server
    together do not all come back together. ``draw`` returns a number from 0 up to 1.
    """
    ceiling = min(MAX_BACKOFF, 2.0 ** min(max(failures, 0), 10))
    return ceiling * (1.0 - draw() / 2)


@dataclass(eq=False)
class _Run:
    """What the supervising tasks share."""

    stop: asyncio.Event
    environ: Mapping[str, str]
    clock: Callable[[], float]
    draw: Callable[[], float]
    children: set[asyncio.subprocess.Process]


async def _terminate(process: asyncio.subprocess.Process) -> None:
    """Stop ``process``: ask, wait a few seconds, then kill."""
    if process.returncode is not None:
        return
    with contextlib.suppress(ProcessLookupError):
        process.terminate()
    try:
        await asyncio.wait_for(process.wait(), STOP_GRACE)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        await process.wait()


async def _spawn(run: _Run, argv: Sequence[str]) -> asyncio.subprocess.Process:
    """Start one of the bridge's programs, with an input that stays open and carries nothing.

    ``ssh -T`` hands its own standard input to the remote command, and ends it when that input
    ends. ``valetkey bridge-hold`` at the other end takes the end of its input for the link
    dropping. So ssh must not read ``/dev/null``, which ends at once: it is given the read end
    of a pipe whose write end this process keeps open, and writes nothing to. The remote command
    sees the end only when this process, or ssh, is gone.
    """
    process = await asyncio.create_subprocess_exec(
        *argv, stdin=asyncio.subprocess.PIPE, env=dict(run.environ)
    )
    run.children.add(process)
    return process


async def _sleep_or_stop(run: _Run, seconds: float) -> None:
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(run.stop.wait(), seconds)


async def _wait_or_stop(run: _Run, process: asyncio.subprocess.Process) -> None:
    """Wait until ``process`` exits or the bridge is told to stop; stop it in the second case."""
    exited = asyncio.ensure_future(process.wait())
    stopped = asyncio.ensure_future(run.stop.wait())
    try:
        await asyncio.wait({exited, stopped}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        exited.cancel()
        stopped.cancel()
    await _terminate(process)
    run.children.discard(process)


async def _supervise(
    run: _Run,
    name: str,
    command: Callable[[], Sequence[str]],
    prepare: Callable[[], None] | None = None,
) -> None:
    """Run ``command()`` again and again, with growing waits, until the bridge is stopped."""
    failures = 0
    while not run.stop.is_set():
        if prepare is not None:
            prepare()
        started = run.clock()
        try:
            process = await _spawn(run, command())
        except OSError as error:
            logger.error("could not start %s: %s", name, error)  # noqa: TRY400 - no trace needed
        else:
            await _wait_or_stop(run, process)
            if run.stop.is_set():
                return
            logger.warning("%s ended with status %s", name, process.returncode)
        failures = 0 if run.clock() - started >= STABLE_AFTER else failures + 1
        delay = backoff(failures - 1, run.draw)
        logger.info("starting %s again in %.1f seconds", name, delay)
        await _sleep_or_stop(run, delay)


async def _probe(run: _Run, ssh: Sequence[str], host: str, valetkey: Sequence[str]) -> Path | None:
    """Ask ``host`` for its runtime directory, trying again with waits until it answers."""
    failures = 0
    while not run.stop.is_set():
        process = await asyncio.create_subprocess_exec(
            *probe_argv(ssh, host, valetkey),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            env=dict(run.environ),
        )
        run.children.add(process)
        try:
            output, _ = await process.communicate()
        finally:
            run.children.discard(process)
        text = output.decode(errors="replace").strip()
        if process.returncode == 0 and text.startswith("/") and "\n" not in text:
            return Path(text)
        logger.warning(
            "%s did not give its runtime directory (status %s)", host, process.returncode
        )
        await _sleep_or_stop(run, backoff(failures, run.draw))
        failures += 1
    return None


def _claim(runtime: Path) -> int:
    """Take the lock that lets one bridge run per runtime directory, or raise."""
    descriptor = os.open(runtime / LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        os.close(descriptor)
        if error.errno in {errno.EWOULDBLOCK, errno.EAGAIN}:
            msg = "another valetkey bridge is already running"
            raise BridgeError(msg) from error
        raise
    return descriptor


async def run_bridge(  # noqa: PLR0913 - the seams the tests replace
    host: str,
    roots: sites.Roots,
    *,
    ssh: Sequence[str] = ("ssh",),
    waypipe: Sequence[str] = ("waypipe",),
    valetkey: Sequence[str] = ("valetkey",),
    remote_runtime: Path | None = None,
    environ: Mapping[str, str] | None = None,
    stop: asyncio.Event | None = None,
    clock: Callable[[], float] = time.monotonic,
    draw: Callable[[], float] = random.random,
    on_connect: Callable[[str], None] | None = None,
) -> None:
    """Run the bridge to ``host`` until ``stop`` is set, and clean up.

    It starts ``waypipe client`` and keeps one ssh connection to ``host``, each restarted with
    :func:`backoff` waits when it ends. ``remote_runtime`` is the server's ``$XDG_RUNTIME_DIR``
    (default: ask the server, which also makes sure its ``valetkey`` directory exists).
    ``ssh``, ``waypipe`` and ``valetkey`` are the commands to run (a program and its leading
    arguments), ``environ`` is the environment of the processes, and ``on_connect`` is told the
    name of each connection's socket. The others are for tests.

    Raises:
        BridgeError: when another bridge runs, or ``host`` is not a host name.
        sites.RuntimeDirUnavailableError: when there is no runtime directory.

    """
    validate_host(host)
    runtime = sites.ensure_runtime(roots)
    local = runtime / LOCAL_SOCKET
    lock = _claim(runtime)
    run = _Run(
        stop or asyncio.Event(),
        environ if environ is not None else os.environ,
        clock,
        draw,
        set(),
    )
    tasks: list[asyncio.Task[None]] = []
    try:
        remote = remote_runtime or await _probe(run, ssh, host, valetkey)
        if remote is None:
            return
        tasks.append(
            asyncio.ensure_future(
                _supervise(
                    run,
                    "waypipe",
                    lambda: waypipe_argv(waypipe, local),
                    lambda: local.unlink(missing_ok=True),
                )
            )
        )

        def connection() -> list[str]:
            rand = secrets.token_hex(8)
            if on_connect is not None:
                on_connect(rand)
            forward = forward_spec(remote / "valetkey" / f"bridge-{rand}.sock", local)
            return ssh_argv(ssh, host, forward, rand, valetkey)

        tasks.append(asyncio.ensure_future(_supervise(run, "ssh", connection)))
        await asyncio.gather(*tasks)
    finally:
        run.stop.set()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.gather(*(_terminate(child) for child in list(run.children)))
        with contextlib.suppress(OSError):
            local.unlink()
        os.close(lock)


def install_stop_signals(stop: asyncio.Event) -> None:
    """Set ``stop`` on SIGTERM, SIGINT and SIGHUP, so a service stop cleans up."""
    loop = asyncio.get_running_loop()
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        loop.add_signal_handler(number, stop.set)


# -- the server's side ---------------------------------------------------------------------------


def socket_of(rand: str, roots: sites.Roots) -> Path:
    """Return the socket the bridge connection named ``rand`` forwards on the server.

    Raises:
        BridgeError: when ``rand`` is not 8 to 64 letters and digits.

    """
    if not _RAND.fullmatch(rand):
        msg = "the connection name must be 8 to 64 letters and digits"
        raise BridgeError(msg)
    return sites.runtime_path(roots) / f"bridge-{rand}.sock"


def _remove_socket(path: Path) -> None:
    """Remove ``path`` if it is a socket of this user. Anything else is left alone."""
    try:
        found = path.lstat()
    except OSError:
        return
    if stat.S_ISSOCK(found.st_mode) and found.st_uid == os.getuid():
        with contextlib.suppress(OSError):
            path.unlink()


async def _end_of_input() -> None:
    """Return when standard input reaches end-of-file: ssh ended the connection."""
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    try:
        await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    except OSError, ValueError:
        return  # standard input cannot be watched, so the connection counts as ended
    while await reader.read(4096):
        pass


async def hold(  # noqa: PLR0913 - the seams the tests replace
    rand: str,
    roots: sites.Roots,
    *,
    link: mcp_server.Bridge | None = None,
    ended: Callable[[], Awaitable[object]] = _end_of_input,
    interval: float = HOLD_INTERVAL,
    socket_wait: float = HOLD_WAIT,
    stop: asyncio.Event | None = None,
) -> int:
    """Hold the bridge ``rand`` registered with valetkeyd until the ssh connection ends.

    Waits for the forwarded socket, then registers it and registers again every ``interval``
    seconds, which keeps the connection to valetkeyd and brings it back after the daemon
    restarted. When ``ended()`` finishes (standard input reached end-of-file, because sshd
    closed the command's input when the connection dropped) or ``stop`` is set, it removes the
    socket, which sshd never does, and returns. The exit status is 1 when the socket never came.

    Raises:
        BridgeError: for a bad ``rand``.

    """
    path = socket_of(rand, roots)
    daemon = link or mcp_server.Bridge()
    over = asyncio.ensure_future(ended())
    halted = asyncio.ensure_future((stop or asyncio.Event()).wait())
    try:
        deadline = time.monotonic() + socket_wait
        while not path.exists():
            if over.done() or halted.done():
                return 0
            if time.monotonic() > deadline:
                sys.stderr.write(f"valetkey bridge-hold: {path} never appeared\n")
                return 1
            await asyncio.sleep(0.05)
        complaint = ""
        while not (over.done() or halted.done()):
            complaint = await _register(daemon, rand, complaint)
            await asyncio.wait(
                {over, halted}, timeout=interval, return_when=asyncio.FIRST_COMPLETED
            )
        return 0
    finally:
        over.cancel()
        halted.cancel()
        _remove_socket(path)
        await daemon.close()


async def _register(daemon: mcp_server.Bridge, rand: str, complaint: str) -> str:
    """Register once; say what went wrong unless it is the same thing as last time."""
    try:
        await daemon.call("bridge_register", rand=rand)
    except DaemonError as error:
        if error.message != complaint:
            sys.stderr.write(f"valetkey bridge-hold: {error.message}\n")
        return error.message
    return ""
