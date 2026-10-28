# SPDX-License-Identifier: Apache-2.0
"""A private audio graph for one browser session: the microphone, and nothing else.

Binding the person's own audio socket into the sandbox would let the browser record what the
person plays, change their devices and load modules (one of which opens a listening port on the
host). So a session with the microphone on gets an audio server of its own: PipeWire and
WirePlumber, started by valetkey inside a bubblewrap jail with no network, a read-only ``/usr`` and
two directories: its own, and the person's pulse socket, the only way to the microphone.

The graph holds two nodes. ``vk_mic`` is a source that pulls from the person's default source
over that socket (``libpipewire-module-pulse-tunnel``), and ``vk_out`` is a null sink for the
audio of the call. The PulseAudio protocol runs inside the PipeWire daemon with module loading
off, and its socket is the only thing the browser's sandbox gets. A browser, and anything that
has taken it over, sees two nodes: it cannot list the person's devices or applications, record
what they play, change a default, or load a module.

The jail has a PID namespace of its own, as the browser's sandbox does. It sees only its own
processes, and a program in it cannot signal one of the person's.

Everything the jail starts lives as long as the supervisor script that runs first. That script
stops them when the pipe it reads from is closed, which is what happens when valetkey dies, and
:meth:`AudioGraph.close` stops the whole process group besides.
"""

import contextlib
import ipaddress
import json
import os
import shlex
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from valetkey import sandbox, seccomp, sites

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

SOURCE_NODE = "vk_mic"
SINK_NODE = "vk_out"
CAPTURE_CLASS = "Stream/Input/Audio"
"""The class of the node a program that records makes in the graph."""
PROGRAMS = ("bwrap", "pipewire", "wireplumber", "pw-dump", "pactl")
"""What a session with the microphone on runs: the jail, the graph and the two tools that ask it."""
START_TIMEOUT = 20.0
"""Seconds the graph has to come up: the socket answers and the microphone is the default source."""
STOP_GRACE = 5.0
"""Seconds the graph gets to end on its own, once told to, before the group is killed."""
ASK_TIMEOUT = 10.0
"""Seconds one question to the graph (or to the person's server) may take."""
RESET_TIMEOUT = 5.0
"""Seconds to look for the stream that carries the microphone, to unmute it and set its volume."""
MAX_SOCKET_PATH = 100
"""The longest path a unix socket may have, with some room under the kernel's limit of 107."""
_LOG_TAIL = 1500
_TAG = "valetkey.session"
"""The property that marks the stream that the graph opens on the person's server."""

PIPEWIRE_CONFIG = """\
context.modules = [
    {{ name = libpipewire-module-pulse-tunnel
      args = {{
        tunnel.mode = source
        pulse.server.address = "unix:{upstream}"
        pulse.latency = 100{target}
        audio.position = [ FL FR ]
        node.name = {source}
        node.description = "Microphone"
      }}
    }}
    {{ name = libpipewire-module-protocol-pulse
      args = {{
        pulse.allow-module-loading = false
        server.address = [ {{ address = "unix:native" client.access = "restricted" }} ]
      }}
    }}
]
context.objects = [
    {{ factory = adapter
      args = {{
        factory.name = support.null-audio-sink
        node.name = {sink}
        node.description = "Call audio"
        media.class = Audio/Sink
        object.linger = true
        audio.position = [ FL FR ]
        monitor.channel-volumes = true
        monitor.passthrough = true
      }}
    }}
]
"""
"""The graph, as a drop-in for PipeWire's defaults."""

WIREPLUMBER_CONFIG = """\
wireplumber.profiles = {
  main = {
    monitor.alsa = disabled
    monitor.alsa-midi = disabled
    monitor.bluez = disabled
    monitor.bluez-midi = disabled
    monitor.libcamera = disabled
    monitor.v4l2 = disabled
  }
}
"""
"""WirePlumber without a single device monitor, so nothing of the machine's hardware appears."""

SUPERVISOR = """\
pipewire & graph=$!
until [ -S "$XDG_RUNTIME_DIR/pipewire-0" ]; do
  kill -0 "$graph" 2>/dev/null || exit 1
  sleep 0.05
done
wireplumber & manager=$!
while kill -0 "$graph" 2>/dev/null && kill -0 "$manager" 2>/dev/null; do
  read -r -t 1 _
  [ "$?" -gt 128 ] || break
done
kill "$graph" "$manager" 2>/dev/null
wait
"""
"""The first command in the jail: PipeWire, then WirePlumber once the socket exists. It ends both
when either is gone, and when its standard input is closed, which is how a dead valetkey shows."""


class AudioError(RuntimeError):
    """The private graph could not be started or asked."""


class MissingSourceError(AudioError):
    """The source the person named for the microphone is not on their audio server."""

    def __init__(self, source: str) -> None:
        """Remember ``source``, the name that was not found."""
        super().__init__(f'microphone source "{source}" does not exist on your audio server')
        self.source = source


def source_names(upstream: Path) -> list[str]:
    """Return the names of the sources on the person's audio server, which include monitors.

    Raises:
        AudioError: when the server cannot be asked.

    """
    listing = _ask([*_server_args(upstream), "list", "short", "sources"])
    return [line.split("\t")[1] for line in listing.splitlines() if line.count("\t") >= 1]


def upstream_socket(runtime: Path) -> Path:
    """Return the person's pulse socket, which the graph pulls the microphone from."""
    return runtime / "pulse" / "native"


def capture_urls(policy: sites.Policy) -> list[str]:
    """Return the origins that may record the microphone in a session of ``policy``'s site.

    That is the start page's origin as it is written, and the registrable domain of the start
    host with its subdomains, over HTTPS. No other host the site may reach is in it, so a sign-in
    provider, a CDN or a frame from a third party cannot record without a prompt. A start host that
    is an address, or that has no registrable domain, gets only its origin. It goes into
    Chrome's ``AudioCaptureAllowedUrls``, so that exactly these origins are allowed to record
    without a prompt, which a browser nobody sees could not answer.
    """
    start = urlsplit(policy.start)
    urls = [f"{start.scheme}://{start.netloc}"]
    host = start.hostname or ""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        with contextlib.suppress(ValueError, sites.SuffixListError):
            urls.append(f"https://[*.]{sites.registrable_domain(host)}")
    return urls


def missing_programs(which: Callable[[str], str | None] = shutil.which) -> list[str]:
    """Return the programs of :data:`PROGRAMS` that are not installed."""
    return [name for name in PROGRAMS if which(name) is None]


def write_config(directory: Path, upstream: Path, source: str | None = None) -> None:
    """Write the graph's configuration under ``directory``, which must exist.

    The microphone copies the person's default source, or ``source`` when one is named. The name
    is checked with :func:`valetkey.sites.validate_source` first, which keeps it safe to write.
    """
    target = (
        "" if source is None else f'\n        target.object = "{sites.validate_source(source)}"'
    )
    pipewire = directory / "config" / "pipewire" / "pipewire.conf.d"
    wireplumber = directory / "config" / "wireplumber" / "wireplumber.conf.d"
    for path in (pipewire, wireplumber):
        path.mkdir(parents=True, exist_ok=True)
    (pipewire / "10-valetkey.conf").write_text(
        PIPEWIRE_CONFIG.format(
            upstream=upstream, source=SOURCE_NODE, sink=SINK_NODE, target=target
        ),
        encoding="utf-8",
    )
    (wireplumber / "10-valetkey.conf").write_text(WIREPLUMBER_CONFIG, encoding="utf-8")


def jail_argv(
    directory: Path,
    upstream: Path,
    tag: str,
    seccomp_fd: int | None = None,
    *,
    system_links: list[str] | None = None,
) -> list[str]:
    """Return the ``bwrap`` command line that runs the graph.

    ``directory`` is the graph's own directory, bound read-write at the same path inside, and
    ``upstream`` the person's pulse socket, bound too. ``tag`` marks the stream the graph opens on
    the person's server, so that it can be found there. Nothing else of the host is visible: no
    network, no devices, no home directory, no session bus, no process. Every namespace is
    unshared, the PID namespace too. ``--die-with-parent`` is left out on purpose: it follows the
    thread that started the jail, and the supervisor's pipe already ends the graph with the daemon.
    """
    argv = ["bwrap", "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-net"]
    argv += ["--unshare-uts"]
    argv += ["--unshare-cgroup", "--new-session", "--hostname", "valetkey-audio"]
    if seccomp_fd is not None:
        argv += ["--seccomp", str(seccomp_fd)]
    argv += ["--ro-bind", "/usr", "/usr"]
    argv += system_links if system_links is not None else sandbox.system_link_args()
    argv += ["--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache"]
    argv += ["--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"]  # noqa: S108  # in the jail
    argv += ["--bind", str(directory), str(directory), "--bind", str(upstream), str(upstream)]
    environment = {
        "PATH": "/usr/bin",
        "HOME": str(directory),
        "XDG_RUNTIME_DIR": str(directory),
        "XDG_CONFIG_HOME": str(directory / "config"),
        "XDG_STATE_HOME": str(directory / "state"),
        "XDG_CACHE_HOME": str(directory / "cache"),
        "PIPEWIRE_RUNTIME_DIR": str(directory),
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={directory / 'no-bus'}",
        "LANG": "C.UTF-8",
        # What the graph's one pulse client, the tunnel, says about itself to the person's server.
        "PULSE_PROP_OVERRIDE_application.name": "valetkey-microphone",
        f"PULSE_PROP_OVERRIDE_{_TAG}": tag,
    }
    argv += ["--clearenv"]
    for name, value in environment.items():
        argv += ["--setenv", name, value]
    return [*argv, "--chdir", str(directory), "/usr/bin/bash", "-c", SUPERVISOR]


def _server_args(socket: Path) -> list[str]:
    return ["pactl", "--server", f"unix:{socket}"]


def _ask(argv: Sequence[str], environment: dict[str, str] | None = None) -> str:
    """Run ``argv`` and return what it printed.

    Raises:
        AudioError: when it cannot run, fails, or takes longer than :data:`ASK_TIMEOUT`.

    """
    try:
        result = subprocess.run(  # noqa: S603  # an argument list built here, no shell
            list(argv),
            capture_output=True,
            text=True,
            check=True,
            timeout=ASK_TIMEOUT,
            stdin=subprocess.DEVNULL,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as error:
        message = f"{shlex.join(argv[:3])}: {error}"
        raise AudioError(message) from error
    return result.stdout


def reset_stream(upstream: Path, tag: str) -> bool:
    """Take the mute off the stream with ``tag`` on the person's server and set it to full volume.

    Tells whether the stream was found. PipeWire remembers the volume and mute of a stream by the
    name of the program that opened it, and the tunnel is always the same program. A client of the
    graph can set the volume and mute of ``vk_mic``, which the tunnel passes on to this stream, so
    a stream left muted or turned down would start so every time, and the microphone would arrive
    silent. Only this stream is touched, never another one or a device.
    """
    listing = _ask([*_server_args(upstream), "list", "source-outputs"])
    for block in listing.split("Source Output #")[1:]:
        if f'{_TAG} = "{tag}"' in block:
            number = block.split("\n", 1)[0].strip()
            _ask([*_server_args(upstream), "set-source-output-mute", number, "0"])
            _ask([*_server_args(upstream), "set-source-output-volume", number, "100%"])
            return True
    return False


@dataclass(slots=True)
class AudioGraph:
    """A running private graph. Create it with :meth:`start`; end it with :meth:`close`."""

    directory: Path
    upstream: Path
    process: subprocess.Popen[bytes]
    tag: str
    source: str | None = None
    """The source on the person's server that the microphone copies; ``None`` is the default."""

    @property
    def socket(self) -> Path:
        """The graph's PulseAudio socket, the only thing the browser's sandbox gets."""
        return self.directory / "pulse" / "native"

    @property
    def log_file(self) -> Path:
        """Where the graph's programs write."""
        return self.directory / "audio.log"

    @classmethod
    def start(  # noqa: PLR0913  # each is a distinct thing the caller decides
        cls,
        directory: Path,
        upstream: Path,
        tag: str,
        *,
        source: str | None = None,
        timeout: float = START_TIMEOUT,
        argv: Callable[[Path, Path, str, int | None], list[str]] = jail_argv,
    ) -> AudioGraph:
        """Start the graph under ``directory`` and return it once the microphone is its default.

        ``directory`` must be short, because a socket's path is limited to about a hundred bytes,
        and ``tag`` unique among the graphs that ever ran against the person's server: a stream
        left over from a graph that has just ended must not be taken for this one's. ``argv``
        builds the command. ``source`` names the source the microphone copies instead of the
        default one. It must exist, and nothing is started when it does not: there is no falling
        back to the default, which would hear something else than the person asked for.

        Raises:
            MissingSourceError: when ``source`` is not on the person's audio server.
            AudioError: when the graph does not come up in ``timeout`` seconds, or ends meanwhile.
                The message ends with the graph's log.

        """
        if len(str(directory / "pulse" / "native")) > MAX_SOCKET_PATH:
            message = f"{directory} is too long for the graph's socket"
            raise AudioError(message)
        if source is not None and source not in source_names(upstream):
            raise MissingSourceError(source)
        shutil.rmtree(directory, ignore_errors=True)  # what a graph that was killed left behind
        directory.mkdir(parents=True, mode=0o700)
        write_config(directory, upstream, source)
        filter_fd = seccomp.open_filter()
        try:
            with (directory / "audio.log").open("ab") as log:
                process = subprocess.Popen(  # noqa: S603  # argument list, no shell
                    argv(directory, upstream, tag, filter_fd),
                    stdin=subprocess.PIPE,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    pass_fds=() if filter_fd is None else (filter_fd,),
                    start_new_session=True,
                )
        finally:
            if filter_fd is not None:
                os.close(filter_fd)
        graph = cls(directory, upstream, process, tag, source)
        try:
            graph._await_ready(timeout)
        except BaseException:
            graph.close()
            raise
        return graph

    def _await_ready(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while True:
            if self.process.poll() is not None:
                message = f"the audio graph ended at start\n{self.log_tail()}"
                raise AudioError(message)
            if self.socket.exists() and self._default_source() == SOURCE_NODE:
                break
            if time.monotonic() > deadline:
                message = (
                    f"the audio graph was not ready after {timeout:g} seconds\n{self.log_tail()}"
                )
                raise AudioError(message)
            time.sleep(0.05)
        self._reset(deadline=time.monotonic() + RESET_TIMEOUT)

    def _default_source(self) -> str | None:
        try:
            info = _ask([*_server_args(self.socket), "info"])
        except AudioError:
            return None
        for line in info.splitlines():
            if line.startswith("Default Source:"):
                return line.partition(":")[2].strip()
        return None

    def _reset(self, *, deadline: float) -> None:
        """Take the mute off the graph's stream on the person's server and set its volume."""
        while time.monotonic() < deadline:
            try:
                if reset_stream(self.upstream, self.tag):
                    return
            except AudioError:
                pass
            time.sleep(0.1)

    def log_tail(self) -> str:
        """Return the end of the graph's log."""
        try:
            return self.log_file.read_text(errors="replace")[-_LOG_TAIL:]
        except OSError:
            return ""

    def is_alive(self) -> bool:
        """Tell whether the graph's supervisor still runs."""
        return self.process.poll() is None

    def capture_nodes(self) -> list[int]:
        """Return the numbers of the nodes of programs that record in the graph, oldest first.

        The graph has nobody but the browser to record, so these are the browser's capture streams.

        Raises:
            AudioError: when the graph cannot be asked.

        """
        dump = _ask(
            ["pw-dump"],
            {"PATH": "/usr/bin", "XDG_RUNTIME_DIR": str(self.directory)}
            | {"PIPEWIRE_RUNTIME_DIR": str(self.directory)},
        )
        try:
            objects = json.loads(dump)
            found = [
                int(item["id"])
                for item in objects
                if item.get("type") == "PipeWire:Interface:Node"
                and item.get("info", {}).get("props", {}).get("media.class") == CAPTURE_CLASS
            ]
        except (ValueError, KeyError, TypeError, AttributeError) as error:
            message = f"pw-dump printed something else than the graph: {error}"
            raise AudioError(message) from error
        return sorted(found)

    def capture_stream(self) -> dict[str, object]:
        """Describe where a recorder finds the browser's capture stream.

        ``source`` is the source the microphone copies (``None`` for the person's default),
        ``socket`` is the graph's PulseAudio socket and ``node`` the number of the capture node
        (the oldest, when the browser records twice), or ``None`` while nothing records or when the
        graph cannot be asked. The graph's PipeWire socket is in ``directory``.
        """
        try:
            nodes = self.capture_nodes()
        except AudioError:
            nodes = []
        return {
            "socket": str(self.socket),
            "node": nodes[0] if nodes else None,
            "directory": str(self.directory),
            "source": self.source,
        }

    def close(self) -> None:
        """End the graph: ask the supervisor to stop it, then kill the group. Safe to call twice."""
        process = self.process
        if process.stdin is not None:
            with contextlib.suppress(OSError):
                process.stdin.close()
        try:
            process.wait(STOP_GRACE)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
