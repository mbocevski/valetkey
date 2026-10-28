# SPDX-License-Identifier: Apache-2.0
"""A throwaway audio server for the tests: PipeWire, its PulseAudio server and WirePlumber.

It stands in for the person's own, with a microphone that plays a tone and a sink that stands for
the desktop's sound. It runs under a short directory of its own, with its own runtime directory,
configuration and state, and every program gets an environment that names only that directory, so
nothing here can reach the real audio server or the real microphone.
"""

import contextlib
import math
import os
import shutil
import signal
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType
    from typing import Self

PROGRAMS = ("pipewire", "pipewire-pulse", "wireplumber", "pactl", "pw-dump", "parec", "pacat")
MICROPHONE = "test_mic"
"""The node that plays the tone and is the default source."""
DESKTOP = "test_desktop"
"""The sink that stands for what the person is listening to."""
TONE_HERTZ = 440
DESKTOP_HERTZ = 960
"""The pitch of what the desktop plays, so that a recording says which of the two it heard."""

_PIPEWIRE = f"""\
context.spa-libs = {{ audiotestsrc = audiotestsrc/libspa-audiotestsrc }}
context.objects = [
    {{ factory = adapter
      args = {{
        factory.name = audiotestsrc
        node.name = {MICROPHONE}
        node.description = "Test microphone"
        media.class = Audio/Source
        object.linger = true
        audio.position = [ FL FR ]
        node.param.Props = {{ frequency = {TONE_HERTZ} volume = 0.5 }}
      }}
    }}
    {{ factory = adapter
      args = {{
        factory.name = support.null-audio-sink
        node.name = {DESKTOP}
        node.description = "Test desktop"
        media.class = Audio/Sink
        object.linger = true
        audio.position = [ FL FR ]
        monitor.channel-volumes = true
      }}
    }}
]
"""
_WIREPLUMBER = """\
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


def missing() -> list[str]:
    """Return the programs the throwaway server needs that are not installed."""
    return [name for name in PROGRAMS if shutil.which(name) is None]


class ThrowawayAudio:
    """Start the server on entering, and stop its programs, by process number, on leaving."""

    def __init__(self) -> None:
        self.base = Path(tempfile.mkdtemp(prefix="vk-audio-", dir="/tmp"))  # short on purpose
        self.runtime = self.base / "rt"
        self._processes: list[subprocess.Popen[bytes]] = []

    @property
    def socket(self) -> Path:
        """The server's PulseAudio socket."""
        return self.runtime / "pulse" / "native"

    @property
    def environment(self) -> dict[str, str]:
        """An environment that names only this server."""
        return {
            "PATH": "/usr/bin",
            "HOME": str(self.base),
            "XDG_RUNTIME_DIR": str(self.runtime),
            "XDG_CONFIG_HOME": str(self.base / "config"),
            "XDG_STATE_HOME": str(self.base / "state"),
            "XDG_CACHE_HOME": str(self.base / "cache"),
            "PIPEWIRE_RUNTIME_DIR": str(self.runtime),
            "PULSE_RUNTIME_PATH": str(self.runtime / "pulse"),
            "PULSE_SERVER": f"unix:{self.socket}",
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path={self.base / 'no-bus'}",
            "LANG": "C.UTF-8",
        }

    def pactl(self, *words: str) -> str:
        """Run ``pactl`` against this server and return its output."""
        result = subprocess.run(  # noqa: S603  # an argument list, no shell
            ["pactl", *words],  # noqa: S607  # from PATH
            capture_output=True,
            text=True,
            check=True,
            timeout=20,
            env=self.environment,
        )
        return result.stdout

    def _spawn(self, *argv: str) -> None:
        log = (self.base / f"{argv[0]}.log").open("ab")
        process = subprocess.Popen(  # noqa: S603  # an argument list, no shell
            argv,
            env=self.environment,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        log.close()
        self._processes.append(process)

    def __enter__(self) -> Self:
        """Start the server and wait until the test microphone is the default source."""
        self.runtime.mkdir(mode=0o700)
        pipewire = self.base / "config" / "pipewire" / "pipewire.conf.d"
        wireplumber = self.base / "config" / "wireplumber" / "wireplumber.conf.d"
        for path in (pipewire, wireplumber):
            path.mkdir(parents=True)
        (pipewire / "10-test.conf").write_text(_PIPEWIRE, encoding="utf-8")
        (wireplumber / "10-test.conf").write_text(_WIREPLUMBER, encoding="utf-8")
        try:
            self._spawn("pipewire")
            self._wait_for((self.runtime / "pipewire-0").exists)
            self._spawn("pipewire-pulse")
            self._spawn("wireplumber")
            self._wait_for(lambda: f"Default Source: {MICROPHONE}" in self.pactl("info"))
            self._play_on_the_desktop()
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def _play_on_the_desktop(self) -> None:
        """Play a tone into the desktop's sink, as a program the person listens to would."""
        player = subprocess.Popen(  # noqa: S603  # an argument list, no shell
            [  # noqa: S607  # from PATH
                "pacat",
                "--playback",
                f"--device={DESKTOP}",
                "--format=s16le",
                "--rate=48000",
                "--channels=2",
                "--raw",
            ],
            env=self.environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self._processes.append(player)
        second = b"".join(
            struct.pack("<hh", value, value)
            for value in (
                int(12000 * math.sin(2 * math.pi * DESKTOP_HERTZ * n / 48000)) for n in range(48000)
            )
        )

        def feed() -> None:
            assert player.stdin is not None
            with contextlib.suppress(OSError):
                while True:
                    player.stdin.write(second)
                    player.stdin.flush()

        threading.Thread(target=feed, daemon=True).start()

    def _wait_for(self, ready: Callable[[], object]) -> None:
        deadline = time.monotonic() + 30
        while True:
            with contextlib.suppress(OSError, subprocess.SubprocessError):
                if ready():
                    return
            if time.monotonic() > deadline:
                logs = {p.name: p.read_text()[-500:] for p in self.base.glob("*.log")}
                message = f"the throwaway audio server did not come up: {logs}"
                raise RuntimeError(message)
            time.sleep(0.1)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Stop the programs and remove the directory."""
        for process in reversed(self._processes):
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
        for process in self._processes:
            if process.stdin is not None:
                with contextlib.suppress(OSError, ValueError):
                    process.stdin.close()
            try:
                process.wait(5)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        shutil.rmtree(self.base, ignore_errors=True)
