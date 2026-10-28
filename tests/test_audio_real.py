# SPDX-License-Identifier: Apache-2.0
"""The private audio graph and the microphone, against a throwaway audio server.

The server is PipeWire's own, started under a short temporary directory with a test microphone
that plays a tone, and a sink that stands for the desktop's sound. The real audio server and the
real microphone are never reached. The sessions are real ones: a contained Chromium with the
graph's socket as its only audio.
"""

import asyncio
import contextlib
import itertools
import math
import os
import select
import signal
import struct
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
import throwaway_audio
from environment import processes_with, unusable_reason
from proxy_stub import PageServer, ProxyStub
from test_cli_daemon import local_proxy_options
from test_daemon import Rig, run, serving

from valetkey import audio, sessions, sites
from valetkey.client import DaemonError

if TYPE_CHECKING:
    from collections.abc import Iterator

_REASON = unusable_reason("bwrap", *throwaway_audio.PROGRAMS)
needs_audio = pytest.mark.skipif(_REASON is not None, reason=_REASON or "")
_BROWSER_REASON = unusable_reason("bwrap", "chromium", "agent-browser", *throwaway_audio.PROGRAMS)
needs_browser = pytest.mark.skipif(_BROWSER_REASON is not None, reason=_BROWSER_REASON or "")


@pytest.fixture
def server() -> Iterator[throwaway_audio.ThrowawayAudio]:
    with throwaway_audio.ThrowawayAudio() as started:
        yield started


def under(directory: Path) -> list[int]:
    """The processes whose runtime directory is ``directory``: what a graph there started."""
    wanted = f"XDG_RUNTIME_DIR={directory}".encode()
    found = []
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            with contextlib.suppress(OSError):
                if wanted in (entry / "environ").read_bytes().split(b"\0"):
                    found.append(int(entry.name))
    return found


def wait_until(check: Any, limit: float = 20) -> None:  # noqa: ANN401
    deadline = time.monotonic() + limit
    while not check():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.05)


def tone(raw: bytes) -> tuple[float, float]:
    """Return the level (RMS, 0 to 1) and pitch (Hz) of 48 kHz stereo 16-bit samples."""
    samples = struct.unpack(f"<{len(raw) // 2}h", raw[: len(raw) // 2 * 2])[::2]
    if not samples:
        return 0.0, 0.0
    level = math.sqrt(sum(s * s for s in samples) / len(samples)) / 32768
    crossings = sum(1 for a, b in itertools.pairwise(samples) if a < 0 <= b)
    return level, crossings / (len(samples) / 48000)


def record(socket: Path, device: str = "@DEFAULT_SOURCE@", seconds: float = 2.0) -> bytes:
    """Record from the server at ``socket`` for ``seconds``, as a client inside the browser can."""
    process = subprocess.Popen(  # noqa: S603  # an argument list, no shell
        [  # noqa: S607  # from PATH
            "parec",
            f"--server=unix:{socket}",
            f"--device={device}",
            "--format=s16le",
            "--rate=48000",
            "--channels=2",
            "--latency-msec=20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    assert process.stdout is not None
    data = b""
    deadline = time.monotonic() + seconds
    try:
        while (left := deadline - time.monotonic()) > 0:
            if select.select([process.stdout], [], [], left)[0]:
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:  # the device is not there
                    break
                data += chunk
    finally:
        process.terminate()
        process.wait()
        process.stdout.close()
    return data


def pactl(socket: Path, *words: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603  # an argument list, no shell
        ["pactl", f"--server=unix:{socket}", *words],  # noqa: S607  # from PATH
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def names(socket: Path, kind: str) -> list[str]:
    listing = pactl(socket, "list", "short", kind).stdout
    return sorted(line.split("\t")[1] for line in listing.splitlines())


@pytest.fixture
def graph(
    server: throwaway_audio.ThrowawayAudio,
) -> Iterator[tuple[throwaway_audio.ThrowawayAudio, audio.AudioGraph]]:
    started = audio.AudioGraph.start(server.base / "g", server.socket, "demo")
    try:
        yield server, started
    finally:
        started.close()


# -- the graph ----------------------------------------------------------------------------


@pytest.mark.integration
@needs_audio
def test_the_graph_carries_the_microphone_and_a_silent_output_and_nothing_else(
    graph: tuple[throwaway_audio.ThrowawayAudio, audio.AudioGraph],
) -> None:
    server, started = graph
    private = started.socket
    # It holds the two nodes it was given. The person's microphone, speakers and desktop sound
    # are not there to be listed.
    assert names(private, "sources") == ["vk_out.monitor", "vk_mic"] or names(
        private, "sources"
    ) == [
        "vk_mic",
        "vk_out.monitor",
    ]
    assert names(private, "sinks") == ["vk_out"]
    assert names(private, "sink-inputs") == []
    assert pactl(private, "info").stdout.count("Default Source: vk_mic") == 1
    # The person's microphone reaches it, as the tone the test microphone plays.
    level, pitch = tone(record(private))
    assert level > 0.05
    assert abs(pitch - throwaway_audio.TONE_HERTZ) < 40
    # What the desktop plays is not in the graph, whatever name a client tries: a device the
    # graph does not have gives nothing, or the default one, which is the microphone.
    heard = tone(record(server.socket, f"{throwaway_audio.DESKTOP}.monitor", 1.0))
    assert abs(heard[1] - throwaway_audio.DESKTOP_HERTZ) < 60  # the stand-in does play it
    for device in (f"{throwaway_audio.DESKTOP}.monitor", throwaway_audio.MICROPHONE):
        _level, pitch = tone(record(private, device, 1.0))
        assert pitch == 0.0 or abs(pitch - throwaway_audio.TONE_HERTZ) < 40, device
    assert server.pactl("info").count(f"Default Source: {throwaway_audio.MICROPHONE}") == 1


@pytest.mark.integration
@needs_audio
def test_a_client_of_the_graph_cannot_load_a_module_or_change_a_default(
    graph: tuple[throwaway_audio.ThrowawayAudio, audio.AudioGraph],
) -> None:
    server, started = graph
    private = started.socket
    before = (server.pactl("list", "short", "modules"), server.pactl("list", "short", "sinks"))
    for module in ("module-null-sink", "module-native-protocol-tcp", "module-loopback"):
        refused = pactl(private, "load-module", module)
        assert refused.returncode != 0, module
        assert "Access denied" in refused.stderr or "Failure" in refused.stderr
    pactl(private, "set-default-source", "vk_out.monitor")
    assert "Default Source: vk_mic" in pactl(private, "info").stdout
    # Neither the private server nor the person's one gained a module or a sink.
    after = (server.pactl("list", "short", "modules"), server.pactl("list", "short", "sinks"))
    assert after == before
    assert names(private, "sinks") == ["vk_out"]
    # A client cannot end another program's connection to the person's server: it sees none.
    other_clients = pactl(private, "list", "short", "clients").stdout.splitlines()
    for line in other_clients:
        pactl(private, "kill-client", line.split("\t")[0])
    assert "Default Source: vk_mic" in pactl(private, "info").stdout
    assert tone(record(private))[0] > 0.05


@pytest.mark.integration
@needs_audio
def test_a_microphone_muted_on_the_persons_server_is_unmuted_for_the_next_graph(
    server: throwaway_audio.ThrowawayAudio,
) -> None:
    directory = server.base / "g"
    first = audio.AudioGraph.start(directory, server.socket, "first")
    stream = server.pactl("list", "short", "source-outputs").split()[0]
    server.pactl("set-source-output-mute", stream, "1")  # as saved state would
    assert "Mute: yes" in server.pactl("list", "source-outputs")
    first.close()
    second = audio.AudioGraph.start(directory, server.socket, "second")
    try:
        assert "Mute: yes" not in server.pactl("list", "source-outputs")
        assert tone(record(second.socket))[0] > 0.05
    finally:
        second.close()


@pytest.mark.integration
@needs_audio
def test_a_volume_and_mute_a_client_left_on_the_microphone_do_not_reach_the_next_graph(
    server: throwaway_audio.ThrowawayAudio,
) -> None:
    directory = server.base / "g"
    first = audio.AudioGraph.start(directory, server.socket, "first")
    # What a page can do through the graph's socket; the tunnel passes it to the stream on the
    # person's server, where WirePlumber saves it under the tunnel's application id.
    assert pactl(first.socket, "set-source-volume", "vk_mic", "0%").returncode == 0
    assert pactl(first.socket, "set-source-mute", "vk_mic", "1").returncode == 0
    first.close()
    second = audio.AudioGraph.start(directory, server.socket, "second")
    try:
        stream = server.pactl("list", "source-outputs")
        assert "Mute: no" in stream
        assert "100%" in stream.split("Volume:")[1].splitlines()[0]
        assert tone(record(second.socket))[0] > 0.05
    finally:
        second.close()


@pytest.mark.integration
@needs_audio
def test_a_recorder_finds_the_capture_stream_by_the_socket_and_the_node(
    graph: tuple[throwaway_audio.ThrowawayAudio, audio.AudioGraph],
) -> None:
    _server, started = graph
    assert started.capture_stream()["node"] is None  # nothing records yet
    recorder = subprocess.Popen(  # noqa: S603  # an argument list, no shell
        [  # noqa: S607  # from PATH
            "parec",
            f"--server=unix:{started.socket}",
            "--format=s16le",
            "--rate=48000",
            "--channels=2",
        ],
        stdout=subprocess.DEVNULL,
    )
    try:
        wait_until(lambda: started.capture_stream()["node"] is not None)
        found = started.capture_stream()
        assert found["socket"] == str(started.socket)
        assert isinstance(found["node"], int)
        # The node is the one PipeWire shows for that program, on the graph's own socket.
        dump = subprocess.run(  # noqa: S603  # an argument list, no shell
            ["pw-dump", str(found["node"])],  # noqa: S607  # from PATH
            env={"PATH": "/usr/bin", "PIPEWIRE_RUNTIME_DIR": str(found["directory"])},
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        assert "Stream/Input/Audio" in dump.stdout
    finally:
        recorder.terminate()
        recorder.wait()
    wait_until(lambda: started.capture_stream()["node"] is None)


@pytest.mark.integration
@needs_audio
def test_the_graph_runs_in_a_jail_and_ends_whole(
    server: throwaway_audio.ThrowawayAudio,
) -> None:
    started = audio.AudioGraph.start(server.base / "g", server.socket, "demo")
    inside = under(started.directory)
    assert len(inside) >= 3  # the supervisor, the graph and its manager
    mine = Path("/proc/self/ns")
    for pid in inside:
        namespaces = Path(f"/proc/{pid}/ns")
        if namespaces.joinpath("net").readlink() == mine.joinpath("net").readlink():
            continue  # bubblewrap's own helper, before it enters the jail
        for kind in ("net", "ipc", "uts", "user"):
            assert namespaces.joinpath(kind).readlink() != mine.joinpath(kind).readlink(), kind
        assert namespaces.joinpath("pid").readlink() != mine.joinpath("pid").readlink()
    started.close()
    wait_until(lambda: under(started.directory) == [])


@pytest.mark.integration
@needs_audio
def test_a_program_in_the_jail_sees_and_signals_none_of_the_persons_processes(
    tmp_path: Path,
) -> None:
    victim = subprocess.Popen(["sleep", "60"])  # noqa: S607  # from PATH
    (tmp_path / "up").touch()
    probe = (
        "ls /proc | grep -c '^[0-9]'; "
        f"kill -0 {victim.pid} 2>/dev/null && echo signalled || echo unreachable"
    )
    argv = audio.jail_argv(tmp_path, tmp_path / "up", "demo")
    argv[-1] = probe
    try:
        ran = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=30)  # noqa: S603
        count, outcome = ran.stdout.split("\n")[:2]
        assert int(count) < 20  # the jail's own, not the machine's
        assert outcome == "unreachable"
        assert victim.poll() is None  # it was not touched
    finally:
        victim.kill()
        victim.wait()


@pytest.mark.integration
@needs_audio
def test_the_graph_ends_when_valetkey_goes_away_without_closing_it(
    server: throwaway_audio.ThrowawayAudio,
) -> None:
    started = audio.AudioGraph.start(server.base / "g", server.socket, "demo")
    assert under(started.directory)
    assert started.process.stdin is not None
    started.process.stdin.close()  # what the death of the daemon does to the pipe
    wait_until(lambda: under(started.directory) == [])
    started.close()


@pytest.mark.integration
@needs_audio
def test_the_graph_ends_when_one_of_its_programs_is_killed(
    server: throwaway_audio.ThrowawayAudio,
) -> None:
    started = audio.AudioGraph.start(server.base / "g", server.socket, "demo")
    manager = next(
        pid
        for pid in under(started.directory)
        if Path(f"/proc/{pid}/comm").read_text().strip() == "wireplumber"
    )
    os.kill(manager, signal.SIGKILL)
    wait_until(lambda: not started.is_alive())
    started.close()
    wait_until(lambda: under(started.directory) == [])


# -- the sessions ---------------------------------------------------------------------------

# Chrome offers the microphone to a secure context only; a plain HTTP page on localhost is one.
RECORDING_PAGE = """
<title>idle</title>
<script>
async function listen() {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({audio: true});
    const context = new AudioContext();
    await context.resume();
    const analyser = context.createAnalyser();
    context.createMediaStreamSource(stream).connect(analyser);
    const samples = new Float32Array(analyser.fftSize);
    let loudest = 0;
    const started = performance.now();
    const timer = setInterval(() => {
      analyser.getFloatTimeDomainData(samples);
      let sum = 0;
      for (const value of samples) sum += value * value;
      loudest = Math.max(loudest, Math.sqrt(sum / samples.length));
      if (performance.now() - started > 3000) {
        clearInterval(timer);
        document.title = 'level:' + loudest.toFixed(3);
      }
    }, 50);
    document.title = 'recording';
  } catch (error) {
    document.title = 'error:' + error.name;
  }
}
listen();
</script>
<p>a call</p>
"""
PAGES = {"/": RECORDING_PAGE}
QUIET_PAGES = {**PAGES, "/quiet": "<title>quiet</title><p>no call</p>"}


def site_roots(server: throwaway_audio.ThrowawayAudio) -> sites.Roots:
    """Roots whose runtime directory is the throwaway server's, and so is its socket."""
    return sites.Roots(server.base / "cfg", server.base / "state", server.runtime)


def save_site(roots: sites.Roots, *, microphone: bool, source: str | None = None) -> None:
    sites.save_policy(
        roots,
        sites.Policy(
            "demo",
            "http://localhost/",
            ("localhost",),
            microphone=microphone,
            microphone_source=source,
        ),
    )


def title_after(session: sessions.Session, prefix: str, limit: float = 30) -> str:
    deadline = time.monotonic() + limit
    while not (title := session.title()).startswith(prefix):
        assert time.monotonic() < deadline, f"the title stayed {title!r}"
        time.sleep(0.2)
    return title


@pytest.mark.integration
@needs_browser
def test_a_session_with_the_microphone_records_and_one_without_cannot(
    server: throwaway_audio.ThrowawayAudio,
) -> None:
    roots = site_roots(server)
    paths = sessions.session_paths(roots, "demo")
    paths.proxy_socket.parent.mkdir(parents=True)
    with PageServer(PAGES) as pages, ProxyStub(paths.proxy_socket, pages.address):
        # Off: the browser has no audio device at all, and the request is turned down.
        save_site(roots, microphone=False)
        with sessions.Session.start(roots, "demo", "http://localhost/", timeout=60) as silent:
            assert silent.capture_stream() is None
            assert title_after(silent, "error:") == "error:NotFoundError"
            assert not paths.audio_dir.exists()
        # On: the same page records the test microphone's tone.
        save_site(roots, microphone=True)
        session = sessions.Session.start(
            roots, "demo", "http://localhost/", timeout=60, microphone=True
        )
        try:
            capture = session.capture_stream()
            assert capture is not None
            assert capture["directory"] == str(paths.audio_dir)
            wait_until(lambda: (session.capture_stream() or {}).get("node") is not None)
            level = float(title_after(session, "level:").removeprefix("level:"))
            assert level > 0.05
            # The jail is there while the session runs, and gone with it.
            assert under(paths.audio_dir)
        finally:
            session.close()
        wait_until(lambda: under(paths.audio_dir) == [])
        assert not paths.audio_dir.exists()


def build_daemon_rig(
    server: throwaway_audio.ThrowawayAudio,
    pages: PageServer,
    source: str | None = None,
    **options: float,
) -> tuple[sites.Roots, contextlib.AbstractAsyncContextManager[Rig]]:
    roots = site_roots(server)
    save_site(roots, microphone=True, source=source)
    return roots, serving(
        roots,
        session_factory=None,
        proxy_options=local_proxy_options(pages.address),
        poll_interval=0.2,
        **options,
    )


def graph_directory(roots: sites.Roots) -> Path:
    return sessions.session_paths(roots, "demo").audio_dir


@pytest.mark.integration
@needs_browser
def test_the_jail_is_gone_after_an_idle_close(server: throwaway_audio.ThrowawayAudio) -> None:
    async def scenario(
        roots: sites.Roots, rig_context: contextlib.AbstractAsyncContextManager[Rig]
    ) -> None:
        async with rig_context as rig, await rig.connect() as c:
            await c.call("open", site="demo")
            assert under(graph_directory(roots))
            (entry,) = (await c.call("status"))["sessions"]
            assert entry["microphone"] is True
            assert entry["capture"]["directory"] == str(graph_directory(roots))
            # A recording keeps the session open, so the page stops before the limit counts.
            await c.call("navigate", site="demo", url="http://localhost/quiet")
            for _ in range(200):  # the idle limit is a few seconds
                if not (await c.call("status"))["sessions"]:
                    break
                await asyncio.sleep(0.1)
            assert (await c.call("status"))["sessions"] == []
            for _ in range(100):
                if not under(graph_directory(roots)):
                    break
                await asyncio.sleep(0.1)
            assert under(graph_directory(roots)) == []
            assert not graph_directory(roots).exists()

    with PageServer(QUIET_PAGES) as pages:
        roots, rig_context = build_daemon_rig(server, pages, idle_limit=3.0)
        run(scenario(roots, rig_context))


@pytest.mark.integration
@needs_browser
def test_a_session_that_records_outlives_the_idle_limit_and_closes_after_it_stops(
    server: throwaway_audio.ThrowawayAudio,
) -> None:
    limit = 3.0

    async def scenario(
        rig_context: contextlib.AbstractAsyncContextManager[Rig],
    ) -> None:
        async with rig_context as rig, await rig.connect() as c:
            await c.call("open", site="demo")
            for _ in range(200):
                (entry,) = (await c.call("status"))["sessions"]
                if entry["capture"]["node"] is not None:
                    break
                await asyncio.sleep(0.1)
            assert entry["capture"]["node"] is not None
            await asyncio.sleep(limit * 2)  # twice the limit with no call that uses the site
            (entry,) = (await c.call("status"))["sessions"]
            assert (entry["idle_seconds"], entry["closes_at"]) == (0, None)
            # Leaving the page ends the recording; then the limit counts.
            await c.call("navigate", site="demo", url="http://localhost/quiet")
            stopped = time.monotonic()
            for _ in range(200):
                if not (await c.call("status"))["sessions"]:
                    break
                await asyncio.sleep(0.1)
            assert (await c.call("status"))["sessions"] == []
            assert time.monotonic() - stopped >= limit - 1  # the call itself restarts the count

    with PageServer(QUIET_PAGES) as pages:
        _roots, rig_context = build_daemon_rig(server, pages, idle_limit=limit)
        run(scenario(rig_context))


@pytest.mark.integration
@needs_browser
def test_the_jail_is_gone_after_the_browser_is_killed(
    server: throwaway_audio.ThrowawayAudio,
) -> None:
    async def scenario(
        roots: sites.Roots, rig_context: contextlib.AbstractAsyncContextManager[Rig]
    ) -> None:
        async with rig_context as rig, await rig.connect() as c:
            await c.call("open", site="demo")
            assert under(graph_directory(roots))
            profile = sessions.session_paths(roots, "demo").profile_dir
            browser = processes_with(f"--user-data-dir={profile}")
            assert browser
            for pid in browser:
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)
            for _ in range(200):
                if not (await c.call("status"))["sessions"]:
                    break
                await asyncio.sleep(0.1)
            assert (await c.call("status"))["sessions"] == []
            for _ in range(100):
                if not under(graph_directory(roots)):
                    break
                await asyncio.sleep(0.1)
            assert under(graph_directory(roots)) == []

    with PageServer(PAGES) as pages:
        roots, rig_context = build_daemon_rig(server, pages)
        run(scenario(roots, rig_context))


# -- the source the microphone copies -------------------------------------------------------


@pytest.mark.integration
@needs_audio
def test_a_named_source_is_what_the_session_hears_instead_of_the_default(
    server: throwaway_audio.ThrowawayAudio,
) -> None:
    default = audio.AudioGraph.start(server.base / "g", server.socket, "plain")
    try:
        assert abs(tone(record(default.socket))[1] - throwaway_audio.TONE_HERTZ) < 40
        assert default.capture_stream()["source"] is None
    finally:
        default.close()
    named = audio.AudioGraph.start(
        server.base / "g", server.socket, "named", source=f"{throwaway_audio.DESKTOP}.monitor"
    )
    try:
        level, pitch = tone(record(named.socket))
        assert level > 0.05
        assert (
            abs(pitch - throwaway_audio.DESKTOP_HERTZ) < 60
        )  # the desktop tone, not the microphone's
        # Nothing else changed: still the two nodes, and the person's server is as it was.
        assert names(named.socket, "sources") == ["vk_mic", "vk_out.monitor"]
        assert names(named.socket, "sinks") == ["vk_out"]
        assert pactl(named.socket, "load-module", "module-null-sink").returncode != 0
        assert f"Default Source: {throwaway_audio.MICROPHONE}" in server.pactl("info")
        assert named.capture_stream()["source"] == f"{throwaway_audio.DESKTOP}.monitor"
    finally:
        named.close()


@pytest.mark.integration
@needs_audio
def test_a_source_that_is_not_there_starts_no_graph_and_does_not_fall_back(
    server: throwaway_audio.ThrowawayAudio,
) -> None:
    directory = server.base / "g"
    with pytest.raises(audio.MissingSourceError, match=r'"gone.monitor" does not exist'):
        audio.AudioGraph.start(directory, server.socket, "demo", source="gone.monitor")
    assert not directory.exists()
    assert under(directory) == []


@pytest.mark.integration
@needs_browser
def test_opening_a_site_whose_source_is_gone_fails_with_the_fix_and_leaves_nothing(
    server: throwaway_audio.ThrowawayAudio,
) -> None:
    async def scenario(
        roots: sites.Roots, rig_context: contextlib.AbstractAsyncContextManager[Rig]
    ) -> None:
        async with rig_context as rig, await rig.connect() as c:
            with pytest.raises(DaemonError) as info:
                await c.call("open", site="demo")
            assert (
                'microphone source "gone.monitor" does not exist on your audio server; '
                "create it, or run: valetkey mic demo on"
            ) in info.value.message
            assert (await c.call("status"))["sessions"] == []
            assert under(graph_directory(roots)) == []
            assert not graph_directory(roots).exists()
            assert (await c.call("status", site="demo"))["state"] == "idle"

    with PageServer(PAGES) as pages:
        roots, rig_context = build_daemon_rig(server, pages, source="gone.monitor")
        run(scenario(roots, rig_context))
