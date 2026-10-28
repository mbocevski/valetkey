# SPDX-License-Identifier: Apache-2.0
"""What a client of the private graph's socket can do with raw PulseAudio protocol commands.

``pactl`` sends only the commands it has a verb for. These tests send every command number, odd
client names and broken packets with ``pulse_client``, to the private graph, which runs against a
throwaway audio server standing for the person's. A command may be refused, or may do something
inside the graph. None may change the person's microphone, speakers, defaults or modules, or
another program's stream, and a broken packet may end only its own connection.

Found by these tests: ``SET_SOURCE_VOLUME`` and ``SET_SOURCE_MUTE`` on the graph's microphone
reach the person's server, as the volume and mute of the graph's own capture stream (the one
tagged ``valetkey.session``). The device is not touched, and the next graph unmutes its stream
and sets it to full volume.
"""

import contextlib
import os
import re
import socket
import struct
import subprocess
import time
from typing import TYPE_CHECKING

import pulse_client as pc
import pytest
import throwaway_audio
from pulse_client import Tags
from test_audio_real import names, needs_audio, record, tone, under, wait_until

from valetkey import audio

if TYPE_CHECKING:
    from collections.abc import Iterator

Graph = tuple[throwaway_audio.ThrowawayAudio, audio.AudioGraph]
REFUSED = {"ACCESS", "COMMAND", "INVALID", "NOENTITY", "PROTOCOL", "NOTSUPPORTED", "BADSTATE"}
"""The errors a server answers with when it does not do what it was asked."""
TAG = "protocol-test"


@pytest.fixture
def graph() -> Iterator[Graph]:
    with throwaway_audio.ThrowawayAudio() as server:
        started = audio.AudioGraph.start(server.base / "g", server.socket, TAG)
        try:
            yield server, started
        finally:
            started.close()


def connect(started: audio.AudioGraph, name: str = "probe") -> pc.PulseClient:
    client = pc.PulseClient(started.socket)
    assert client.authenticate().ok
    assert client.name({"application.name": name}).ok
    return client


def persons_audio(server: throwaway_audio.ThrowawayAudio) -> dict[str, str]:
    """What the throwaway server holds that is the person's: devices, defaults, modules, streams.

    The capture stream of the graph is left out, because the graph is a client of it.
    """
    state = {}
    for kind in ("sources", "sinks"):
        text = server.pactl("list", kind)
        state[kind] = re.sub(r"\n\s*(?:Latency|Flags|State):[^\n]*", "", text)
    state["modules"] = server.pactl("list", "short", "modules")
    state["sink-inputs"] = server.pactl("list", "short", "sink-inputs")
    state["defaults"] = "\n".join(
        line for line in server.pactl("info").splitlines() if line.startswith("Default ")
    )
    return state


def graph_stream(server: throwaway_audio.ThrowawayAudio) -> str:
    """The text of the graph's capture stream on the person's server."""
    blocks = server.pactl("list", "source-outputs").split("Source Output #")[1:]
    (mine,) = (b for b in blocks if f'valetkey.session = "{TAG}"' in b)
    return mine


def still_works(server: throwaway_audio.ThrowawayAudio, started: audio.AudioGraph) -> None:
    """Check the graph answers a new client and still carries the microphone."""
    assert started.is_alive()
    with pc.PulseClient(started.socket) as fresh:
        assert fresh.authenticate().ok
        assert fresh.command(pc.GET_SERVER_INFO).ok
    assert tone(record(started.socket, seconds=1.5))[0] > 0.05
    assert server.pactl("info").count(f"Default Source: {throwaway_audio.MICROPHONE}") == 1


ARGUMENTS = {
    "none": Tags,
    "index": lambda: Tags().u32(0xFFFFFFFF),
    "index and name": lambda: Tags().u32(0xFFFFFFFF).string("test_mic"),
    "name": lambda: Tags().string("test_mic"),
    "two numbers": lambda: Tags().u32(0).u32(0),
    "index, name and true": lambda: Tags().u32(0xFFFFFFFF).string("test_mic").boolean(value=True),
    "index, name and volume": lambda: Tags().u32(0xFFFFFFFF).string("test_mic").cvolume(2, 0),
}
"""Argument shapes for the sweep, naming the person's devices where a name goes."""
SWEEP_SKIPPED = {pc.AUTH, pc.EXIT, pc.KILL_CLIENT}
"""AUTH is how the client signs in, EXIT ends the connection, and a kill has a test of its own."""


@pytest.mark.integration
@needs_audio
def test_no_command_number_with_any_arguments_changes_the_persons_audio(graph: Graph) -> None:
    server, started = graph
    before = persons_audio(server)
    client = connect(started)
    answers: dict[int, set[str]] = {}
    for number in range(pc.CREATE_PLAYBACK_STREAM, 100):
        if number in SWEEP_SKIPPED:
            continue
        for make in ARGUMENTS.values():
            try:
                answer = client.command(number, make())
            except pc.ClosedError, ConnectionError, pc.ProtocolError:
                client = connect(started)
                answers.setdefault(number, set()).add("closed")
                continue
            answers.setdefault(number, set()).add("OK" if answer.ok else str(answer.error))
    client.close()
    assert persons_audio(server) == before
    # The commands that change the person's server, or the graph's wiring, are refused whatever
    # the arguments: modules, defaults, ports, cards, suspending and moving.
    for number in (
        pc.LOAD_MODULE,
        pc.UNLOAD_MODULE,
        pc.SET_DEFAULT_SINK,
        pc.SET_DEFAULT_SOURCE,
        pc.SET_CARD_PROFILE,
        pc.SET_SINK_PORT,
        pc.SET_SOURCE_PORT,
        pc.MOVE_SINK_INPUT,
        pc.MOVE_SOURCE_OUTPUT,
    ):
        assert "OK" not in answers[number], number
    still_works(server, started)


@pytest.mark.integration
@needs_audio
def test_loading_a_module_or_changing_a_default_stays_refused_whatever_the_client_calls_itself(
    graph: Graph,
) -> None:
    server, started = graph
    before = persons_audio(server)
    names_to_try = (
        {"pipewire.access": "unrestricted"},
        {"pipewire.access": "flatpak", "pipewire.access.portal.app_id": "x"},
        {"pipewire.access": "restricted"},
        {"application.process.binary": "valetkey", "pipewire.module.id": "1"},
        {"media.class": "Audio/Sink", "node.name": "test_mic", "node.target": "test_mic"},
        {f"k{n}": "v" for n in range(2000)},
    )
    for properties in names_to_try:
        with pc.PulseClient(started.socket) as client:
            assert client.authenticate().ok
            client.name(properties)
            for number, arguments in (
                (pc.LOAD_MODULE, Tags().string("module-null-sink").string("")),
                (pc.LOAD_MODULE, Tags().string("module-native-protocol-tcp").string("")),
                (pc.UNLOAD_MODULE, Tags().u32(0)),
                (pc.SET_DEFAULT_SOURCE, Tags().string("test_desktop.monitor")),
                (pc.SET_DEFAULT_SOURCE, Tags().string("vk_out.monitor")),
                (pc.SET_DEFAULT_SINK, Tags().string("test_desktop")),
                (pc.SET_DEFAULT_SINK, Tags().string("vk_out")),
            ):
                assert not client.command(number, arguments).ok, (properties, number)
    with pc.PulseClient(started.socket) as client:  # no sign-in at all
        assert not client.command(pc.LOAD_MODULE, Tags().string("module-null-sink").string("")).ok
    assert persons_audio(server) == before
    assert names(started.socket, "sinks") == ["vk_out"]
    assert started._default_source() == audio.SOURCE_NODE  # noqa: SLF001
    still_works(server, started)


@pytest.mark.integration
@needs_audio
def test_the_client_lists_only_the_graph_and_never_the_persons_devices_or_streams(
    graph: Graph,
) -> None:
    _server, started = graph
    wanted = {pc.GET_SINK_INFO_LIST: "sinks", pc.GET_SOURCE_INFO_LIST: "sources"}
    with connect(started) as client:
        for number in wanted:
            listed = [v for v in client.command(number).values if isinstance(v, str)]
            assert {v for v in listed if v.startswith(("vk_", "test_"))} <= {
                "vk_mic",
                "vk_out",
                "vk_out.monitor",
            }
            assert not any("test_" in v or "Test" in v for v in listed)
        for number in (pc.GET_SINK_INPUT_INFO_LIST, pc.GET_CARD_INFO_LIST):
            assert client.command(number).values == []
        clients = [v for v in client.command(pc.GET_CLIENT_INFO_LIST).values if isinstance(v, str)]
        assert "probe" in clients  # the graph's own programs and this client: nobody else


KILLABLE = ("WirePlumber", "pipewire", "recorder", "capture stream")


@pytest.mark.integration
@needs_audio
@pytest.mark.parametrize("victim", KILLABLE)
def test_killing_a_client_or_stream_ends_only_things_in_the_graph(
    graph: Graph, victim: str
) -> None:
    server, started = graph
    recorder = subprocess.Popen(  # noqa: S603  # an argument list, no shell
        [  # noqa: S607  # from PATH
            "parec",
            f"--server=unix:{started.socket}",
            "--format=s16le",
            "--rate=48000",
            "--channels=2",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_until(lambda: started.capture_stream()["node"] is not None)
        before = persons_audio(server)
        with connect(started) as client:
            values = client.command(pc.GET_CLIENT_INFO_LIST).values
            clients = {
                values[i + 1]: values[i]
                for i in range(len(values) - 1)
                if isinstance(values[i], int) and isinstance(values[i + 1], str)
            }
            stream = client.command(pc.GET_SOURCE_OUTPUT_INFO_LIST).values[0]
            if victim == "capture stream":
                answer = client.command(pc.KILL_SOURCE_OUTPUT, Tags().u32(stream))
            else:
                name = "parec" if victim == "recorder" else victim
                answer = client.command(pc.KILL_CLIENT, Tags().u32(clients[name]))
            assert answer.ok
        time.sleep(2)
        assert persons_audio(server) == before
        if victim == "WirePlumber":  # the graph loses its manager and ends, as a whole
            wait_until(lambda: not started.is_alive())
            started.close()
            wait_until(lambda: under(started.directory) == [])
    finally:
        recorder.kill()
        recorder.wait()
    assert persons_audio(server) == before


@pytest.mark.integration
@needs_audio
def test_volume_and_mute_of_the_microphone_reach_only_the_graphs_own_stream(
    graph: Graph,
) -> None:
    server, started = graph
    before = persons_audio(server)
    other = subprocess.Popen(  # noqa: S603  # an argument list, no shell
        [  # noqa: S607  # from PATH
            "parec",
            f"--server=unix:{server.socket}",
            f"--device={throwaway_audio.MICROPHONE}",
            "--format=s16le",
            "--rate=48000",
            "--channels=2",
        ],
        stdout=subprocess.DEVNULL,
    )
    try:
        wait_until(lambda: len(_blocks(server)) == 2)
        others = _other_blocks(server)
        with connect(started) as client:
            volume = Tags().u32(0xFFFFFFFF).string("vk_mic").cvolume(2, 0)
            assert client.command(pc.SET_SOURCE_VOLUME, volume).ok
            mute = Tags().u32(0xFFFFFFFF).string("vk_mic").boolean(value=True)
            assert client.command(pc.SET_SOURCE_MUTE, mute).ok
        wait_until(lambda: "Mute: yes" in graph_stream(server))
        # The graph's own stream on the person's server is muted and silent, as it is told ...
        assert "Volume: front-left: 0 /" in graph_stream(server)
        # ... and nothing else of the person's audio is touched: not the microphone, not the
        # speakers, not another program's recording of the same microphone.
        assert persons_audio(server) == before
        assert _other_blocks(server) == others
    finally:
        other.kill()
        other.wait()


@pytest.mark.integration
@needs_audio
def test_a_page_that_silences_its_stream_does_not_silence_the_next_graph(
    graph: Graph,
) -> None:
    server, started = graph
    saved = server.base / "state" / "wireplumber" / "stream-properties"
    with connect(started) as client:
        volume = Tags().u32(0xFFFFFFFF).string("vk_mic").cvolume(2, 0)
        assert client.command(pc.SET_SOURCE_VOLUME, volume).ok
        mute = Tags().u32(0xFFFFFFFF).string("vk_mic").boolean(value=True)
        assert client.command(pc.SET_SOURCE_MUTE, mute).ok
    # The person's WirePlumber saves what a stream was set to, and restores it for the next stream
    # that has the same application id, which is every graph's tunnel.
    wait_until(
        lambda: saved.exists() and '"channelVolumes":[0.000000, 0.000000]' in saved.read_text()
    )
    assert '"mute":true' in saved.read_text()
    started.close()
    second = audio.AudioGraph.start(server.base / "g", server.socket, "second")
    try:
        # Whatever the saved state brings back, the graph takes the mute off and sets full
        # volume at start, so the stream records the microphone.
        stream = graph_stream_for(server, "second")
        assert "Mute: no" in stream
        assert "Volume: front-left: 65536 /" in stream
        assert tone(record(second.socket, seconds=1.5))[0] > 0.05
    finally:
        second.close()


def graph_stream_for(server: throwaway_audio.ThrowawayAudio, tag: str) -> str:
    """The text of the capture stream tagged ``tag`` on the person's server."""
    (mine,) = (b for b in _blocks(server) if f'valetkey.session = "{tag}"' in b)
    return mine


def _blocks(server: throwaway_audio.ThrowawayAudio) -> list[str]:
    return server.pactl("list", "source-outputs").split("Source Output #")[1:]


def _other_blocks(server: throwaway_audio.ThrowawayAudio) -> list[list[str]]:
    """The mute, volume and program of every recording but the graph's, without its timings."""
    return [
        [line.strip() for line in b.splitlines() if line.strip().startswith(("Mute:", "Volume:"))]
        + re.findall(r'application.name = "[^"]*"', b)
        for b in _blocks(server)
        if f'valetkey.session = "{TAG}"' not in b
    ]


@pytest.mark.integration
@needs_audio
def test_a_stream_to_the_persons_speakers_has_nowhere_to_go(graph: Graph) -> None:
    server, started = graph
    before = persons_audio(server)
    player = subprocess.Popen(  # noqa: S603  # an argument list, no shell
        [  # noqa: S607  # from PATH
            "pacat",
            "--playback",
            f"--server=unix:{started.socket}",
            f"--device={throwaway_audio.DESKTOP}",
            "--format=s16le",
            "--rate=48000",
            "--channels=2",
            "--raw",
        ],
        stdin=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    try:
        assert player.stdin is not None
        with contextlib.suppress(OSError):
            player.stdin.write(b"\0" * 192000)
            player.stdin.flush()
        time.sleep(1.5)
        assert persons_audio(server) == before  # no new sink input on the person's sink
    finally:
        player.kill()
        player.wait()
        if player.stdin is not None:
            with contextlib.suppress(OSError):
                player.stdin.close()


def _descriptor(length: int, channel: int = pc.CONTROL_CHANNEL, flags: int = 0) -> bytes:
    return struct.pack(">IIIII", length, channel, 0, 0, flags)


def _command(number: int, tag: int = 1) -> bytes:
    return bytes(Tags().u32(number).u32(tag).data)


BROKEN = {
    "nothing": b"",
    "part of a descriptor": b"\0" * 19,
    "an empty packet": _descriptor(0),
    "one byte": _descriptor(1) + b"\xff",
    "a length of four gigabytes": _descriptor(0xFFFFFFFF),
    "a length beyond the limit": _descriptor(64 * 1024 * 1024 + 1) + b"x" * 100,
    "a long packet that never arrives": _descriptor(16 * 1024 * 1024) + b"x" * 1000,
    "a packet cut short": _descriptor(100) + b"x" * 10,
    "an unknown tag": _descriptor(5) + b"Z1234",
    "a number cut short": _descriptor(3) + b"L\0\0",
    "a string with no end": _descriptor(8) + b"Lxxxxt" + b"abc",
    "a command with no tag": _descriptor(5) + b"L\0\0\0\x14",
    "an unknown command": _descriptor(len(_command(9999))) + _command(9999),
    "audio on a channel nobody opened": _descriptor(10, channel=5) + b"x" * 10,
    "every flag set": _descriptor(len(_command(20)), flags=0xFFFFFFFF) + _command(20),
    "a big packet of zeros": _descriptor(70000) + _command(20) + b"\0" * (70000 - 10),
    "a property list cut short": _descriptor(20) + _command(pc.SET_CLIENT_NAME) + b"Pt" + b"a" * 5,
}


@pytest.mark.integration
@needs_audio
def test_a_broken_packet_ends_only_its_own_connection(graph: Graph) -> None:
    server, started = graph
    for label, data in [*BROKEN.items(), ("random bytes", os.urandom(2048))]:
        with socket.socket(socket.AF_UNIX) as broken:
            broken.settimeout(2)
            broken.connect(str(started.socket))
            with contextlib.suppress(OSError):
                broken.sendall(data)
            # The server answers with an error, closes the connection, or waits for the rest of
            # the packet. It does not stop answering anyone else, and the graph keeps running.
            with contextlib.suppress(TimeoutError, OSError):
                broken.recv(65536)
        with pc.PulseClient(started.socket) as fresh:
            assert fresh.authenticate().ok, label
            assert fresh.command(pc.GET_SERVER_INFO).ok, label
        assert started.is_alive(), label
    still_works(server, started)
