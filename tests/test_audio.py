# SPDX-License-Identifier: Apache-2.0
"""The private audio graph: its parts, run with a stand-in for the jail."""

import json
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from valetkey import audio, sandbox, seccomp, sites

# -- pure pieces ----------------------------------------------------------------------------


def policy(start: str, allow: tuple[str, ...], denied: tuple[str, ...] = ()) -> sites.Policy:
    return sites.Policy("demo", start, allow, denied=denied)


def test_recording_is_allowed_on_the_start_origin_and_the_sites_own_domain_only() -> None:
    urls = audio.capture_urls(
        policy(
            "https://app.sitex.co.uk/start",
            ("sitex.co.uk", "accounts.other.test", "cdn.other.test", "login.sitex.co.uk"),
        )
    )
    # A subdomain of the site's own registrable domain is covered; a sign-in provider and a CDN
    # on another domain are not, although the site may reach them.
    assert urls == ["https://app.sitex.co.uk", "https://[*.]sitex.co.uk"]


def test_an_address_gets_its_origin_alone() -> None:
    urls = audio.capture_urls(policy("http://127.0.0.1:8765/", ("127.0.0.1", "cdn.sitex.test")))
    assert urls == ["http://127.0.0.1:8765"]


def test_without_a_suffix_list_only_the_origin_is_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing() -> None:
        raise sites.SuffixListError

    monkeypatch.setattr(sites, "system_suffixes", missing)
    assert audio.capture_urls(policy("https://app.sitex.test/", ("sitex.test",))) == [
        "https://app.sitex.test"
    ]


def test_missing_programs_are_named() -> None:
    have = {"bwrap", "pipewire", "pw-dump"}
    assert audio.missing_programs(lambda name: name if name in have else None) == [
        "wireplumber",
        "pactl",
    ]
    assert audio.missing_programs(lambda name: name) == []


def test_the_person_s_socket_is_in_the_runtime_directory(tmp_path: Path) -> None:
    assert audio.upstream_socket(tmp_path) == tmp_path / "pulse" / "native"


def test_the_graph_s_configuration_names_the_person_s_socket_and_the_two_nodes(
    tmp_path: Path,
) -> None:
    audio.write_config(tmp_path, Path("/run/user/1000/pulse/native"))
    pipewire = (tmp_path / "config/pipewire/pipewire.conf.d/10-valetkey.conf").read_text()
    assert 'pulse.server.address = "unix:/run/user/1000/pulse/native"' in pipewire
    assert "tunnel.mode = source" in pipewire
    assert "node.name = vk_mic" in pipewire
    assert "node.name = vk_out" in pipewire
    assert "pulse.allow-module-loading = false" in pipewire
    assert "unix:native" in pipewire
    wireplumber = (tmp_path / "config/wireplumber/wireplumber.conf.d/10-valetkey.conf").read_text()
    for monitor in ("alsa", "bluez", "libcamera", "v4l2"):
        assert f"monitor.{monitor} = disabled" in wireplumber
    audio.write_config(tmp_path, Path("/x"))  # again is fine


def jail(tmp_path: Path, **options: Any) -> list[str]:  # noqa: ANN401
    return audio.jail_argv(
        tmp_path / "graph",
        Path("/run/user/1000/pulse/native"),
        "demo",
        system_links=["--symlink", "usr/lib", "/lib"],
        **options,
    )


def test_the_jail_has_no_network_devices_or_home_and_shares_the_pid_namespace(
    tmp_path: Path,
) -> None:
    argv = jail(tmp_path)
    for flag in ("--unshare-user", "--unshare-ipc", "--unshare-net", "--unshare-uts"):
        assert flag in argv
    assert "--unshare-cgroup" in argv
    assert "--unshare-pid" not in argv  # the graph cannot tell its clients apart in one
    assert "--unshare-all" not in argv
    assert "--new-session" in argv
    binds = [(argv[i + 1], argv[i + 2]) for i, word in enumerate(argv) if word == "--bind"]
    graph = str(tmp_path / "graph")
    assert binds == [
        (graph, graph),
        ("/run/user/1000/pulse/native", "/run/user/1000/pulse/native"),
    ]
    read_only = [(argv[i + 1], argv[i + 2]) for i, word in enumerate(argv) if word == "--ro-bind"]
    assert read_only == [("/usr", "/usr"), ("/etc/ld.so.cache", "/etc/ld.so.cache")]
    assert "--dev" in argv
    assert "--dev-bind" not in argv
    assert argv[-3:-1] == ["/usr/bin/bash", "-c"]
    assert argv[-1] == audio.SUPERVISOR


def test_the_jail_environment_is_its_own_and_marks_the_graph_s_stream(tmp_path: Path) -> None:
    argv = jail(tmp_path)
    graph = str(tmp_path / "graph")
    env = {argv[i + 1]: argv[i + 2] for i, word in enumerate(argv) if word == "--setenv"}
    assert argv.index("--clearenv") < argv.index("--setenv")
    assert env["XDG_RUNTIME_DIR"] == env["PIPEWIRE_RUNTIME_DIR"] == env["HOME"] == graph
    assert env["XDG_CONFIG_HOME"] == f"{graph}/config"
    assert env["DBUS_SESSION_BUS_ADDRESS"] == f"unix:path={graph}/no-bus"
    assert env["PULSE_PROP_OVERRIDE_valetkey.session"] == "demo"
    assert env["PULSE_PROP_OVERRIDE_application.name"] == "valetkey-microphone"
    assert set(env) & {"WAYLAND_DISPLAY", "DISPLAY", "PULSE_SERVER", "SSH_AUTH_SOCK"} == set()


def test_the_jail_gets_the_filter_when_there_is_one(tmp_path: Path) -> None:
    assert "--seccomp" not in jail(tmp_path)
    argv = jail(tmp_path, seccomp_fd=7)
    assert argv[argv.index("--seccomp") + 1] == "7"


def test_the_jail_links_the_system_directories_like_the_browser_s_sandbox(tmp_path: Path) -> None:
    argv = audio.jail_argv(tmp_path / "graph", Path("/x"), "demo")
    links = sandbox.system_link_args()
    assert any(argv[i : i + len(links)] == links for i in range(len(argv)))


# -- the graph, with a stand-in for the jail -----------------------------------------------

SOURCE_OUTPUTS = (
    'Source Output #3\n\tProperties:\n\t\tvaletkey.session = "other"\n'
    'Source Output #{number}\n\tProperties:\n\t\tvaletkey.session = "{tag}"\n'
)


class Pactl:
    """Answers the questions the graph asks of ``pactl`` and ``pw-dump``, and writes them down."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.default_source = "vk_mic"
        self.stream_appears_after = 0
        self.fail = False
        self.nodes: list[dict[str, Any]] = []

    def __call__(self, argv: list[str], environment: dict[str, str] | None = None) -> str:
        self.calls.append(list(argv))
        if self.fail:
            message = "no server"
            raise audio.AudioError(message)
        if argv[0] == "pw-dump":
            assert environment is not None
            return json.dumps(self.nodes)
        words = argv[3:]
        if words == ["info"]:
            return f"Server Name: PipeWire\nDefault Source: {self.default_source}\n"
        if words == ["list", "source-outputs"]:
            if self.stream_appears_after > 0:
                self.stream_appears_after -= 1
                return ""
            return SOURCE_OUTPUTS.format(number=17, tag="demo")
        return ""


@pytest.fixture
def pactl(monkeypatch: pytest.MonkeyPatch) -> Pactl:
    fake = Pactl()
    monkeypatch.setattr(audio, "_ask", fake)
    return fake


def stand_in(script: str) -> Any:  # noqa: ANN401
    """Return a replacement for the jail command that runs ``script`` and makes the socket."""

    def argv(directory: Path, _upstream: Path, _tag: str, _fd: int | None) -> list[str]:
        socket = directory / "pulse" / "native"
        return ["sh", "-c", f"mkdir -p {socket.parent}; touch {socket}; {script}"]

    return argv


def alive(pid: int) -> bool:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return False
    return stat.rpartition(")")[2].split()[0] != "Z"


def test_the_graph_is_ready_when_the_microphone_is_the_default_and_its_stream_is_unmuted(
    tmp_path: Path, pactl: Pactl
) -> None:
    upstream = tmp_path / "pulse" / "native"
    pactl.stream_appears_after = 2  # the stream on the person's server is not there at first
    graph = audio.AudioGraph.start(
        tmp_path / "graph", upstream, "demo", argv=stand_in("cat >/dev/null")
    )
    try:
        assert graph.is_alive()
        assert graph.socket == tmp_path / "graph" / "pulse" / "native"
        assert graph.log_file == tmp_path / "graph" / "audio.log"
        server = f"unix:{upstream}"
        assert ["pactl", "--server", server, "set-source-output-mute", "17", "0"] in pactl.calls
        asked_about = [call for call in pactl.calls if "set-source-output-mute" in call]
        assert len(asked_about) == 1  # the other session's stream is not touched
        assert (tmp_path / "graph").stat().st_mode & 0o777 == 0o700
    finally:
        graph.close()
    assert not graph.is_alive()


def test_what_an_earlier_graph_left_in_the_directory_is_cleared(
    tmp_path: Path, pactl: Pactl
) -> None:
    del pactl
    (tmp_path / "graph" / "pulse").mkdir(parents=True)
    (tmp_path / "graph" / "pulse" / "native").write_text("stale")
    (tmp_path / "graph" / "state").write_text("stale")
    graph = audio.AudioGraph.start(
        tmp_path / "graph", tmp_path / "up", "demo", argv=stand_in("cat >/dev/null")
    )
    graph.close()
    assert not (tmp_path / "graph" / "state").exists()
    assert (
        tmp_path / "graph" / "pulse" / "native"
    ).read_text() == ""  # made again, not the old one


def test_closing_the_graph_closes_the_pipe_that_tells_the_supervisor_to_stop(
    tmp_path: Path, pactl: Pactl
) -> None:
    del pactl
    graph = audio.AudioGraph.start(
        tmp_path / "graph", tmp_path / "up", "demo", argv=stand_in("cat >/dev/null")
    )
    pid = graph.process.pid
    graph.close()
    assert graph.process.returncode == 0  # it ended by itself, not killed
    assert not alive(pid)
    graph.close()  # again is fine


def test_a_supervisor_that_does_not_stop_is_killed_with_its_group(
    tmp_path: Path, pactl: Pactl, monkeypatch: pytest.MonkeyPatch
) -> None:
    del pactl
    monkeypatch.setattr(audio, "STOP_GRACE", 0.3)
    script = "trap '' TERM HUP; sleep 600 & echo $! > $PWD/child.pid; wait"
    graph = audio.AudioGraph.start(
        tmp_path / "graph", tmp_path / "up", "demo", argv=stand_in(f"cd {tmp_path}; {script}")
    )
    deadline = time.monotonic() + 10
    while not (tmp_path / "child.pid").exists():
        assert time.monotonic() < deadline
        time.sleep(0.02)
    child = int((tmp_path / "child.pid").read_text())
    assert alive(child)
    graph.close()
    assert graph.process.returncode == -signal.SIGKILL
    deadline = time.monotonic() + 10
    while alive(child):
        assert time.monotonic() < deadline
        time.sleep(0.02)


def test_a_graph_that_ends_at_start_says_why(tmp_path: Path, pactl: Pactl) -> None:
    del pactl

    def argv(directory: Path, _u: Path, _t: str, _fd: int | None) -> list[str]:
        return [
            "sh",
            "-c",
            f"echo 'pipewire: cannot open the socket' >> {directory}/audio.log; exit 1",
        ]

    with pytest.raises(audio.AudioError) as info:
        audio.AudioGraph.start(tmp_path / "graph", tmp_path / "up", "demo", argv=argv)
    assert str(info.value).startswith("the audio graph ended at start\n")
    assert "cannot open the socket" in str(info.value)


def test_a_graph_that_is_not_ready_in_time_is_stopped_and_says_so(
    tmp_path: Path, pactl: Pactl
) -> None:
    pactl.default_source = "something_else"
    started = time.monotonic()
    with pytest.raises(audio.AudioError, match=r"not ready after 0\.5 seconds"):
        audio.AudioGraph.start(
            tmp_path / "graph",
            tmp_path / "up",
            "demo",
            timeout=0.5,
            argv=stand_in("cat >/dev/null"),
        )
    assert time.monotonic() - started < 10


def test_a_graph_whose_server_does_not_answer_is_not_ready(tmp_path: Path, pactl: Pactl) -> None:
    pactl.fail = True
    with pytest.raises(audio.AudioError, match="not ready after"):
        audio.AudioGraph.start(
            tmp_path / "graph",
            tmp_path / "up",
            "demo",
            timeout=0.3,
            argv=stand_in("cat >/dev/null"),
        )


def test_a_server_that_prints_no_default_source_is_not_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(audio, "_ask", lambda *_args: "Server Name: PipeWire\n")
    with pytest.raises(audio.AudioError, match="not ready"):
        audio.AudioGraph.start(
            tmp_path / "graph",
            tmp_path / "up",
            "demo",
            timeout=0.3,
            argv=stand_in("cat >/dev/null"),
        )


def test_a_directory_too_long_for_a_socket_is_refused(tmp_path: Path) -> None:
    with pytest.raises(audio.AudioError, match="too long for the graph's socket"):
        audio.AudioGraph.start(tmp_path / ("d" * 100), tmp_path / "up", "demo")


def test_the_stream_is_looked_for_until_the_time_is_up(
    tmp_path: Path, pactl: Pactl, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(audio, "UNMUTE_TIMEOUT", 0.3)
    pactl.stream_appears_after = 10_000  # never
    graph = audio.AudioGraph.start(
        tmp_path / "graph", tmp_path / "up", "demo", argv=stand_in("cat >/dev/null")
    )
    graph.close()
    assert not any("set-source-output-mute" in call for call in pactl.calls)


def test_a_person_s_server_that_cannot_be_asked_does_not_keep_the_graph_from_starting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def ask(argv: list[str], environment: dict[str, str] | None = None) -> str:
        del environment
        if "list" in argv:
            message = "the server went away"
            raise audio.AudioError(message)
        return "Default Source: vk_mic\n"

    monkeypatch.setattr(audio, "UNMUTE_TIMEOUT", 0.3)
    monkeypatch.setattr(audio, "_ask", ask)
    graph = audio.AudioGraph.start(
        tmp_path / "graph", tmp_path / "up", "demo", argv=stand_in("cat >/dev/null")
    )
    graph.close()


@pytest.mark.parametrize("filter_available", [True, False])
def test_the_syscall_filter_goes_to_the_jail_when_there_is_one(
    tmp_path: Path, pactl: Pactl, monkeypatch: pytest.MonkeyPatch, *, filter_available: bool
) -> None:
    del pactl
    given: list[int | None] = []
    real = seccomp.open_filter
    monkeypatch.setattr(seccomp, "open_filter", lambda: real() if filter_available else None)

    def argv(directory: Path, upstream: Path, tag: str, descriptor: int | None) -> list[str]:
        given.append(descriptor)
        return stand_in("cat >/dev/null")(directory, upstream, tag, descriptor)

    graph = audio.AudioGraph.start(tmp_path / "graph", tmp_path / "up", "demo", argv=argv)
    graph.close()
    assert (given[0] is not None) is (filter_available and seccomp.available())
    if given[0] is not None:
        with pytest.raises(OSError, match="Bad file descriptor"):
            os.fstat(given[0])  # valetkey's own copy is closed


def test_the_graph_s_log_tail_is_empty_without_a_log(tmp_path: Path, pactl: Pactl) -> None:
    del pactl
    graph = audio.AudioGraph.start(
        tmp_path / "graph", tmp_path / "up", "demo", argv=stand_in("cat >/dev/null")
    )
    graph.close()
    graph.log_file.write_text("x" * 3000 + "end")
    assert graph.log_tail().endswith("end")
    assert len(graph.log_tail()) == 1500
    graph.log_file.unlink()
    assert graph.log_tail() == ""


def node(number: int, media_class: str, kind: str = "PipeWire:Interface:Node") -> dict[str, Any]:
    return {"id": number, "type": kind, "info": {"props": {"media.class": media_class}}}


def test_the_capture_stream_is_the_node_of_the_program_that_records(
    tmp_path: Path, pactl: Pactl
) -> None:
    graph = audio.AudioGraph.start(
        tmp_path / "graph", tmp_path / "up", "demo", argv=stand_in("cat >/dev/null")
    )
    try:
        pactl.nodes = [
            node(31, "Audio/Sink"),
            node(52, "Stream/Input/Audio"),
            node(48, "Stream/Input/Audio"),
            node(40, "Stream/Input/Audio", "PipeWire:Interface:Port"),
            {"id": 3, "type": "PipeWire:Interface:Node", "info": {}},
            {"id": 4, "type": "PipeWire:Interface:Node"},
        ]
        assert graph.capture_nodes() == [48, 52]
        assert graph.capture_stream() == {
            "socket": str(graph.socket),
            "node": 48,
            "directory": str(graph.directory),
        }
        pactl.nodes = [node(31, "Audio/Sink")]
        assert graph.capture_stream()["node"] is None
        pactl.fail = True
        assert graph.capture_stream()["node"] is None
    finally:
        graph.close()


def test_a_dump_that_is_not_the_graph_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    graph = audio.AudioGraph(tmp_path, tmp_path, subprocess.Popen(["true"]), "demo")  # noqa: S607
    for text in ("not json", '{"id": 1}', "[1, 2]"):
        monkeypatch.setattr(audio, "_ask", lambda *_a, text=text: text)
        with pytest.raises(audio.AudioError, match="pw-dump printed something else"):
            graph.capture_nodes()
    graph.close()  # a process with no pipe to close has only to be waited for


def test_a_program_that_cannot_run_or_fails_is_an_audio_error(tmp_path: Path) -> None:
    with pytest.raises(audio.AudioError, match="no-such-program"):
        audio._ask(["no-such-program-valetkey", "a", "b"])  # noqa: SLF001
    with pytest.raises(audio.AudioError, match="false"):
        audio._ask(["false"])  # noqa: SLF001
    assert audio._ask(["echo", "hello"]).strip() == "hello"  # noqa: SLF001
    del tmp_path


def test_unmuting_finds_the_stream_by_its_tag_only(pactl: Pactl) -> None:
    assert audio.unmute_stream(Path("/up"), "demo") is True
    assert audio.unmute_stream(Path("/up"), "someone-else") is False
    assert [c[3:] for c in pactl.calls if "set-source-output-mute" in c] == [
        ["set-source-output-mute", "17", "0"]
    ]
