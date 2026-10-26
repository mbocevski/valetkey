# SPDX-License-Identifier: Apache-2.0

import contextlib
import json
import logging
import os
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from environment import unusable_reason
from proxy_stub import PageServer, ProxyStub, host_of_request

from valetkey import procs, sandbox, sessions, sites

# --- helpers ------------------------------------------------------------------------------

LAUNCH_FLAGS = (
    "--profile",
    "--proxy",
    "--proxy-bypass",
    "--user-agent",
    "--args",
    "--executable-path",
    "--idle-timeout",
    "--engine",
    "--headed",
    "--extension",
    "--state",
    "--restore",
    "--allowed-domains",
    "--cdp",
    "--provider",
    "--init-script",
    "--ca-cert",
)
CALL_ENV = {
    "PATH",
    "HOME",
    "LANG",
    "XDG_RUNTIME_DIR",
    "AGENT_BROWSER_SESSION",
    "AGENT_BROWSER_NAMESPACE",
    "AGENT_BROWSER_IDLE_TIMEOUT_MS",
    "AGENT_BROWSER_CONFIG",
}
OK = json.dumps({"success": True, "data": {}, "error": None})


def make_roots(base: Path) -> sites.Roots:
    (base / "rt").mkdir(mode=0o700, parents=True, exist_ok=True)
    return sites.Roots(base / "cfg", base / "state", base / "rt")


def make_session(base: Path) -> sessions.Session:
    roots = make_roots(base)
    paths = sessions.session_paths(roots, "demo")
    return sessions.Session(paths, base / "rt", "/usr/bin/agent-browser", 5, sessions.Page("", ""))


REAL_ISOLATED = sessions.Session._isolated  # noqa: SLF001
REAL_DRIVER_ANSWERS = sessions.Session._driver_answers  # noqa: SLF001


@pytest.fixture(autouse=True)
def _no_driver_probe(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Let the tests with a stand-in for agent-browser call it without a daemon's socket.

    The integration tests have the real agent-browser, so they get the real checks too.
    """
    if request.node.get_closest_marker("integration"):
        return
    monkeypatch.setattr(sessions.Session, "_driver_answers", lambda _self: True)
    monkeypatch.setattr(sessions.Session, "_isolated", lambda _self, argv, _env: argv)


def listen_as_the_driver(session: sessions.Session) -> socket.socket:
    """Return a listening socket where the sandbox's agent-browser daemon would be."""
    path = session.paths.driver_dir / "run" / f"{sessions.SESSION_NAME}.sock"
    path.parent.mkdir(parents=True, exist_ok=True)
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(path))
    server.listen()
    return server


class FakeRun:
    """Stands in for ``subprocess.run`` and records what it was asked to run."""

    def __init__(self, stdout: str = OK) -> None:
        self.stdout = stdout
        self.calls: list[tuple[list[str], dict[str, str]]] = []

    def __call__(
        self, argv: list[str], **kwargs: dict[str, str]
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((argv, kwargs["env"]))
        return subprocess.CompletedProcess(argv, 0, self.stdout, "")


def answer(data: dict[str, Any]) -> str:
    return json.dumps({"success": True, "data": data, "error": None})


# --- versions -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "version"),
    [("agent-browser 0.39.2\n", (0, 39, 2)), ("agent-browser 1.0.10", (1, 0, 10))],
)
def test_parse_version(text: str, version: tuple[int, int, int]) -> None:
    assert sessions.parse_version(text) == version


def test_parse_version_rejects_text_without_one() -> None:
    with pytest.raises(ValueError, match="no version number"):
        sessions.parse_version("agent-browser")


def test_check_version_accepts_the_minimum_and_the_tested_version(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sessions.check_version(sessions.MIN_VERSION)
    sessions.check_version(sessions.TESTED_VERSION)
    assert caplog.records == []


def test_check_version_rejects_an_old_version() -> None:
    with pytest.raises(sessions.VersionError, match=r"0\.38\.9 is too old.*0\.39\.0"):
        sessions.check_version((0, 38, 9))


def test_check_version_warns_once_about_a_newer_version(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sessions, "_warned", set())
    with caplog.at_level(logging.WARNING):
        sessions.check_version((0, 40, 0))
        sessions.check_version((0, 40, 0))
        sessions.check_version((0, 41, 0))
    assert "0.40.0 is newer than 0.39.2" in caplog.text
    assert [r.getMessage().split()[1] for r in caplog.records] == ["0.40.0", "0.41.0"]


def test_check_version_can_leave_the_warning_to_the_caller(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sessions, "_warned", set())
    with caplog.at_level(logging.WARNING):
        sessions.check_version((0, 40, 0), warn=False)
    assert caplog.records == []
    with pytest.raises(sessions.VersionError):
        sessions.check_version((0, 38, 0), warn=False)


def test_version_texts_and_the_untested_test() -> None:
    assert sessions.version_text((0, 39, 2)) == "0.39.2"
    assert sessions.short_version_text((0, 39, 0)) == "0.39"
    assert sessions.short_version_text((0, 39, 2)) == "0.39.2"
    assert not sessions.is_untested(sessions.TESTED_VERSION)
    assert not sessions.is_untested(sessions.MIN_VERSION)
    assert sessions.is_untested((0, 39, 3))


def test_the_minimum_does_not_exceed_the_tested_version() -> None:
    assert sessions.MIN_VERSION <= sessions.TESTED_VERSION


def test_installed_version_runs_the_program(tmp_path: Path) -> None:
    fake = tmp_path / "ab"
    fake.write_text("#!/bin/sh\necho 'agent-browser 0.39.7'\n")
    fake.chmod(0o755)
    assert sessions.installed_version(str(fake)) == (0, 39, 7)


@pytest.mark.parametrize("body", ["#!/bin/sh\necho nothing\n", "#!/bin/sh\nexit 3\n"])
def test_installed_version_reports_a_broken_program(tmp_path: Path, body: str) -> None:
    fake = tmp_path / "ab"
    fake.write_text(body)
    fake.chmod(0o755)
    with pytest.raises(sessions.SessionError, match="cannot read the version"):
        sessions.installed_version(str(fake))


def test_installed_version_reports_a_missing_program(tmp_path: Path) -> None:
    with pytest.raises(sessions.SessionError, match="cannot read the version"):
        sessions.installed_version(str(tmp_path / "missing"))


# --- paths --------------------------------------------------------------------------------


def test_every_path_belongs_to_one_site(tmp_path: Path) -> None:
    roots = make_roots(tmp_path)
    one, two = (sessions.session_paths(roots, name) for name in ("one", "two"))
    assert one.driver_dir == tmp_path / "rt" / "agent-browser" / "namespaces" / "one"
    assert one.ready_file == one.driver_dir / "ready.json"
    assert (
        one.proxy_socket
        == tmp_path / "rt" / "valetkey" / "sessions" / "one" / "proxy" / "proxy.sock"
    )
    assert one.profile_dir == sites.profile_path(roots, "one")
    assert one.downloads_dir == sites.downloads_path(roots, "one")
    assert one.incoming_dir == one.downloads_dir / ".incoming"
    assert one.screenshots_dir == one.downloads_dir / ".screenshots"
    for field in ("directory", "proxy_socket", "log_file", "config_file", "driver_dir"):
        assert getattr(one, field) != getattr(two, field)
        assert not getattr(one, field).is_relative_to(getattr(two, "directory"))  # noqa: B009  # name is data
    # agent-browser's own directory and the proxy's must be separate mounts
    assert not one.proxy_socket.is_relative_to(one.driver_dir)
    assert not one.log_file.is_relative_to(one.proxy_socket.parent)


def test_longest_socket_path_fits_the_limit() -> None:
    roots = sites.Roots(Path("/c"), Path("/s"), Path("/run/user/1000"))
    name = "a" * sites.MAX_NAME_LENGTH
    socket = (
        sessions.session_paths(roots, name).driver_dir / "run" / f"{sessions.SESSION_NAME}.sock"
    )
    assert len(str(socket)) <= 103
    assert len(str(sessions.session_paths(roots, name).proxy_socket)) <= 103


def test_paths_need_a_runtime_dir_and_a_valid_name(tmp_path: Path) -> None:
    with pytest.raises(sites.RuntimeDirUnavailableError):
        sessions.session_paths(sites.Roots(tmp_path, tmp_path, None), "demo")
    with pytest.raises(ValueError, match="invalid site name"):
        sessions.session_paths(make_roots(tmp_path), "../escape")


# --- commands -----------------------------------------------------------------------------


def test_agent_args_leave_out_what_has_flags_of_its_own() -> None:
    flags = sandbox.chrome_flags(156)
    args = sessions.agent_args(flags)
    assert not any(a.startswith(("--proxy-server=", "--user-agent=")) for a in args)
    assert "--proxy-bypass-list=<-loopback>" in args
    assert len(args) == len(flags) - 2


def test_launch_command_carries_every_launch_option_once(tmp_path: Path) -> None:
    paths = sessions.session_paths(make_roots(tmp_path), "demo")
    argv = sessions.launch_command(
        "/usr/bin/ab", paths, "http://site.test/", "/usr/bin/chromium", 156
    )
    assert argv[:2] == ["/usr/bin/ab", "--json"]
    assert argv[-2:] == ["open", "http://site.test/"]
    option = {
        argv[i]: argv[i + 1] for i, a in enumerate(argv) if a.startswith("--") and i + 1 < len(argv)
    }
    assert option["--profile"] == str(paths.profile_dir)
    assert option["--download-path"] == str(paths.incoming_dir)
    assert paths.incoming_dir == paths.downloads_dir / ".incoming"
    assert option["--proxy"] == "http://127.0.0.1:3128"
    assert "Chrome/156.0.0.0" in option["--user-agent"]
    assert option["--executable-path"] == "/usr/bin/chromium"
    assert option["--idle-timeout"] == "0"
    # Flags with commas inside survive because the list is newline-separated.
    assert "\n" in option["--args"]
    assert any(
        ",PreconnectToSearch" in line or ",Translate" in line
        for line in option["--args"].split("\n")
    )
    assert sum(a == "--proxy" for a in argv) == 1
    assert "--proxy-server" not in option["--args"]


@pytest.mark.parametrize(
    "url", ["file:///etc/passwd", "javascript:alert(1)", "data:text/html,x", "http://", "site.test"]
)
def test_only_http_urls_are_opened(tmp_path: Path, url: str) -> None:
    paths = sessions.session_paths(make_roots(tmp_path), "demo")
    with pytest.raises(ValueError, match="only http and https"):
        sessions.launch_command("ab", paths, url, "/usr/bin/chromium", 156)


def test_holder_script_is_valid_shell_and_quotes_what_it_is_given(tmp_path: Path) -> None:
    roots = make_roots(tmp_path / "it's a dir; touch pwned")
    paths = sessions.session_paths(roots, "demo")
    command = sessions.launch_command(
        "/usr/bin/ab", paths, "http://site.test/?a=b&c=d", "/usr/bin/chromium", 156
    )
    script = sessions.holder_script(paths, "/usr/bin/ab", command, roots.runtime or tmp_path)
    subprocess.run(["bash", "-n"], input=script, text=True, check=True)  # noqa: S607  # syntax check only
    assert "AGENT_BROWSER_SESSION=s" in script
    assert "AGENT_BROWSER_NAMESPACE=demo" in script
    assert "AGENT_BROWSER_CONFIG" not in script
    assert script.count("/dev/tcp/127.0.0.1/3128") == 1
    assert "touch pwned" in script
    assert not (tmp_path / "pwned").exists()
    assert script.rstrip().endswith("wait")


def test_the_holder_script_waits_for_the_bridge_then_stops_if_it_dies(tmp_path: Path) -> None:
    roots = make_roots(tmp_path)
    paths = sessions.session_paths(roots, "demo")
    paths.driver_dir.mkdir(parents=True)
    # No proxy socket exists, so the forwarder exits at once; the holder must notice and fail.
    script = sessions.holder_script(paths, "/usr/bin/false", ["x", "open", "http://a/"], tmp_path)
    result = subprocess.run(["bash", "-c", script], capture_output=True, check=False, timeout=30)  # noqa: S603, S607
    assert result.returncode == 71


def test_the_holder_script_reports_a_failed_open_and_exits_with_its_status(tmp_path: Path) -> None:
    roots = make_roots(tmp_path)
    paths = sessions.session_paths(roots, "demo")
    paths.driver_dir.mkdir(parents=True)
    fake = tmp_path / "ab"
    fake.write_text('#!/bin/sh\necho \'{"success":false,"error":"boom"}\'\nexit 4\n')
    fake.chmod(0o755)
    ready = paths.ready_file
    # Replace the forwarder with a harmless listener-less command by satisfying the port test.
    script = sessions.holder_script(paths, str(fake), ["x", "open", "http://a/"], tmp_path)
    script = script.replace(script.split("\n", 1)[0], "sleep 3 >/dev/null 2>&1 &", 1)
    script = script.replace("until (exec 3<>/dev/tcp/127.0.0.1/3128)", "until true")
    result = subprocess.run(["bash", "-c", script], capture_output=True, check=False, timeout=30)  # noqa: S603, S607
    assert result.returncode == 4
    assert json.loads(ready.read_text())["error"] == "boom"


def test_a_call_waits_for_nothing_when_the_driver_is_gone(
    short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """agent-browser would start a daemon and a browser on the host, outside the sandbox."""
    monkeypatch.setattr(sessions.Session, "_driver_answers", REAL_DRIVER_ANSWERS)
    run = FakeRun(answer({}))
    monkeypatch.setattr(sessions.subprocess, "run", run)
    session = make_session(short_dir)
    for verb in (session.snapshot, session.current_url, lambda: session.open("http://a.test/")):
        with pytest.raises(sessions.SessionError, match="driver in the sandbox is gone"):
            verb()
    assert run.calls == []  # agent-browser was never run

    path = session.paths.driver_dir / "run" / f"{sessions.SESSION_NAME}.sock"
    path.parent.mkdir(parents=True)
    path.write_text("a file is not a socket")
    with pytest.raises(sessions.SessionError, match="driver in the sandbox is gone"):
        session.snapshot()
    assert run.calls == []

    path.unlink()
    with listen_as_the_driver(session):
        session.current_url()
    assert len(run.calls) == 1


def test_a_call_runs_without_a_network_and_ends_with_the_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sessions.Session, "_isolated", REAL_ISOLATED)
    run = FakeRun(answer({}))
    monkeypatch.setattr(sessions.subprocess, "run", run)
    session = make_session(tmp_path)
    session.current_url()
    argv, env = run.calls[0]
    assert argv[:2] == ["bwrap", "--unshare-all"]
    assert "--unshare-net" not in argv  # --unshare-all covers the network
    assert "--die-with-parent" in argv
    assert argv[argv.index("--chdir") + 2 :] == ["/usr/bin/agent-browser", "--json", "get", "url"]
    assert ["--bind", str(session.paths.driver_dir)] == argv[
        argv.index("--bind") : argv.index("--bind") + 2
    ]
    assert env["AGENT_BROWSER_NAMESPACE"] == "demo"


def test_close_does_not_run_agent_browser_without_a_driver(
    short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sessions.Session, "_driver_answers", REAL_DRIVER_ANSWERS)
    run = FakeRun(answer({}))
    monkeypatch.setattr(sessions.subprocess, "run", run)
    session = make_session(short_dir)
    session._holder = subprocess.Popen(["sleep", "59.5"])  # noqa: S607, SLF001
    session.close()
    assert run.calls == []
    assert session._holder.poll() is not None  # noqa: SLF001


def test_call_command_carries_the_session_name_and_no_launch_option(tmp_path: Path) -> None:
    paths = sessions.session_paths(make_roots(tmp_path), "demo")
    verbs = [
        ("snapshot", "-i"),
        ("click", "@e1"),
        ("fill", "@e1", "x"),
        ("get", "url"),
        ("close",),
    ]
    for verb in verbs:
        argv, env = sessions.call_command("/usr/bin/ab", paths, tmp_path / "rt", *verb)
        assert argv == ["/usr/bin/ab", "--json", *verb]
        assert not [
            a
            for a in argv
            if a in LAUNCH_FLAGS or a.startswith(tuple(f"{f}=" for f in LAUNCH_FLAGS))
        ]
        assert set(env) == CALL_ENV
        assert env["AGENT_BROWSER_SESSION"] == sessions.SESSION_NAME
        assert env["AGENT_BROWSER_NAMESPACE"] == "demo"
        assert env["AGENT_BROWSER_IDLE_TIMEOUT_MS"] == "0"
        assert env["AGENT_BROWSER_CONFIG"] == str(paths.config_file)


@pytest.mark.parametrize("argument", ["--headed", "-x", "--session", "--profile=/tmp/x", "-", "--"])
def test_an_argument_that_looks_like_an_option_never_reaches_agent_browser(
    tmp_path: Path, argument: str
) -> None:
    paths = sessions.session_paths(make_roots(tmp_path), "demo")
    with pytest.raises(ValueError, match="looks like an option"):
        sessions.call_command("/usr/bin/ab", paths, tmp_path / "rt", "fill", "@e1", argument)
    # Our own flag is fine, and so is a dash anywhere but first.
    sessions.call_command("/usr/bin/ab", paths, tmp_path / "rt", "snapshot", "-i")
    sessions.call_command("/usr/bin/ab", paths, tmp_path / "rt", "fill", "@e1", "a --headed")
    # The verb itself is ours.
    sessions.call_command("/usr/bin/ab", paths, tmp_path / "rt", "get", "url")


DANGEROUS = ["--headed", "-x", "--session other", "--json", "--", "-", "--profile=/x", "- a dash"]


def test_no_session_method_lets_a_leading_dash_reach_the_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = FakeRun(answer({"url": "u", "title": "t", "refs": {}, "snapshot": "", "origin": "u"}))
    monkeypatch.setattr(sessions.subprocess, "run", run)
    session = make_session(tmp_path)
    methods = {
        "open": session.open,
        "click": session.click,
        "screenshot": session.screenshot,
    }
    for name, method in methods.items():
        for value in DANGEROUS:
            with pytest.raises(ValueError):  # noqa: PT011 - any refusal will do
                method(value)
            assert not run.calls, f"{name}({value!r}) built a command"
    # fill takes text, so it must accept every one of them, and none may start a word with a dash.
    for value in DANGEROUS:
        session.fill("e1", value)
    for argv, _ in run.calls:
        assert not [a for a in argv[2:] if a.startswith("-") and a not in sessions.OWN_FLAGS]
    typed = [argv[4] for argv, _ in run.calls if argv[2] == "fill"]
    assert typed == [f" {value}" for value in DANGEROUS]
    assert [argv[2:] for argv, _ in run.calls if argv[2] == "press"][:2] == [
        ["press", "Control+Home"],
        ["press", "Delete"],
    ]


def test_attachments_counts_only_successful_attachment_responses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    logged = [
        {"status": 200, "responseHeaders": {"Content-Disposition": 'attachment; filename="a.pdf"'}},
        {"status": 200, "responseHeaders": {"content-disposition": " Attachment"}},
        {"status": 200, "responseHeaders": {"Content-Disposition": 'inline; filename="b.pdf"'}},
        {"status": 404, "responseHeaders": {"Content-Disposition": "attachment"}},
        {"status": 302, "responseHeaders": {"Content-Disposition": "attachment"}},
        {"status": 200, "responseHeaders": {"Content-Type": "text/html"}},
        {"status": None, "responseHeaders": None},
        {},
    ]
    run = FakeRun(answer({"requests": logged}))
    monkeypatch.setattr(sessions.subprocess, "run", run)
    session = make_session(tmp_path)
    assert session.attachments() == 2
    session.clear_requests()
    assert [argv[2:] for argv, _ in run.calls] == [
        ["network", "requests"],
        ["network", "requests", "--clear"],
    ]
    monkeypatch.setattr(sessions.subprocess, "run", FakeRun(answer({})))
    assert session.attachments() == 0


def test_password_fields_asks_the_browser_to_count_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = FakeRun(answer({"count": 2, "selector": "input[type=password]"}))
    monkeypatch.setattr(sessions.subprocess, "run", run)
    session = make_session(tmp_path)
    assert session.password_fields() == 2
    assert [argv[2:] for argv, _ in run.calls] == [["get", "count", "input[type=password]"]]
    monkeypatch.setattr(sessions.subprocess, "run", FakeRun(answer({})))
    assert session.password_fields() == 0


def test_start_leaves_a_fresh_private_incoming_folder(tmp_path: Path) -> None:
    roots = make_roots(tmp_path)
    paths = sessions.session_paths(roots, "demo")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep", encoding="utf-8")
    sites.ensure_downloads(roots, "demo")
    paths.incoming_dir.mkdir()
    (paths.incoming_dir / "stale.crdownload").write_text("stale", encoding="utf-8")
    (paths.incoming_dir / "link").symlink_to(outside)
    (paths.incoming_dir / "linked.txt").symlink_to(outside / "keep.txt")
    (paths.incoming_dir / "sub").mkdir()
    (paths.incoming_dir / "sub" / "deep").symlink_to(outside)
    sessions._prepare(roots, paths)  # noqa: SLF001
    assert list(paths.incoming_dir.iterdir()) == []
    assert stat.S_IMODE(paths.incoming_dir.stat().st_mode) == 0o700
    assert [p.name for p in outside.iterdir()] == ["keep.txt"]  # nothing was followed
    assert paths.screenshots_dir.is_dir()


@pytest.mark.parametrize("kind", ["file", "link", "missing"])
def test_an_incoming_path_that_is_not_a_directory_is_replaced(tmp_path: Path, kind: str) -> None:
    roots = make_roots(tmp_path)
    paths = sessions.session_paths(roots, "demo")
    sites.ensure_downloads(roots, "demo")
    outside = tmp_path / "outside"
    outside.mkdir()
    if kind == "file":
        paths.incoming_dir.write_text("in the way", encoding="utf-8")
    elif kind == "link":
        paths.incoming_dir.symlink_to(outside)
    sessions._prepare(roots, paths)  # noqa: SLF001
    assert paths.incoming_dir.is_dir()
    assert not paths.incoming_dir.is_symlink()
    assert list(outside.iterdir()) == []


def test_every_verb_goes_through_call_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = FakeRun(answer({"url": "u", "title": "t", "refs": {}, "snapshot": "", "origin": "u"}))
    monkeypatch.setattr(sessions.subprocess, "run", run)
    session = make_session(tmp_path)
    session.open("http://a.test/")
    session.snapshot()
    session.click("e1")
    session.fill("@e1", "plain text")
    session.fill("@e1", "--proxy http://evil")
    session.press_enter()
    session.outline()
    session.current_url()
    session.screenshot("x.png")
    assert [argv[2:] for argv, _ in run.calls] == [
        ["open", "http://a.test/"],
        ["snapshot", "-i"],
        ["click", "@e1"],
        ["fill", "@e1", "plain text"],
        ["fill", "@e1", " --proxy http://evil"],
        ["press", "Control+Home"],
        ["press", "Delete"],
        ["press", "Enter"],
        ["snapshot"],
        ["get", "url"],
        ["screenshot", str(session.paths.screenshots_dir / "x.png")],
    ]
    for argv, env in run.calls:
        assert set(env) == CALL_ENV
        assert not [a for a in argv[:-1] if a in LAUNCH_FLAGS]


# --- answers ------------------------------------------------------------------------------


def test_parse_response_returns_the_data() -> None:
    assert sessions.parse_response(answer({"url": "u"})) == {"url": "u"}
    assert sessions.parse_response(json.dumps({"success": True, "data": None})) == {}


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (
            json.dumps({"success": False, "data": None, "error": "Unknown ref: e9"}),
            "Unknown ref: e9",
        ),
        (
            json.dumps({"success": False, "error": "Missing arguments", "type": "x"}),
            "Missing arguments",
        ),
        (json.dumps({"success": False}), "agent-browser failed"),
        ("not json", "something other than JSON"),
        ("", "something other than JSON"),
        ("[1]", "unexpected answer"),
    ],
)
def test_parse_response_maps_failures_to_an_error(text: str, message: str) -> None:
    with pytest.raises(sessions.AgentBrowserError, match=message):
        sessions.parse_response(text)


def test_parse_page_and_snapshot() -> None:
    assert sessions.parse_page({"url": "http://a/", "title": "A"}) == sessions.Page(
        "http://a/", "A"
    )
    assert sessions.parse_page({}) == sessions.Page("", "")
    snapshot = sessions.parse_snapshot(
        {
            "origin": "http://a/",
            "snapshot": '- button "Go" [ref=e1]',
            "refs": {"e1": {"role": "button", "name": "Go"}},
        }
    )
    assert snapshot == sessions.Snapshot(
        "http://a/", '- button "Go" [ref=e1]', {"e1": sessions.Ref("button", "Go")}
    )
    assert sessions.parse_snapshot({}) == sessions.Snapshot("", "", {})


def test_a_failed_call_raises_with_the_tools_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = FakeRun(json.dumps({"success": False, "data": None, "error": "Unknown ref: e9"}))
    monkeypatch.setattr(sessions.subprocess, "run", run)
    with pytest.raises(sessions.AgentBrowserError, match="Unknown ref: e9"):
        make_session(tmp_path).click("e9")


def test_a_call_that_hangs_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def hang(argv: list[str], **_: object) -> None:
        raise subprocess.TimeoutExpired(argv, 1)

    monkeypatch.setattr(sessions.subprocess, "run", hang)
    with pytest.raises(sessions.AgentBrowserError, match="snapshot timed out"):
        make_session(tmp_path).snapshot()


@pytest.mark.parametrize("ref", ["", "e", "button", "@e1 --proxy x", "e1;ls", "--proxy"])
def test_click_and_fill_take_only_snapshot_references(tmp_path: Path, ref: str) -> None:
    session = make_session(tmp_path)
    with pytest.raises(ValueError, match="not a reference"):
        session.click(ref)
    with pytest.raises(ValueError, match="not a reference"):
        session.fill(ref, "x")


@pytest.mark.parametrize("name", ["", "../x.png", "a/b.png", "x.txt", ".png", "-x.png", "x.png\n"])
def test_screenshot_names_are_plain_png_files(tmp_path: Path, name: str) -> None:
    with pytest.raises(ValueError, match=r"plain \.png"):
        make_session(tmp_path).screenshot(name)


def test_open_refuses_other_schemes(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="only http and https"):
        make_session(tmp_path).open("file:///etc/passwd")


def test_the_session_has_no_eval_or_passthrough() -> None:
    public = {n for n in dir(sessions.Session) if not n.startswith("_")}
    assert public == {
        "start", "is_alive", "close", "open", "snapshot", "outline", "click", "fill", "press_enter",
        "current_url", "screenshot", "clear_requests", "attachments", "password_fields",
    }  # fmt: skip


# --- lifecycle without a browser ----------------------------------------------------------


def test_a_closed_session_refuses_calls_and_closing_twice_is_fine(tmp_path: Path) -> None:
    session = make_session(tmp_path)
    session.close()
    session.close()
    assert not session.is_alive()
    with pytest.raises(sessions.SessionError, match="closed"):
        session.snapshot()


def test_close_stops_the_holder_and_removes_the_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = FakeRun()
    monkeypatch.setattr(sessions.subprocess, "run", run)
    session = make_session(tmp_path)
    for directory in (session.paths.driver_dir, session.paths.proxy_socket.parent):
        directory.mkdir(parents=True)
    session.paths.log_file.write_text("log")
    session.paths.config_file.write_text("{}")
    session._holder = subprocess.Popen(["sleep", "59.5"])  # noqa: S607, SLF001
    assert session.is_alive()
    session.close()
    assert not session.is_alive()
    assert run.calls[0][0][2:] == ["close"]
    assert not session.paths.driver_dir.exists()
    assert not session.paths.directory.exists()
    assert (tmp_path / "rt").exists()


def test_close_kills_a_holder_that_ignores_sigterm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sessions.subprocess, "run", FakeRun())
    monkeypatch.setattr(sessions, "STOP_GRACE", 0.3)
    session = make_session(tmp_path)
    code = (
        "import signal, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "print('up', flush=True)\n"
        "time.sleep(60)"
    )
    holder = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE)  # noqa: S603
    assert holder.stdout is not None
    assert holder.stdout.readline() == b"up\n"
    session._holder = holder  # noqa: SLF001
    session.close()
    holder.stdout.close()
    assert holder.returncode == -signal.SIGKILL


def test_close_keeps_a_proxy_directory_that_is_still_in_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sessions.subprocess, "run", FakeRun())
    session = make_session(tmp_path)
    session.paths.proxy_socket.parent.mkdir(parents=True)
    session.paths.proxy_socket.touch()
    session.close()
    assert session.paths.proxy_socket.exists()


class FakeStart:
    """Replaces the launch of the holder with a local command, so no browser is needed."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, script: str | None) -> None:
        self.script = script
        self.policies: list[str] = []
        monkeypatch.setattr(sessions, "installed_version", lambda _: sessions.TESTED_VERSION)
        monkeypatch.setattr(sessions, "_resolve_binary", lambda _: "/usr/bin/agent-browser")
        monkeypatch.setattr(sandbox, "installed_chrome_major", lambda _: 156)
        monkeypatch.setattr(sandbox, "start", self)
        monkeypatch.setattr(subprocess, "run", FakeRun())

    def __call__(self, box: sandbox.Sandbox, command: list[str]) -> subprocess.Popen[bytes]:
        if self.script is None:
            message = "no bwrap"
            raise OSError(message)
        assert command[:2] == ["/usr/bin/bash", "-c"]
        assert (
            box.shared_dir
            == sessions.session_paths(make_roots(box.runtime_dir.parent), "demo").driver_dir
        )
        assert box.policy_dir is not None
        self.policies.append((box.policy_dir / "managed" / "valetkey.json").read_text())
        env = {**os.environ, "READY": str(box.shared_dir / "ready.json"), "LOG": str(box.log_file)}
        with box.log_file.open("ab") as log:
            return subprocess.Popen(["sh", "-c", self.script], env=env, stdout=log, stderr=log)  # noqa: S603, S607


def start(
    tmp_path: Path, *, timeout: float = 10, proxy_socket: Path | None = None
) -> sessions.Session:
    return sessions.Session.start(
        make_roots(tmp_path),
        "demo",
        "http://site.test/",
        timeout=timeout,
        proxy_socket=proxy_socket,
    )


def browser_lines(session: sessions.Session) -> list[list[str]]:
    return [["/usr/lib/chromium/chromium", f"--user-data-dir={session.paths.profile_dir}"]]


def test_is_alive_looks_for_the_browser_only_when_asked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = make_session(tmp_path)
    session._holder = subprocess.Popen(["sleep", "59.5"])  # noqa: S607, SLF001
    lines: list[list[str]] = []
    monkeypatch.setattr(procs, "command_lines", lambda: lines)
    try:
        assert session.is_alive()  # the holder is enough, as at startup
        session._watch_browser = True  # noqa: SLF001
        assert not session.is_alive()  # the holder runs but the browser is gone
        lines.extend(browser_lines(session))
        assert session.is_alive()
        lines[:] = [[*browser_lines(session)[0], "--type=renderer"]]
        assert not session.is_alive()  # a helper process is not the browser
    finally:
        session.close()
    assert not session.is_alive()


def test_a_watched_session_is_gone_when_the_driver_stops_answering(
    short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sessions.Session, "_driver_answers", REAL_DRIVER_ANSWERS)
    session = make_session(short_dir)
    session._holder = subprocess.Popen(["sleep", "59.5"])  # noqa: S607, SLF001
    session._watch_browser = True  # noqa: SLF001
    monkeypatch.setattr(procs, "command_lines", lambda: browser_lines(session))
    try:
        assert not session.is_alive()  # the browser runs, the driver does not
        with listen_as_the_driver(session):
            assert session.is_alive()
        assert not session.is_alive()
    finally:
        session.close()


def test_start_can_watch_the_browser(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    page = json.dumps({"success": True, "data": {"url": "http://site.test/", "title": "Hi"}})
    FakeStart(monkeypatch, f"echo '{page}' > \"$READY\"; sleep 60")
    lines: list[list[str]] = []
    monkeypatch.setattr(procs, "command_lines", lambda: lines)
    session = sessions.Session.start(
        make_roots(tmp_path), "demo", "http://site.test/", timeout=10, watch_browser=True
    )
    try:
        assert not session.is_alive()  # no browser process is running
        lines.extend(browser_lines(session))
        assert session.is_alive()
    finally:
        session.close()


def test_start_waits_for_the_first_page(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    page = json.dumps({"success": True, "data": {"url": "http://site.test/", "title": "Hi"}})
    fake = FakeStart(monkeypatch, f"echo '{page}' > \"$READY\"; sleep 60")
    with start(tmp_path, timeout=10) as session:
        assert session.first_page == sessions.Page("http://site.test/", "Hi")
        assert [json.loads(text) for text in fake.policies] == [sandbox.CHROME_POLICY]
        assert session.is_alive()
        assert session.paths.profile_dir.is_dir()
        assert session.paths.config_file.read_text() == "{}\n"
    assert not session.is_alive()
    assert not session.paths.driver_dir.exists()


def test_start_reports_a_first_page_that_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    page = json.dumps(
        {"success": False, "error": "Navigation failed: net::ERR_PROXY_CONNECTION_FAILED"}
    )
    FakeStart(monkeypatch, f"echo '{page}' > \"$READY\"; sleep 60")
    with pytest.raises(sessions.AgentBrowserError, match="ERR_PROXY_CONNECTION_FAILED"):
        start(tmp_path, timeout=10)
    assert not (tmp_path / "rt" / "agent-browser" / "namespaces" / "demo").exists()


def test_start_reports_a_holder_that_exits_early_with_the_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    FakeStart(monkeypatch, "echo 'bridge said no'; exit 71")
    with pytest.raises(sessions.SessionError, match=r"(?s)exited before.*bridge said no"):
        start(tmp_path, timeout=10)


def test_start_gives_up_after_the_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    FakeStart(monkeypatch, "sleep 60")
    started = time.monotonic()
    with pytest.raises(sessions.SessionError, match=r"no page after 0\.5 seconds"):
        start(tmp_path, timeout=0.5)
    assert time.monotonic() - started < 10


def test_start_reports_a_sandbox_that_cannot_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    FakeStart(monkeypatch, None)
    with pytest.raises(sessions.SessionError, match="cannot start the sandbox: no bwrap"):
        start(tmp_path)


def test_start_uses_the_proxy_socket_it_is_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    page = json.dumps({"success": True, "data": {"url": "u", "title": ""}})
    fake = FakeStart(monkeypatch, f"echo '{page}' > \"$READY\"; sleep 60")
    seen: list[Path] = []
    original = fake.__call__
    monkeypatch.setattr(
        sandbox,
        "start",
        lambda box, command: (seen.append(box.proxy_socket), original(box, command))[1],
    )
    custom = tmp_path / "elsewhere" / "p.sock"
    with start(tmp_path, proxy_socket=custom, timeout=10):
        pass
    assert seen == [custom]


def test_start_refuses_an_old_agent_browser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    FakeStart(monkeypatch, "sleep 1")
    monkeypatch.setattr(sessions, "installed_version", lambda _: (0, 30, 0))
    with pytest.raises(sessions.VersionError):
        start(tmp_path)


def test_start_clears_what_an_earlier_session_left(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    page = json.dumps({"success": True, "data": {"url": "u", "title": ""}})
    FakeStart(monkeypatch, f'test ! -e "$READY" && echo \'{page}\' > "$READY"; sleep 60')
    stale = sessions.session_paths(make_roots(tmp_path), "demo")
    stale.driver_dir.mkdir(parents=True)
    stale.ready_file.write_text("old")
    with start(tmp_path, timeout=10) as session:
        assert session.first_page.url == "u"


def test_resolve_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert sessions._resolve_binary("sh").startswith("/usr/")  # noqa: SLF001
    with pytest.raises(sessions.SessionError, match="not installed"):
        sessions._resolve_binary("no-such-program-here")  # noqa: SLF001
    outside = tmp_path / "ab"
    outside.write_text("#!/bin/sh\n")
    outside.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(sessions.SessionError, match="outside /usr"):
        sessions._resolve_binary("ab")  # noqa: SLF001


# --- integration: a real session ----------------------------------------------------------


_SKIP_REASON = unusable_reason("bwrap", "chromium", "agent-browser")
needs_everything = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")

PAGES = {
    "/": (
        '<title>One</title><input placeholder="Your name">'
        "<button onclick=\"document.title='clicked'\">Go</button>"
    ),
    "/two": "<title>Two</title><h1>second page</h1>",
}


def descendants(pid: int) -> set[int]:
    """Every process below ``pid`` on the host, found from /proc."""
    parents: dict[int, int] = {}
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            try:
                fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            except OSError:
                continue
            parents[int(entry.name)] = int(fields[1])
    found: set[int] = set()
    todo = [pid]
    while todo:
        current = todo.pop()
        for child, parent in parents.items():
            if parent == current and child not in found:
                found.add(child)
                todo.append(child)
    return found


def command_line(pid: int) -> str:
    try:
        return (Path("/proc") / str(pid) / "cmdline").read_bytes().replace(b"\0", b" ").decode()
    except OSError:
        return ""


@pytest.mark.integration
@needs_everything
def test_a_real_session_from_start_to_close(short_dir: Path) -> None:
    roots = make_roots(short_dir)
    paths = sessions.session_paths(roots, "demo")
    paths.proxy_socket.parent.mkdir(parents=True)
    with PageServer(PAGES) as pages, ProxyStub(paths.proxy_socket, pages.address) as proxy:
        session = sessions.Session.start(roots, "demo", "http://site.test/", timeout=60)
        holder = session._holder  # noqa: SLF001
        assert holder is not None
        assert session.first_page.url == "http://site.test/"
        assert session.first_page.title == "One"

        snapshot = session.snapshot()
        assert {ref.role for ref in snapshot.refs.values()} == {"textbox", "button"}
        assert snapshot.url == "http://site.test/"
        field = next(r for r, e in snapshot.refs.items() if e.role == "textbox")
        button = next(r for r, e in snapshot.refs.items() if e.role == "button")
        session.fill(field, "--not-an-option")
        session.click(button)
        with pytest.raises(sessions.AgentBrowserError, match="Unknown ref"):
            session.click("e99")

        assert session.open("http://site.test/two").title == "Two"
        assert session.current_url() == "http://site.test/two"
        shot = session.screenshot("two.png")
        assert shot.parent == paths.screenshots_dir
        assert shot.read_bytes().startswith(b"\x89PNG")

        # The browser's daemon lives in another network namespace than this process.
        family = descendants(holder.pid)
        daemons = [
            p
            for p in family
            if "agent-browser" in command_line(p) and "bash" not in command_line(p)
        ]
        assert daemons
        host_net = Path("/proc/self/ns/net").readlink()
        assert all(Path(f"/proc/{p}/ns/net").readlink() != host_net for p in daemons)
        chrome = [p for p in family if "/usr/lib/chromium/chromium" in command_line(p)]
        assert chrome
        assert all(Path(f"/proc/{p}/ns/net").readlink() != host_net for p in chrome)

        # Only the page's host was asked for (bar the startup requests no flag stops), and the
        # user agent does not give the headless browser away.
        assert {host_of_request(r) for r in proxy.requests} - sandbox.BACKGROUND_HOSTS == {
            "site.test"
        }
        page_requests = [r for r in proxy.requests if r.startswith("GET http://site.test/")]
        assert page_requests
        assert all("Chrome/156.0.0.0" in r and "HeadlessChrome" not in r for r in page_requests)

        assert session.is_alive()
        session.close()
        assert not session.is_alive()
        time.sleep(0.2)
        assert not [p for p in family if Path(f"/proc/{p}").exists() and "Z" not in _state(p)]
        assert not paths.driver_dir.exists()
        assert not paths.log_file.exists()
        assert not paths.config_file.exists()
        assert not paths.directory.exists() or not any(paths.directory.glob("*.*"))
        assert paths.profile_dir.is_dir()
        session.close()  # idempotent


def processes_of(runtime: Path) -> set[int]:
    """The processes whose environment says they run under ``runtime`` (``XDG_RUNTIME_DIR``)."""
    wanted = f"XDG_RUNTIME_DIR={runtime}".encode()
    found = set()
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            with contextlib.suppress(OSError):
                if wanted in (entry / "environ").read_bytes().split(b"\0"):
                    found.add(int(entry.name))
    return found


def kill_the_driver(session: sessions.Session) -> None:
    """Do to the daemon in the sandbox what code running in the sandbox can do."""
    holder = session._holder  # noqa: SLF001
    assert holder is not None
    daemons = [
        p
        for p in descendants(holder.pid)
        if command_line(p).startswith("/usr/lib/agent-browser/bin/agent-browser")
    ]
    assert daemons
    for daemon in daemons:
        os.kill(daemon, signal.SIGKILL)
    deadline = time.monotonic() + 10
    while any(Path(f"/proc/{p}").exists() and "Z" not in _state(p) for p in daemons):
        assert time.monotonic() < deadline
        time.sleep(0.05)


def new_outside_the_sandbox(runtime: Path, before: set[int]) -> list[str]:
    """Return the agent-browser and browser processes since ``before`` in the host's network."""
    host_net = Path("/proc/self/ns/net").readlink()
    found = []
    for pid in processes_of(runtime) - before:
        with contextlib.suppress(OSError):
            if Path(f"/proc/{pid}/ns/net").readlink() == host_net and (
                "agent-browser" in command_line(pid) or "chromium" in command_line(pid)
            ):
                found.append(command_line(pid))
    return found


@pytest.mark.integration
@needs_everything
def test_a_dead_driver_ends_the_session_and_starts_nothing_on_the_host(short_dir: Path) -> None:
    roots = make_roots(short_dir)
    paths = sessions.session_paths(roots, "demo")
    paths.proxy_socket.parent.mkdir(parents=True)
    with PageServer(PAGES) as pages, ProxyStub(paths.proxy_socket, pages.address):
        session = sessions.Session.start(
            roots, "demo", "http://site.test/", timeout=60, watch_browser=True
        )
        try:
            before = processes_of(short_dir / "rt")
            assert session.is_alive()
            kill_the_driver(session)
            deadline = time.monotonic() + 10
            while session.is_alive():  # the browser may run on a moment, but nothing drives it
                assert time.monotonic() < deadline
                time.sleep(0.1)
            with pytest.raises(sessions.SessionError, match="driver in the sandbox is gone"):
                session.snapshot()
            assert new_outside_the_sandbox(short_dir / "rt", before) == []
        finally:
            session.close()
        assert new_outside_the_sandbox(short_dir / "rt", before) == []


@pytest.mark.integration
@needs_everything
def test_a_driver_that_stops_during_a_call_leaves_nothing_on_the_host(
    short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without the check, the call would start a daemon and a browser, which die with it."""
    roots = make_roots(short_dir)
    paths = sessions.session_paths(roots, "demo")
    paths.proxy_socket.parent.mkdir(parents=True)
    with PageServer(PAGES) as pages, ProxyStub(paths.proxy_socket, pages.address):
        session = sessions.Session.start(roots, "demo", "http://site.test/", timeout=60)
        try:
            before = processes_of(short_dir / "rt")
            kill_the_driver(session)
            monkeypatch.setattr(sessions.Session, "_driver_answers", lambda _self: True)
            started = time.monotonic()
            with contextlib.suppress(sessions.AgentBrowserError, sessions.SessionError):
                session.snapshot()
            assert time.monotonic() - started < 60
            time.sleep(0.5)
            assert new_outside_the_sandbox(short_dir / "rt", before) == []
            assert not [
                p
                for p in processes_of(short_dir / "rt") - before
                if "chromium" in command_line(p) or "agent-browser" in command_line(p)
            ]
        finally:
            session.close()


def _state(pid: int) -> str:
    try:
        return (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()[0]
    except OSError:
        return "Z"


@pytest.mark.integration
@needs_everything
def test_a_session_without_a_proxy_fails_with_the_reason(short_dir: Path) -> None:
    roots = make_roots(short_dir)
    started = time.monotonic()
    with pytest.raises(sessions.SessionError, match="exited before"):
        sessions.Session.start(roots, "demo", "http://site.test/", timeout=60)
    assert time.monotonic() - started < 30
    assert not sessions.session_paths(roots, "demo").driver_dir.exists()


def test_start_copes_with_a_log_that_is_gone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    FakeStart(monkeypatch, 'rm -f "$LOG"; exit 3')
    with pytest.raises(sessions.SessionError, match="exited before it loaded a page"):
        start(tmp_path)
