# SPDX-License-Identifier: Apache-2.0
"""What valetkey assumes about agent-browser, checked against the installed one.

agent-browser is not 1.0 and changes often. valetkey drives it through its command line and
depends on a few behaviors that no documentation promises. Each test here pins one of them, and
its failure message says what changed and which code to look at. When a new release breaks one,
read the message, change the code that relied on the old behavior, and update the test.
"""

import contextlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from environment import unusable_reason
from proxy_stub import PageServer

from valetkey import procs, sessions, sites

if TYPE_CHECKING:
    from collections.abc import Iterator

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        (_reason := unusable_reason("agent-browser", "chromium")) is not None,
        reason=_reason or "",
    ),
]

PAGE = (
    "<title>Probe</title><input placeholder='Your name'>"
    "<button onclick=\"document.title='clicked'\">Go</button><input type='password'>"
)
SITE = "probe"


def belonging_to(directory: Path) -> list[tuple[int, str]]:
    """The processes that have ``directory`` in their arguments or their environment.

    agent-browser's own daemon is started with no arguments at all and finds its directory in the
    environment, so the arguments alone would miss exactly the process that is easiest to leak.
    Only this directory is looked for, so nothing else on the machine is ever named.
    """
    found = []
    needle = str(directory).encode()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            arguments = (entry / "cmdline").read_bytes()
            environment = (entry / "environ").read_bytes()
        except OSError:
            continue  # it ended, or it is not ours to read
        if needle in arguments or needle in environment:
            found.append((int(entry.name), arguments.replace(b"\0", b" ").decode(errors="replace")))
    return found


def kill_all_of(directory: Path) -> None:
    """Kill, by process id, every process that belongs to ``directory``."""
    for pid, _ in belonging_to(directory):
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.kill(pid, signal.SIGKILL)


class Driver:
    """agent-browser run the way valetkey runs it, against a local page, in a short directory."""

    def __init__(self, base: Path, url: str) -> None:
        self.url = url
        self.binary = shutil.which("agent-browser") or "agent-browser"
        self.roots = sites.Roots(base / "c", base / "s", base / "r")
        (base / "r").mkdir(mode=0o700)
        self.runtime = base / "r"
        self.paths = sessions.session_paths(self.roots, SITE)
        self.paths.config_file.parent.mkdir(parents=True)
        self.paths.config_file.write_text("{}\n")
        self.profile = base / "profile"
        self.base = base

    def run(self, *verb: str, before: tuple[str, ...] = ()) -> dict[str, Any]:
        """Run ``verb`` as valetkey would after the first ``open``, and return the JSON answer.

        ``before`` puts extra words between ``--json`` and the verb, as a launch option would.
        """
        argv, env = sessions.call_command(self.binary, self.paths, self.runtime, *verb)
        argv[2:2] = before
        return self._run(argv, env)

    def launch(self) -> dict[str, Any]:
        """Start the browser with the first ``open``, the only call that carries launch options."""
        _, env = sessions.call_command(self.binary, self.paths, self.runtime, "get", "url")
        argv = [
            self.binary,
            "--json",
            "--profile",
            str(self.profile),
            "--executable-path",
            "/usr/bin/chromium",
            "--idle-timeout",
            "0",
            "open",
            self.url,
        ]
        return self._run(argv, env)

    def raw(self, argv: list[str]) -> dict[str, Any]:
        """Run an arbitrary argument list in the session's environment (for hazards only)."""
        _, env = sessions.call_command(self.binary, self.paths, self.runtime, "get", "url")
        return self._run(argv, env)

    def _run(self, argv: list[str], env: dict[str, str]) -> dict[str, Any]:
        result = subprocess.run(  # noqa: S603  # the installed agent-browser, fixed arguments
            argv, env=env, capture_output=True, text=True, check=False, timeout=90
        )
        try:
            answer = json.loads(result.stdout)
        except json.JSONDecodeError:
            pytest.fail(
                f"agent-browser did not answer in JSON: {result.stdout!r} {result.stderr!r}"
            )
        assert isinstance(answer, dict)
        return answer

    def main_pids(self) -> list[int]:
        """The ids of the browser's main processes that use this driver's profile."""
        return [
            pid
            for pid, arguments in self._processes()
            if procs.browser_running(self.profile, [arguments])
        ]

    def _processes(self) -> Iterator[tuple[int, list[str]]]:
        for entry in Path("/proc").iterdir():
            if entry.name.isdigit():
                try:
                    raw = (entry / "cmdline").read_bytes()
                except OSError:
                    continue
                yield int(entry.name), raw.decode(errors="replace").split("\0")

    def arguments_of(self, pid: int) -> list[str]:
        return next(arguments for found, arguments in self._processes() if found == pid)

    def stop(self) -> None:
        """Close the session, then kill whatever still belongs to this directory, by process id."""
        with contextlib.suppress(Exception, pytest.fail.Exception):
            self.run("close")
        kill_all_of(self.base)


@pytest.fixture(scope="module")
def module_dir() -> Iterator[Path]:
    """One short directory for the whole module, checked for leftovers when the module ends."""
    directory = Path(tempfile.mkdtemp(prefix="vk-drift-"))
    try:
        yield directory
        leftovers = belonging_to(directory)
        assert not leftovers, f"the drift probe left processes running: {leftovers}"
    finally:
        kill_all_of(directory)
        shutil.rmtree(directory, ignore_errors=True)


@pytest.fixture
def driver(module_dir: Path) -> Iterator[Driver]:
    base = Path(tempfile.mkdtemp(prefix="t", dir=module_dir))
    with PageServer({"/": PAGE}) as pages:
        host, port = pages.address
        tool = Driver(base, f"http://{host}:{port}/")
        try:
            assert tool.launch()["success"] is True
            yield tool
        finally:
            tool.stop()


def data_of(answer: dict[str, Any], what: str) -> dict[str, Any]:
    assert answer.get("success") is True, f"{what} failed: {answer}"
    data = answer["data"]
    assert isinstance(data, dict), f"{what} has no data object: {answer}"
    return data


def test_json_answers_keep_the_shape_valetkey_reads(driver: Driver) -> None:
    opened = driver.run("open", driver.url)
    assert set(opened) >= {"success", "data", "error"}, (
        f"the --json envelope changed: it has {sorted(opened)}; sessions.parse_response reads "
        "success, data and error"
    )
    assert opened["error"] is None
    data = data_of(opened, "open")
    assert (data.get("url"), data.get("title")) == (driver.url, "Probe"), (
        f"open's data changed: {data}; sessions.parse_page reads url and title"
    )

    snapshot = data_of(driver.run("snapshot", "-i"), "snapshot -i")
    assert isinstance(snapshot.get("snapshot"), str)
    assert snapshot.get("origin") == driver.url, (
        f"snapshot -i no longer reports the page's origin: {sorted(snapshot)}; "
        "sessions.parse_snapshot reads origin"
    )
    refs = snapshot.get("refs")
    assert isinstance(refs, dict)
    assert {ref: (info["role"], info["name"]) for ref, info in refs.items()} == {
        "e1": ("textbox", "Your name"),
        "e2": ("button", "Go"),
        "e3": ("textbox", ""),
    }, f"snapshot -i refs changed: {refs}; sessions.parse_snapshot reads refs as ref -> role, name"

    count = data_of(driver.run("get", "count", "input[type=password]"), "get count")
    assert count.get("count") == 1, (
        f"get count no longer answers with an integer count: {count}; "
        "Session.password_fields reads data.count"
    )
    url = data_of(driver.run("get", "url"), "get url")
    assert url.get("url") == driver.url, f"get url changed: {url}; Session.current_url reads url"


def test_a_failure_still_comes_back_as_json_with_a_message(driver: Driver) -> None:
    answer = driver.run("click", "@e99")
    assert answer.get("success") is False, f"a click on a missing ref no longer fails: {answer}"
    assert isinstance(answer.get("error"), str)
    assert answer["error"], (
        f"a failure no longer carries a message: {answer}; sessions.parse_response shows it"
    )


def test_the_driver_keeps_its_files_in_the_namespace_directory(driver: Driver) -> None:
    root = driver.runtime / sessions.DRIVER_DIR
    socket_path = driver.paths.driver_dir / "run" / f"{sessions.SESSION_NAME}.sock"
    assert socket_path.is_socket(), (
        f"the daemon socket is no longer at {socket_path.relative_to(driver.runtime)}; "
        "the sandbox binds only SessionPaths.driver_dir, so the browser driver would not reach it"
    )
    assert sorted(path.name for path in root.iterdir()) == ["namespaces"], (
        f"agent-browser now keeps files outside namespaces/ in {root.name}: "
        f"{sorted(path.name for path in root.iterdir())}; they would not be in the sandbox"
    )
    assert sorted(path.name for path in (root / "namespaces").iterdir()) == [SITE], (
        "agent-browser no longer keeps one directory per --namespace"
    )


def test_chrome_runs_with_a_debugging_port_and_the_profile_argument(driver: Driver) -> None:
    (pid,) = driver.main_pids() or pytest.fail(
        "no Chrome main process has --user-data-dir=<profile>; the liveness check in "
        "Session.is_alive finds the browser that way (see valetkey.procs.browser_running)"
    )
    arguments = driver.arguments_of(pid)
    assert any(a.startswith("--remote-debugging-port") for a in arguments), (
        "agent-browser no longer starts Chrome with --remote-debugging-port; the sandbox "
        f"allows loopback inside the namespace for it. Chrome was started with {arguments[:6]}"
    )
    assert not any(a.startswith("--remote-debugging-pipe") for a in arguments), (
        "agent-browser now connects to Chrome over a pipe; check what the sandbox and the "
        "forwarder assume about the debugging port"
    )


def test_calls_built_by_valetkey_never_relaunch_the_browser(driver: Driver) -> None:
    (pid,) = driver.main_pids()
    hashes = set()
    for verb in (("get", "url"), ("snapshot", "-i"), ("get", "count", "input"), ("get", "url")):
        data = data_of(driver.run(*verb), " ".join(verb))
        lifecycle = data.get("lifecycle", {})
        assert lifecycle.get("relaunchedBrowser") is False, (
            f"{verb[0]} {verb[1]} relaunched the browser: {lifecycle}"
        )
        hashes.add(lifecycle.get("effectiveLaunch", {}).get("launchHash"))
    assert len(hashes) == 1, f"the launch changed between plain calls: {hashes}"
    assert driver.main_pids() == [pid], "Chrome was replaced during plain calls"
    assert data_of(driver.run("get", "url"), "get url")["url"] == driver.url


def test_a_launch_option_on_a_later_call_still_relaunches_the_browser(driver: Driver) -> None:
    (pid,) = driver.main_pids()
    driver.raw([driver.binary, "--json", "--user-agent", "probe", "get", "url"])
    page = data_of(driver.run("get", "url"), "get url")["url"]
    relaunched = page == "about:blank"
    assert relaunched, (
        "a launch option on a later call no longer relaunches the browser. valetkey never sends "
        "one, and call_command refuses them; with this change the guard may be relaxed"
    )
    assert pid not in driver.main_pids(), "the old Chrome is still running after the relaunch"


@pytest.mark.parametrize("separator", [(), ("--",)])
def test_option_words_in_arguments_are_still_read_as_options(
    driver: Driver, separator: tuple[str, ...]
) -> None:
    (pid,) = driver.main_pids()
    driver.raw([driver.binary, "--json", "get", "url", *separator, "--user-agent", "probe"])
    page = data_of(driver.run("get", "url"), "get url")["url"]
    ended_options = page == driver.url and pid in driver.main_pids()
    assert not ended_options, (
        "agent-browser now reads an option-like argument after the verb as plain text"
        + (" after `--`" if separator else "")
        + "; the guard in sessions.call_command may be relaxed, at least for text"
    )


def test_the_finalizer_stops_what_close_leaves_behind(
    module_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A test that fails partway, or a ``close`` that fails, must not leak a browser or a daemon."""
    base = Path(tempfile.mkdtemp(prefix="t", dir=module_dir))
    with PageServer({"/": PAGE}) as pages:
        host, port = pages.address
        tool = Driver(base, f"http://{host}:{port}/")
        try:
            assert tool.launch()["success"] is True
            assert belonging_to(base), "no process was found for the running session"

            def broken_close(*_verb: str, **_options: object) -> dict[str, Any]:
                message = "close failed"
                raise OSError(message)

            monkeypatch.setattr(tool, "run", broken_close)
        finally:
            tool.stop()
    assert belonging_to(base) == []
