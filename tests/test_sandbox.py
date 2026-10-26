# SPDX-License-Identifier: Apache-2.0

import contextlib
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from environment import processes_with, unusable_reason
from proxy_stub import ProxyStub, host_of_request

from valetkey import sandbox, seccomp, sites

# --- pure functions -----------------------------------------------------------------------


def make_sandbox(  # noqa: PLR0913  # one keyword per field a test varies
    base: Path,
    *,
    runtime_dir: Path = Path("/run/user/4242"),
    shared_dir: Path | None = None,
    etc_entries: tuple[str, ...] = ("passwd", "ssl"),
    die_with_parent: bool = True,
    wayland_socket: Path | None = None,
    writable_dirs: tuple[Path, ...] = (),
) -> sandbox.Sandbox:
    """A sandbox whose paths all lie under ``base``."""
    return sandbox.Sandbox(
        profile_dir=base / "profile",
        writable_dirs=writable_dirs,
        proxy_socket=base / "proxy" / "p.sock",
        log_file=base / "logs" / "box.log",
        runtime_dir=runtime_dir,
        shared_dir=shared_dir,
        etc_entries=etc_entries,
        die_with_parent=die_with_parent,
        wayland_socket=wayland_socket,
    )


def build(  # noqa: PLR0913  # one keyword per field a test varies
    base: Path,
    command: list[str] | None = None,
    *,
    shared_dir: Path | None = None,
    die_with_parent: bool = True,
    wayland_socket: Path | None = None,
    writable_dirs: tuple[Path, ...] = (),
) -> list[str]:
    return sandbox.bwrap_argv(
        make_sandbox(
            base,
            writable_dirs=writable_dirs,
            shared_dir=shared_dir,
            die_with_parent=die_with_parent,
            wayland_socket=wayland_socket,
        ),
        command or ["chromium"],
        roots=(Path("/opt/venv"), Path("/opt/src")),
        system_links=["--symlink", "usr/lib", "/lib"],
        interpreter_links=[],
    )


def setenvs(argv: list[str]) -> dict[str, str]:
    return {argv[i + 1]: argv[i + 2] for i, arg in enumerate(argv) if arg == "--setenv"}


def pairs(argv: list[str], option: str) -> list[tuple[str, ...]]:
    """The arguments that follow each occurrence of ``option``, as the option takes them."""
    width = {"--bind": 2, "--ro-bind": 2, "--setenv": 2, "--symlink": 2}.get(option, 1)
    return [tuple(argv[i + 1 : i + 1 + width]) for i, arg in enumerate(argv) if arg == option]


@pytest.mark.parametrize(
    ("output", "major"),
    [
        ("Chromium 156.0.8078.47 Arch Linux", 156),
        ("Google Chrome 120.0.6099.109 \n", 120),
        ("Chromium 99.0.4844.84 built on Debian", 99),
    ],
)
def test_parse_chrome_major(output: str, major: int) -> None:
    assert sandbox.parse_chrome_major(output) == major


@pytest.mark.parametrize("output", ["", "Chromium", "version 12.3", "command not found"])
def test_parse_chrome_major_rejects_output_without_a_version(output: str) -> None:
    with pytest.raises(ValueError, match="no version number"):
        sandbox.parse_chrome_major(output)


def test_installed_chrome_major_runs_the_executable(tmp_path: Path) -> None:
    fake = tmp_path / "fakechrome"
    fake.write_text("#!/bin/sh\necho 'Chromium 142.0.7444.1 Test'\n")
    fake.chmod(0o755)
    assert sandbox.installed_chrome_major(str(fake)) == 142


def test_only_the_updater_is_left_as_background_noise() -> None:
    # The new tab page and the AI-mode check are stopped by policy, so a refused
    # www.google.com is a page asking for it. The policy also stops the component updater, which
    # the flag alone does not; the host of the updater stays listed in case a browser asks anyway.
    assert {"update.googleapis.com"} == sandbox.BACKGROUND_HOSTS
    assert sandbox.CHROME_POLICY == {
        "DefaultSearchProviderEnabled": False,
        "ComponentUpdatesEnabled": False,
    }


def test_write_chrome_policy(tmp_path: Path) -> None:
    directory = sandbox.write_chrome_policy(tmp_path / "policy")
    assert directory == tmp_path / "policy"
    written = (directory / "managed" / "valetkey.json").read_text()
    assert json.loads(written) == sandbox.CHROME_POLICY
    assert sandbox.write_chrome_policy(directory) == directory  # again is fine


def test_the_policy_is_bound_read_only_where_chromium_and_chrome_read_it(tmp_path: Path) -> None:
    box = make_sandbox(tmp_path)
    plain = sandbox.bwrap_argv(box, ["true"], roots=(), system_links=[], interpreter_links=[])
    assert not any("policies" in arg for arg in plain)
    with_policy = replace(box, policy_dir=tmp_path / "policy")
    argv = sandbox.bwrap_argv(
        with_policy, ["true"], roots=(), system_links=[], interpreter_links=[]
    )
    ro = pairs(argv, "--ro-bind")
    assert (str(tmp_path / "policy"), "/etc/chromium/policies") in ro
    assert (str(tmp_path / "policy"), "/etc/opt/chrome/policies") in ro


def test_chrome_flags_hold_the_containment_and_quiet_flags() -> None:
    flags = sandbox.chrome_flags(156)
    assert "--proxy-server=http://127.0.0.1:3128" in flags
    assert "--proxy-bypass-list=<-loopback>" in flags
    for flag in (
        "--disable-background-networking",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-session-crashed-bubble",
        "--hide-crash-restore-bubble",
        "--disable-blink-features=AutomationControlled",
    ):
        assert flag in flags
    assert len(flags) == len(set(flags))


def test_chrome_flags_can_leave_out_the_automation_flag() -> None:
    quiet = sandbox.chrome_flags(156, hide_automation=False)
    assert not any("AutomationControlled" in flag for flag in quiet)
    assert quiet == [f for f in sandbox.chrome_flags(156) if "AutomationControlled" not in f]


def test_chrome_user_agent_names_the_installed_major() -> None:
    agent = next(f for f in sandbox.chrome_flags(131) if f.startswith("--user-agent="))
    assert "Chrome/131.0.0.0" in agent
    assert "Headless" not in agent
    assert sandbox.chrome_flags(131) != sandbox.chrome_flags(132)


def test_argv_unshares_everything_and_ends_with_the_command(tmp_path: Path) -> None:
    argv = build(tmp_path, ["chromium", "--headless=new"])
    assert argv[0] == "bwrap"
    for flag in ("--unshare-all", "--new-session", "--die-with-parent", "--clearenv"):
        assert flag in argv
    assert "--share-net" not in argv
    chdir = argv.index("--chdir")
    assert argv[chdir : chdir + 2] == ["--chdir", sandbox.SANDBOX_HOME]
    assert argv[chdir + 2 : chdir + 4] == ["/usr/bin/sh", "-c"]
    assert argv[chdir + 5 :] == ["sh", "chromium", "--headless=new"]
    assert f"ulimit -n {sandbox.MAX_OPEN_FILES}" in argv[chdir + 4]
    assert f"ulimit -u {sandbox.MAX_PROCESSES}" in argv[chdir + 4]


def test_argv_has_no_display_by_default(tmp_path: Path) -> None:
    argv = build(tmp_path)
    assert "WAYLAND_DISPLAY" not in setenvs(argv)
    assert not any("wayland" in arg for arg in argv)


def test_argv_binds_only_the_wayland_socket_into_the_private_runtime_dir(tmp_path: Path) -> None:
    host_socket = Path("/run/user/1000/wayland-7")
    argv = build(tmp_path, wayland_socket=host_socket)
    assert ("/run/user/1000/wayland-7", "/run/user/4242/wayland-7") in pairs(argv, "--bind")
    assert setenvs(argv)["WAYLAND_DISPLAY"] == "wayland-7"
    # The socket is mounted into the tmpfs runtime directory, so the tmpfs comes first.
    assert argv.index("--tmpfs") < argv.index("/run/user/1000/wayland-7") < argv.index("--clearenv")
    assert "/run/user/1000" not in argv
    assert "--dev-bind" not in argv


def test_argv_can_leave_out_die_with_parent(tmp_path: Path) -> None:
    assert "--die-with-parent" not in build(tmp_path, die_with_parent=False)


def test_argv_binds_nothing_broad(tmp_path: Path) -> None:
    argv = build(tmp_path)
    assert "--dev-bind" not in argv
    assert "--dev-bind-try" not in argv
    sources = [src for flag in ("--bind", "--ro-bind") for src, _ in pairs(argv, flag)]
    home = str(Path.home())
    for source in sources:
        assert source not in {"/", "/etc", "/home", "/run", "/var", home, str(Path(home).parent)}
        assert not Path(home).is_relative_to(source) or source == "/usr"
        assert not source.startswith("/run/user/4242"), source


def test_argv_system_directories_are_read_only(tmp_path: Path) -> None:
    argv = build(tmp_path)
    ro = pairs(argv, "--ro-bind")
    assert ("/usr", "/usr") in ro
    assert ("/etc/passwd", "/etc/passwd") in ro
    assert ("/etc/ssl", "/etc/ssl") in ro
    assert ("/opt/venv", "/opt/venv") in ro
    assert ("/opt/src", "/opt/src") in ro
    assert ("usr/lib", "/lib") in pairs(argv, "--symlink")
    assert argv[argv.index("--dev") + 1] == "/dev"
    assert argv[argv.index("--proc") + 1] == "/proc"


def test_argv_writes_only_where_it_was_told(tmp_path: Path) -> None:
    argv = build(
        tmp_path,
        shared_dir=tmp_path / "shared",
        writable_dirs=(tmp_path / "downloads" / ".incoming", tmp_path / "downloads" / ".shots"),
    )
    writable = {src for src, _ in pairs(argv, "--bind")}
    assert writable == {
        str(tmp_path / "profile"),
        str(tmp_path / "downloads" / ".incoming"),
        str(tmp_path / "downloads" / ".shots"),
        str(tmp_path / "proxy" / "p.sock"),
        str(tmp_path / "shared"),
    }
    for src, dest in pairs(argv, "--bind"):
        assert src == dest


def test_argv_binds_a_shared_directory_once(tmp_path: Path) -> None:
    argv = build(tmp_path, shared_dir=tmp_path / "shared")
    assert [src for src, _ in pairs(argv, "--bind")].count(str(tmp_path / "shared")) == 1


def test_argv_tmpfs_come_before_every_bind_that_may_sit_inside_them(tmp_path: Path) -> None:
    argv = build(tmp_path, shared_dir=Path("/run/user/4242/agent-browser"))
    mounts = [path for (path,) in pairs(argv, "--tmpfs")]
    assert set(mounts) == {"/tmp", "/run/user/4242", sandbox.SANDBOX_HOME}  # noqa: S108  # inside
    last_tmpfs = max(argv.index(path) for path in mounts)
    later = [
        src
        for flag in ("--bind", "--ro-bind")
        for src, _ in pairs(argv, flag)
        if src.startswith("/")
    ]
    positions = {src: argv.index(src) for src in later if not src.startswith(("/usr", "/etc"))}
    assert "/opt/venv" in positions
    assert all(position > last_tmpfs for position in positions.values())


def test_argv_environment_is_cleared_then_minimal(tmp_path: Path) -> None:
    argv = build(tmp_path)
    assert argv.index("--clearenv") < argv.index("--setenv")
    assert setenvs(argv) == {
        "PATH": "/usr/bin",
        "HOME": sandbox.SANDBOX_HOME,
        "XDG_RUNTIME_DIR": "/run/user/4242",
        "LANG": "C.UTF-8",
    }


def test_argv_defaults_come_from_the_host(tmp_path: Path) -> None:
    argv = sandbox.bwrap_argv(replace(make_sandbox(tmp_path), etc_entries=()), ["true"])
    assert ("/usr", "/usr") in pairs(argv, "--ro-bind")
    assert ("/etc/ld.so.cache", "/etc/ld.so.cache") in pairs(argv, "--ro-bind")
    assert str(Path(sys.prefix)) in {src for src, _ in pairs(argv, "--ro-bind")}


def test_default_etc_entries_skip_what_is_missing(tmp_path: Path) -> None:
    (tmp_path / "passwd").touch()
    (tmp_path / "ssl").mkdir()
    (tmp_path / "hosts").touch()
    assert sandbox.default_etc_entries(tmp_path) == ("ssl", "passwd")


def test_system_link_args(tmp_path: Path) -> None:
    (tmp_path / "usr" / "lib").mkdir(parents=True)
    (tmp_path / "lib").symlink_to("usr/lib")
    (tmp_path / "bin").mkdir()
    assert sandbox.system_link_args(tmp_path) == [
        "--ro-bind",
        "/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
    ]


def test_python_roots_leave_out_system_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sys, "prefix", str(tmp_path / "venv"))
    monkeypatch.setattr(sys, "base_prefix", "/usr")
    roots = sandbox.python_roots()
    assert roots[0] == tmp_path / "venv"
    assert Path(sandbox.valetkey.__file__).resolve().parent.parent in roots
    assert all(not root.is_relative_to("/usr") for root in roots)


def uv_layout(base: Path) -> tuple[Path, Path, Path]:
    """Build venv/bin/python -> alias/bin/python3, alias -> real, real/bin/python3 -> /usr."""
    real, alias, venv = base / "python-3.14.9", base / "python-3.14", base / "venv"
    (real / "bin").mkdir(parents=True)
    (real / "bin" / "python3").symlink_to("/usr/bin/python3")
    alias.symlink_to("python-3.14.9")
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").symlink_to(alias / "bin" / "python3")
    return venv, alias, real


def test_interpreter_links_recreate_a_uv_style_alias(tmp_path: Path) -> None:
    venv, alias, real = uv_layout(tmp_path)
    args = sandbox.interpreter_link_args(venv / "bin" / "python", (venv, real))
    assert args == ["--symlink", "python-3.14.9", str(alias)]


def test_interpreter_links_skip_what_the_sandbox_has_already(tmp_path: Path) -> None:
    venv, _, real = uv_layout(tmp_path)
    assert sandbox.interpreter_link_args(Path("/usr/bin/python3"), ()) == []
    # Every link here sits in a bound directory, so none is recreated.
    assert sandbox.interpreter_link_args(venv / "bin" / "python", (tmp_path,)) == []
    assert real.is_dir()


def test_interpreter_links_follow_relative_targets(tmp_path: Path) -> None:
    (tmp_path / "a" / "bin").mkdir(parents=True)
    (tmp_path / "a" / "bin" / "python").symlink_to("../../b/bin/python")
    (tmp_path / "b" / "bin").mkdir(parents=True)
    (tmp_path / "b" / "bin" / "python").touch()
    args = sandbox.interpreter_link_args(tmp_path / "a" / "bin" / "python", ())
    assert args == ["--symlink", "../../b/bin/python", str(tmp_path / "a" / "bin" / "python")]


def test_interpreter_links_stop_at_a_loop(tmp_path: Path) -> None:
    (tmp_path / "a").symlink_to(tmp_path / "b")
    (tmp_path / "b").symlink_to(tmp_path / "a")
    args = sandbox.interpreter_link_args(tmp_path / "a", ())
    assert args.count("--symlink") == 2


def test_a_link_in_the_home_never_makes_its_surroundings_visible(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """~/.local/bin/python3 -> /usr/bin/python3: only the link appears, not ~/.local."""
    home = tmp_path / "home"
    (home / ".local" / "bin").mkdir(parents=True)
    (home / ".local" / "share" / "keyrings").mkdir(parents=True)
    link = home / ".local" / "bin" / "python3"
    link.symlink_to("/usr/bin/python3")
    monkeypatch.setattr(sys, "executable", str(link))
    monkeypatch.setattr(sys, "prefix", "/usr")
    monkeypatch.setattr(sys, "base_prefix", "/usr")
    argv = sandbox.bwrap_argv(make_sandbox(tmp_path), ["true"], system_links=[])
    bound = [argv[i + 1] for i, arg in enumerate(argv) if arg in {"--bind", "--ro-bind"}]
    assert not [path for path in bound if str(home) in path or path == str(home / ".local")]
    assert ("/usr/bin/python3", str(link)) in pairs(argv, "--symlink")
    assert not any("keyrings" in arg for arg in argv)


def test_python_roots_list_a_shared_prefix_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sys, "prefix", str(tmp_path))
    monkeypatch.setattr(sys, "base_prefix", str(tmp_path))
    assert sandbox.python_roots().count(tmp_path) == 1


def test_default_runtime_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/7")
    assert sandbox.default_runtime_dir() == Path("/run/user/7")
    monkeypatch.delenv("XDG_RUNTIME_DIR")
    with pytest.raises(sites.RuntimeDirUnavailableError, match="XDG_RUNTIME_DIR"):
        sandbox.default_runtime_dir()


def test_bridge_command_names_the_listener_and_the_socket(tmp_path: Path) -> None:
    assert sandbox.bridge_command(tmp_path / "p.sock") == [
        sys.executable,
        "-m",
        "valetkey.nsbridge",
        "--listen",
        "127.0.0.1:3128",
        "--connect",
        str(tmp_path / "p.sock"),
    ]


def test_start_sends_output_to_the_log_file_and_not_to_a_pipe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, object] = {}

    def fake_popen(argv: list[str], **kwargs: object) -> str:
        seen.update(kwargs, argv=argv)
        return "process"

    monkeypatch.setattr(sandbox.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(sandbox.seccomp, "open_filter", lambda **_: None)
    box = make_sandbox(tmp_path)
    assert sandbox.start(box, ["true"]) == "process"
    assert seen["argv"] == sandbox.bwrap_argv(box, ["true"])
    assert seen["pass_fds"] == ()
    assert seen["stdin"] == subprocess.DEVNULL
    assert seen["stderr"] == subprocess.STDOUT
    assert getattr(seen["stdout"], "name", None) == str(box.log_file)
    assert box.log_file.exists()


def test_start_hands_the_filter_to_bwrap_and_closes_its_own_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def fake_popen(argv: list[str], **kwargs: Any) -> str:  # noqa: ANN401 - Popen's own keywords
        (descriptor,) = kwargs["pass_fds"]
        assert argv[argv.index("--seccomp") + 1] == str(descriptor)
        seen["program"] = os.read(descriptor, 4096)  # the child reads it from the start
        seen["descriptor"] = descriptor
        return "process"

    monkeypatch.setattr(sandbox.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(sandbox.seccomp, "available", lambda *_: True)
    box = make_sandbox(tmp_path)
    sandbox.start(box, ["true"])
    assert seen["program"] == seccomp.program()
    with pytest.raises(OSError, match="Bad file descriptor"):
        os.fstat(seen["descriptor"])
    sandbox.start(replace(box, allow_ptrace=True), ["true"])
    assert seen["program"] == seccomp.program(allow_ptrace=True)


def test_start_runs_bwrap_as_the_program_of_a_wrapper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[list[str]] = []
    monkeypatch.setattr(
        sandbox.subprocess, "Popen", lambda argv, **_: seen.append(argv) or "process"
    )
    monkeypatch.setattr(sandbox.seccomp, "open_filter", lambda **_: None)
    box = replace(make_sandbox(tmp_path), wrapper=("setpriv", "--pdeathsig", "SIGTERM", "waypipe"))
    sandbox.start(box, ["true"])
    sandbox.start(replace(box, wrapper=()), ["true"])
    assert seen[0] == [
        "setpriv",
        "--pdeathsig",
        "SIGTERM",
        "waypipe",
        *sandbox.bwrap_argv(box, ["true"]),
    ]
    assert seen[1][0] == "bwrap"
    # The limits are set by the command inside the namespace, so they hold behind a wrapper too.
    for argv in seen:
        limits = next(arg for arg in argv if arg.startswith("ulimit -n"))
        assert argv.index(limits) > argv.index("bwrap")
        assert argv[-2:] == ["sh", "true"]
    # The wrapper is not part of the namespace's own command line.
    assert sandbox.bwrap_argv(box, ["true"]) == sandbox.bwrap_argv(
        replace(box, wrapper=()), ["true"]
    )


# --- integration: a real namespace --------------------------------------------------------


_SKIP_REASON = unusable_reason("bwrap", "chromium")
integration = pytest.mark.integration
needs_namespaces = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")


@pytest.fixture
def box(short_dir: Path) -> sandbox.Sandbox:
    for name in ("profile", "downloads", "proxy", "run"):
        (short_dir / name).mkdir()
    return make_sandbox(short_dir, runtime_dir=short_dir / "run", etc_entries=())


def run_inside(box: sandbox.Sandbox, command: list[str], timeout: float = 60) -> tuple[int, str]:
    """Run ``command`` in the namespace and return its exit status and the log."""
    if not box.proxy_socket.exists():  # the proxy is up before a sandbox starts
        with socket.socket(socket.AF_UNIX) as placeholder:
            placeholder.bind(str(box.proxy_socket))
    process = sandbox.start(box, command)
    status = process.wait(timeout=timeout)
    return status, box.log_file.read_text()


def run_python(box: sandbox.Sandbox, code: str, *args: str) -> tuple[int, str]:
    return run_inside(box, [sys.executable, "-I", "-c", code, *args])


_INSIDE_PROBE = """
import errno, json, os, socket
from pathlib import Path
from typing import Any
out = {}
out["env"] = sorted(os.environ)
out["missing"] = {}
for path in json.loads(os.environ.get("PROBE", "[]")):
    out["missing"][path] = Path(path).exists()
print(json.dumps(out))
"""


@integration
@needs_namespaces
def test_forbidden_paths_do_not_exist_inside(box: sandbox.Sandbox) -> None:
    uid = os.getuid()
    forbidden = [
        os.environ.get("SSH_AUTH_SOCK", "/nonexistent/ssh-agent"),
        f"/run/user/{uid}/gnupg",
        f"/run/user/{uid}/gnupg/S.gpg-agent",
        f"/run/user/{uid}/bus",
        "/run/docker.sock",
        "/var/run/docker.sock",
        "/run/dbus/system_bus_socket",
        "/run/systemd/resolve",
        "/run/systemd/resolve/io.systemd.Resolve",
        "/etc/resolv.conf",
        "/etc/shadow",
        str(Path.home() / ".ssh"),
        str(Path.home() / ".gnupg"),
        str(Path.home() / ".config"),
    ]
    code = (
        "import os, sys\n"
        "from pathlib import Path\n"
        "print([p for p in sys.argv[1:] if os.path.lexists(p)])\n"
        "print(sorted(os.environ))\n"
        "print(sorted(Path(os.environ['XDG_RUNTIME_DIR']).iterdir()))\n"
    )
    status, log = run_python(box, code, *forbidden)
    lines = log.splitlines()
    assert status == 0, log
    assert lines == ["[]", str(["HOME", "LANG", "PATH", "PWD", "XDG_RUNTIME_DIR"]), "[]"]


def bound_paths(box: sandbox.Sandbox) -> list[Path]:
    """Every path outside the system directories that the real argv binds or links.

    A link, such as uv's alias for its interpreter directory, shows up inside as a name beside
    the bound directory and nothing else.
    """
    argv = sandbox.bwrap_argv(box, ["true"])
    system = ("/usr", "/etc", "/bin", "/sbin", "/lib")
    return [
        *(
            Path(src)
            for flag in ("--bind", "--ro-bind")
            for src, _ in pairs(argv, flag)
            if not src.startswith(system)
        ),
        *(Path(link) for _, link in pairs(argv, "--symlink") if not link.startswith(system)),
    ]


@integration
@needs_namespaces
def test_home_exists_only_as_the_path_to_a_bound_directory(box: sandbox.Sandbox) -> None:
    """Wherever the project or the profile lives, each parent directory shows only the way down."""
    bound = bound_paths(box)
    directories = {Path("/home"), Path.home()}
    for path in bound:
        directories.update(parent for parent in path.parents if parent.is_relative_to("/home"))
    expected: dict[str, list[str]] = {}
    for directory in directories:
        if any(directory.is_relative_to(path) for path in bound):
            continue  # inside a bound directory, whose contents are the point
        below = {
            path.parts[len(directory.parts)] for path in bound if path.is_relative_to(directory)
        }
        if directory == Path("/home"):
            below.add("valetkey")  # the throwaway home
        expected[str(directory)] = sorted(below)
    code = (
        "import json, os, sys\n"
        "expected = json.loads(sys.argv[1])\n"
        "seen = {d: sorted(os.listdir(d)) if os.path.isdir(d) else [] for d in expected}\n"
        "print(json.dumps(seen == expected), json.dumps(seen))\n"
    )
    status, log = run_python(box, code, json.dumps(expected))
    assert status == 0, log
    assert log.startswith("true"), f"expected {expected}, inside saw {log}"


@integration
@needs_namespaces
def test_only_the_bound_directories_of_a_home_are_visible(
    box: sandbox.Sandbox, short_dir: Path
) -> None:
    home = short_dir / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "id_ed25519").write_text("secret")
    (home / "notes.txt").write_text("private")
    profile = home / ".cache" / "profile"
    profile.mkdir(parents=True)
    code = (
        "import os\n"
        f"print(sorted(os.listdir({str(home)!r})))\n"
        f"print(sorted(os.listdir({str(home / '.cache')!r})))\n"
        f"print(os.path.exists({str(home / '.ssh')!r}))\n"
    )
    status, log = run_python(replace(box, profile_dir=profile), code)
    assert status == 0, log
    assert log.splitlines() == ["['.cache']", "['profile']", "False"]


@integration
@needs_namespaces
def test_network_is_unreachable_and_dns_fails(box: sandbox.Sandbox) -> None:
    code = """
import errno, socket
def attempt(kind, address):
    s = socket.socket(socket.AF_INET, kind)
    s.settimeout(5)
    try:
        s.connect(address)
    except OSError as error:
        return errno.errorcode[error.errno]
    return "connected"
print("tcp", attempt(socket.SOCK_STREAM, ("1.1.1.1", 443)))
print("udp", attempt(socket.SOCK_DGRAM, ("8.8.8.8", 53)))
try:
    socket.getaddrinfo("example.com", 443)
except socket.gaierror:
    print("dns failed")
print("interfaces", [name for _, name in socket.if_nameindex()])
"""
    status, log = run_python(box, code)
    assert status == 0, log
    assert "tcp ENETUNREACH" in log
    assert "udp ENETUNREACH" in log
    assert "dns failed" in log
    assert "interfaces ['lo']" in log


@integration
@needs_namespaces
def test_bridge_forwards_to_the_proxy_socket_on_the_host(box: sandbox.Sandbox) -> None:
    code = """
import socket, subprocess, sys, time
bridge = subprocess.Popen(sys.argv[1:])
try:
    for _ in range(100):
        try:
            conn = socket.create_connection(("127.0.0.1", 3128), timeout=5)
            break
        except OSError:
            time.sleep(0.1)
    conn.sendall(b"GET http://site.test/ HTTP/1.1\\r\\nHost: site.test\\r\\n\\r\\n")
    data = b""
    while chunk := conn.recv(4096):
        data += chunk
    print(data.decode())
finally:
    bridge.kill()
"""
    with ProxyStub(box.proxy_socket) as stub:
        status, log = run_python(box, code, *sandbox.bridge_command(box.proxy_socket))
    assert status == 0, log
    assert "proxied page" in log
    assert stub.requests[0].startswith("GET http://site.test/ HTTP/1.1")


@integration
@needs_namespaces
def test_shared_directory_is_visible_from_both_sides(box: sandbox.Sandbox) -> None:
    shared = box.runtime_dir / "agent-browser"
    shared.mkdir()
    (shared / "from-host").write_text("host")
    inside = replace(box, shared_dir=shared)
    code = (
        "from pathlib import Path\n"
        f"d = Path({str(shared)!r})\n"
        "print((d / 'from-host').read_text())\n"
        "(d / 'from-inside').write_text('inside')\n"
    )
    status, log = run_python(inside, code)
    assert status == 0, log
    assert log.strip() == "host"
    assert (shared / "from-inside").read_text() == "inside"


@integration
@needs_namespaces
def test_system_directories_are_read_only_and_other_writes_stay_inside(
    box: sandbox.Sandbox,
) -> None:
    code = """
for path in ("/usr/valetkey-probe", "/etc/valetkey-probe"):
    try:
        open(path, "w").close()
    except OSError as error:
        print(path, error.strerror)
"""
    status, log = run_python(box, code)
    assert status == 0, log
    assert "/usr/valetkey-probe Read-only file system" in log
    # /etc is a scratch directory of bind mounts: the write succeeds but never reaches the host.
    assert not Path("/etc/valetkey-probe").exists()


@integration
@needs_namespaces
def test_background_processes_end_with_the_first_command(box: sandbox.Sandbox) -> None:
    # Only this test's sleeper carries this number, so a sleeper of someone else's is not mistaken
    # for it.
    sleeper = f"sleep 300.{secrets.randbelow(10**9):09d}"
    status, log = run_inside(box, ["/usr/bin/sh", "-c", f"{sleeper} & echo started"])
    assert status == 0, log
    left = processes_with(sleeper)
    for pid in left:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)  # a failure here must not leave it running
    assert left == []


_CHROMIUM_DRIVER = """
import json, socket, subprocess, sys, time
flags, bridge = json.loads(sys.argv[1]), json.loads(sys.argv[2])
helper = subprocess.Popen(bridge)
try:
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", 3128), timeout=5).close()
            break
        except OSError:
            time.sleep(0.1)
    result = subprocess.run(
        ["/usr/bin/chromium", "--headless=new", "--dump-dom", "--user-data-dir=" + sys.argv[3],
         *flags, "http://site.test/"],
        stdin=subprocess.DEVNULL, timeout=60, check=False,
    )
    sys.exit(result.returncode)
finally:
    helper.kill()
"""


@integration
@needs_namespaces
def test_chromium_loads_a_page_through_the_bridge(box: sandbox.Sandbox) -> None:
    flags = sandbox.chrome_flags(sandbox.installed_chrome_major())
    bridge = sandbox.bridge_command(box.proxy_socket)
    policy = sandbox.write_chrome_policy(box.profile_dir.parent / "policy")
    with ProxyStub(box.proxy_socket) as stub:
        status, log = run_python(
            replace(box, policy_dir=policy),
            _CHROMIUM_DRIVER,
            json.dumps(flags),
            json.dumps(bridge),
            str(box.profile_dir),
        )
    assert status == 0, log
    assert "proxied page" in log
    request = next(r for r in stub.requests if r.startswith("GET http://site.test/ HTTP/1.1"))
    assert "Chrome/" in request
    assert "HeadlessChrome" not in request
    # With the policy, Chrome contacts the page's host and nothing else, bar the updater.
    assert {host_of_request(r) for r in stub.requests} - sandbox.BACKGROUND_HOSTS == {"site.test"}


@integration
@needs_namespaces
def test_a_uv_style_interpreter_runs_inside_the_namespace(
    box: sandbox.Sandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The environment's python is a link to a link; both must resolve inside the sandbox."""
    venv, alias, real = uv_layout(box.profile_dir.parent / "py")
    monkeypatch.setattr(sys, "executable", str(venv / "bin" / "python"))
    monkeypatch.setattr(sys, "prefix", str(venv))
    monkeypatch.setattr(sys, "base_prefix", str(real))
    status, log = run_inside(box, [str(venv / "bin" / "python"), "-c", "print('resolved')"])
    assert status == 0, log
    assert log.strip() == "resolved"
    # The alias is a link in there too, and nothing around the real directory came with it.
    box.log_file.unlink()
    status, log = run_inside(
        box, ["/usr/bin/sh", "-c", f"test -L {alias} && ls {alias.parent} | sort"]
    )
    assert status == 0, log
    assert log.split() == sorted([alias.name, real.name, venv.name])


@integration
@needs_namespaces
def test_the_browser_finds_its_policy_inside_the_namespace(box: sandbox.Sandbox) -> None:
    policy = sandbox.write_chrome_policy(box.profile_dir.parent / "policy")
    inside = replace(box, policy_dir=policy)
    code = (
        "import json\n"
        "for root in ('/etc/chromium', '/etc/opt/chrome'):\n"
        "    print(json.load(open(root + '/policies/managed/valetkey.json')))\n"
        "try:\n"
        "    open('/etc/chromium/policies/managed/other.json', 'w')\n"
        "except OSError as error:\n"
        "    print(error.strerror)\n"
    )
    status, log = run_python(inside, code)
    assert status == 0, log
    assert log.splitlines() == [str(sandbox.CHROME_POLICY)] * 2 + ["Read-only file system"]


def test_a_driver_call_runs_in_a_namespace_without_network_or_the_persons_files(
    tmp_path: Path,
) -> None:
    driver = tmp_path / "rt" / "agent-browser" / "namespaces" / "demo"
    config = tmp_path / "rt" / "valetkey" / "agent-browser.json"
    environment = {"PATH": "/home/me/bin", "HOME": "/home/me", "AGENT_BROWSER_SESSION": "s"}
    argv = sandbox.isolated_call_argv(
        ["/opt/ab/agent-browser", "--json", "snapshot"],
        environment,
        runtime_dir=tmp_path / "rt",
        driver_dir=driver,
        read_only=[Path("/usr/bin/other"), config, Path("/opt/ab/agent-browser")],
        system_links=["--symlink", "usr/bin", "/bin"],
    )
    assert argv[:7] == [
        "bwrap",
        "--unshare-all",
        "--new-session",
        "--hostname",
        "valetkey",
        "--die-with-parent",
        "--ro-bind",
    ]
    binds = [argv[i : i + 3] for i, word in enumerate(argv) if word in {"--bind", "--ro-bind"}]
    assert ["--bind", str(driver), str(driver)] in binds
    assert ["--ro-bind", str(config), str(config)] in binds
    assert ["--ro-bind", "/opt/ab/agent-browser", "/opt/ab/agent-browser"] in binds
    assert ["--ro-bind", "/usr/bin/other", "/usr/bin/other"] not in binds  # /usr is bound anyway
    assert not [b for b in binds if b[1].startswith(("/home", "/root"))]
    assert argv[argv.index("--clearenv") :][:7] == [
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin",
        "--setenv",
        "HOME",
        sandbox.SANDBOX_HOME,
    ]
    assert argv[
        argv.index("AGENT_BROWSER_SESSION") - 1 : argv.index("AGENT_BROWSER_SESSION") + 2
    ] == ["--setenv", "AGENT_BROWSER_SESSION", "s"]
    assert argv[-3:] == ["/opt/ab/agent-browser", "--json", "snapshot"]


@integration
@needs_namespaces
def test_the_proxy_socket_cannot_be_removed_or_replaced_from_inside(box: sandbox.Sandbox) -> None:
    code = """
import errno, os, sys
from pathlib import Path
from typing import Any
path = Path(sys.argv[1])
results = {}


def replace():
    other = Path(str(path) + ".new")
    other.write_text("x")
    os.replace(other, path)


for name, action in {
    "unlink": path.unlink,
    "rename": lambda: path.rename(path.with_name("moved")),
    "replace": replace,
    "rmdir": path.parent.rmdir,
}.items():
    try:
        action()
        results[name] = "worked"
    except OSError as error:
        results[name] = errno.errorcode[error.errno]
print(results)
print("still a socket:", path.is_socket())
"""
    with ProxyStub(box.proxy_socket):
        status, log = run_python(box, code, str(box.proxy_socket))
        assert box.proxy_socket.is_socket()
    assert status == 0, log
    assert "'unlink': 'EBUSY'" in log
    assert "'rename': 'EBUSY'" in log
    assert "'replace': 'EBUSY'" in log
    assert "worked" not in log
    assert "still a socket: True" in log


@integration
@needs_namespaces
def test_the_browser_sees_and_writes_only_its_download_folders(box: sandbox.Sandbox) -> None:
    """The folder the person reads is not bound: nothing inside reaches what is delivered there."""
    delivered = box.profile_dir.parent / "downloads"
    (delivered / ".incoming").mkdir()
    (delivered / ".shots").mkdir()
    (delivered / "invoice.txt").write_text("delivered")
    box = replace(box, writable_dirs=(delivered / ".incoming", delivered / ".shots"))
    code = """
import os, sys
from pathlib import Path
from typing import Any
delivered = Path(sys.argv[1])
print("sees", sorted(entry.name for entry in delivered.iterdir()))
for action in (
    lambda: (delivered / "new.txt").write_text("x"),
    lambda: os.symlink("/etc/passwd", delivered / "link"),
    lambda: (delivered / "invoice.txt").write_text("changed"),
    lambda: (delivered / "dir").mkdir(),
):
    action()  # these land in the namespace's own temporary file system, not on the host
(delivered / ".incoming" / "a.bin").write_text("x")
(delivered / ".shots" / "s.png").write_text("x")
"""
    status, log = run_python(box, code, str(delivered))
    assert status == 0, log
    assert "sees ['.incoming', '.shots']" in log  # the delivered file is not even visible
    # On the host, the delivered folder is as it was, and only the two bound folders took files.
    assert sorted(entry.name for entry in delivered.iterdir()) == [
        ".incoming",
        ".shots",
        "invoice.txt",
    ]
    assert (delivered / "invoice.txt").read_text() == "delivered"
    assert (delivered / ".incoming" / "a.bin").is_file()
    assert (delivered / ".shots" / "s.png").is_file()


@integration
@needs_namespaces
def test_the_sandbox_limits_descriptors_and_tasks_and_they_cannot_be_raised(
    box: sandbox.Sandbox,
) -> None:
    code = """
import resource
for name in ("RLIMIT_NOFILE", "RLIMIT_NPROC"):
    limit = getattr(resource, name)
    print(name, resource.getrlimit(limit))
    try:
        resource.setrlimit(limit, (1 << 20, 1 << 20))
        print(name, "raised")
    except (ValueError, OSError) as error:
        print(name, "cannot be raised:", type(error).__name__)
"""
    status, log = run_python(box, code)
    assert status == 0, log
    assert f"RLIMIT_NOFILE ({sandbox.MAX_OPEN_FILES}, {sandbox.MAX_OPEN_FILES})" in log
    assert f"RLIMIT_NPROC ({sandbox.MAX_PROCESSES}, {sandbox.MAX_PROCESSES})" in log
    assert "raised\n" not in log.replace("cannot be raised", "")
    assert log.count("cannot be raised") == 2


_FILTER_PROBE = """
import ctypes, errno, os
libc = ctypes.CDLL(None, use_errno=True)
lines = open("/proc/self/status").read().splitlines()
print("Seccomp:", next(line for line in lines if line.startswith("Seccomp:")).split()[1])
for name, number in (("keyctl", 250), ("bpf", 321), ("userfaultfd", 323), ("perf_event_open", 298),
                     ("mount", 165), ("process_vm_readv", 310), ("ptrace", 101)):
    ctypes.set_errno(0)
    result = libc.syscall(number, 0, 0, 0, 0, 0, 0)
    print(name, result, errno.errorcode.get(ctypes.get_errno()))
ctypes.set_errno(0)
print("getpid", libc.syscall(39) == os.getpid())
"""


@integration
@needs_namespaces
def test_the_filter_holds_inside_the_namespace(box: sandbox.Sandbox) -> None:
    status, log = run_python(box, _FILTER_PROBE)
    assert status == 0, log
    assert "Seccomp: 2" in log
    for name in ("keyctl", "bpf", "userfaultfd", "perf_event_open", "mount", "process_vm_readv"):
        assert f"{name} -1 EPERM" in log
    assert "ptrace -1 EPERM" in log
    assert "getpid True" in log  # the calls the browser makes are untouched


@integration
@needs_namespaces
def test_ptrace_is_possible_only_when_the_option_is_set(box: sandbox.Sandbox) -> None:
    status, log = run_python(replace(box, allow_ptrace=True), _FILTER_PROBE)
    assert status == 0, log
    assert "Seccomp: 2" in log
    assert "keyctl -1 EPERM" in log
    assert "ptrace -1 EPERM" not in log  # not refused by the filter (the kernel answers)
