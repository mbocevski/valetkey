# SPDX-License-Identifier: Apache-2.0

import io
import json
import os
import runpy
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

import pytest

from valetkey import __version__, cli, daemon, mcp_server, sandbox, sites
from valetkey.cli import main

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence


def test_without_arguments_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "Usage: valetkey" in capsys.readouterr().out


def test_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--help"]) == 0
    out = capsys.readouterr().out
    assert "Usage: valetkey" in out
    assert "--version" in out


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == f"valetkey {__version__}"


def test_unknown_option_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--no-such-option"])
    assert exit_info.value.code == 2
    captured = capsys.readouterr()
    assert "--no-such-option" in captured.out + captured.err


def test_module_entry_point(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "argv", ["valetkey"])
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("valetkey", run_name="__main__")
    assert exit_info.value.code == 0
    assert "Usage: valetkey" in capsys.readouterr().out


def test_runs_as_a_module_in_a_subprocess() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "valetkey", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == f"valetkey {__version__}"


# -- site commands -----------------------------------------------------------------------


@pytest.fixture
def roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> sites.Roots:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    # No real daemon of the person running the tests may be reached.
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    return sites.roots_from_env()


def make_site(
    roots: sites.Roots,
    name: str = "sitex",
    allow: tuple[str, ...] = ("sitex.com",),
    excluded: tuple[str, ...] = (),
    learned: datetime | None = None,
) -> sites.Policy:
    policy = sites.Policy(name, f"https://app.{name}.com/", allow, excluded, learned)
    sites.save_policy(roots, policy)
    return policy


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    status = main(list(argv))
    captured = capsys.readouterr()
    return status, captured.out, captured.err


@pytest.mark.usefixtures("roots")
def test_sites_with_none(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(capsys, "sites") == (0, "No sites yet.\n", "")
    assert run(capsys, "sites", "--json") == (0, "[]\n", "")


def test_sites_lists_one_and_several(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(
        roots,
        "sitex",
        ("sitex.com", "login.okta.com"),
        ("t.example",),
        datetime(2026, 10, 26, 9, 0, tzinfo=UTC),
    )
    sites.ensure_profile(roots, "sitex")
    status, out, _ = run(capsys, "sites")
    assert status == 0
    assert out.splitlines() == [
        "SITE   HOST           ALLOWED  EXCLUDED  LEARNED               PROFILE",
        "sitex  app.sitex.com  2        1         2026-10-26T09:00:00Z  yes",
    ]
    make_site(roots, "another")
    status, out, _ = run(capsys, "sites")
    assert [line.split()[0] for line in out.splitlines()] == ["SITE", "another", "sitex"]
    assert out.splitlines()[1].split()[-2:] == ["never", "no"]


def test_sites_json_shape(roots: sites.Roots, capsys: pytest.CaptureFixture[str]) -> None:
    make_site(roots, "sitex", learned=datetime(2026, 10, 26, 9, 0, tzinfo=UTC))
    make_site(roots, "another")
    sites.ensure_profile(roots, "another")
    _, out, _ = run(capsys, "sites", "--json")
    assert json.loads(out) == [
        {
            "site": "another",
            "host": "app.another.com",
            "allowed": 1,
            "excluded": 0,
            "learned": None,
            "profile": True,
        },
        {
            "site": "sitex",
            "host": "app.sitex.com",
            "allowed": 1,
            "excluded": 0,
            "learned": "2026-10-26T09:00:00Z",
            "profile": False,
        },
    ]


def test_sites_skips_unreadable_policies_and_odd_files(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots)
    directory = sites.policy_path(roots, "x").parent
    (directory / "broken.json").write_text("{", encoding="utf-8")
    (directory / "Not A Name.json").write_text("{}", encoding="utf-8")
    (directory / "adir.json").mkdir()
    status, out, err = run(capsys, "sites")
    assert status == 0
    assert [line.split()[0] for line in out.splitlines()] == ["SITE", "sitex"]
    assert "skipping broken" in err


def test_allow_adds_a_host(roots: sites.Roots, capsys: pytest.CaptureFixture[str]) -> None:
    make_site(roots)
    status, out, _ = run(capsys, "allow", "sitex", "https://Login.Okta.com/sso")
    assert (status, out) == (0, "sitex: login.okta.com is allowed.\n")
    assert sites.load_policy(roots, "sitex").allow == ("sitex.com", "login.okta.com")


def test_allow_is_idempotent(roots: sites.Roots, capsys: pytest.CaptureFixture[str]) -> None:
    make_site(roots)
    before = sites.policy_path(roots, "sitex").stat().st_mtime_ns
    status, out, _ = run(capsys, "allow", "sitex", "sitex.com")
    assert (status, out) == (0, "sitex: sitex.com was already allowed.\n")
    assert sites.policy_path(roots, "sitex").stat().st_mtime_ns == before


@pytest.mark.parametrize(
    ("excluded", "gone"),
    [
        (("login.okta.com", "t.example"), "login.okta.com"),
        (("okta.com", "t.example"), "okta.com"),
        (("sso.login.okta.com", "t.example"), None),
    ],
)
def test_allow_removes_the_exclusions_that_would_block_it(
    roots: sites.Roots,
    capsys: pytest.CaptureFixture[str],
    excluded: tuple[str, ...],
    gone: str | None,
) -> None:
    make_site(roots, excluded=excluded)
    status, out, _ = run(capsys, "allow", "sitex", "login.okta.com")
    saved = sites.load_policy(roots, "sitex")
    assert status == 0
    assert sites.allows(saved, "login.okta.com")
    assert saved.excluded == tuple(e for e in excluded if e != gone)
    assert (f"no longer excluding {gone}" in out) is (gone is not None)


def test_allow_clears_an_exclusion_of_an_already_allowed_host(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots, excluded=("okta.com",), allow=("sitex.com", "login.okta.com"))
    status, out, _ = run(capsys, "allow", "sitex", "login.okta.com")
    assert status == 0
    assert "was already allowed" in out
    assert sites.load_policy(roots, "sitex").excluded == ()


@pytest.mark.parametrize("host", ["", "bad host", "http://"])
def test_allow_rejects_a_bad_host(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str], host: str
) -> None:
    make_site(roots)
    status, out, err = run(capsys, "allow", "sitex", host)
    assert (status, out) == (1, "")
    assert err.startswith("valetkey: cannot read a host from")


def test_unknown_and_invalid_sites(roots: sites.Roots, capsys: pytest.CaptureFixture[str]) -> None:
    make_site(roots, "sitex")
    make_site(roots, "another")
    for command in (
        ["allow", "nope", "a.com"],
        ["deny", "nope", "a.com"],
        ["forget", "nope", "--yes"],
    ):
        status, out, err = run(capsys, *command)
        assert (status, out) == (1, "")
        assert err == "valetkey: no site named 'nope'. Known sites: another, sitex\n"
    status, _, err = run(capsys, "allow", "../evil", "a.com")
    assert status == 1
    assert "invalid site name" in err
    status, _, err = run(capsys, "forget", "../evil", "--yes")
    assert (status, "invalid site name" in err) == (1, True)


@pytest.mark.usefixtures("roots")
def test_no_sites_yet_message(capsys: pytest.CaptureFixture[str]) -> None:
    _, _, err = run(capsys, "allow", "sitex", "a.com")
    assert err.endswith("Known sites: none yet\n")


def test_unreadable_policy_is_reported(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    path = sites.policy_path(roots, "broken")
    path.parent.mkdir(parents=True)
    path.write_text("{", encoding="utf-8")
    status, _, err = run(capsys, "allow", "broken", "a.com")
    assert status == 1
    assert "broken.json" in err


def test_deny_removes_an_allowed_host(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots, allow=("sitex.com", "login.okta.com"))
    status, out, _ = run(capsys, "deny", "sitex", "login.okta.com")
    assert (status, out) == (0, "sitex: login.okta.com is no longer allowed.\n")
    saved = sites.load_policy(roots, "sitex")
    assert (saved.allow, saved.excluded) == (("sitex.com",), ())
    assert not sites.allows(saved, "login.okta.com")


def test_deny_excludes_a_host_a_wider_entry_still_covers(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots, allow=("sitex.com", "app.sitex.com"))
    status, out, _ = run(capsys, "deny", "sitex", "app.sitex.com")
    assert status == 0
    assert out.splitlines() == [
        "sitex: app.sitex.com is no longer allowed.",
        "sitex: a wider allowed entry still covers app.sitex.com, so it is now excluded.",
    ]
    saved = sites.load_policy(roots, "sitex")
    assert (saved.allow, saved.excluded) == (("sitex.com",), ("app.sitex.com",))
    assert not sites.allows(saved, "app.sitex.com")
    assert sites.allows(saved, "www.sitex.com")


def test_deny_carves_out_a_host_with_no_entry_of_its_own(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots)
    status, out, _ = run(capsys, "deny", "sitex", "ads.sitex.com")
    assert status == 0
    assert "no longer allowed" not in out
    assert sites.load_policy(roots, "sitex").excluded == ("ads.sitex.com",)
    status, _, _ = run(capsys, "deny", "sitex", "ads.sitex.com")
    assert sites.load_policy(roots, "sitex").excluded == ("ads.sitex.com",)


def test_deny_of_a_host_that_was_never_allowed_changes_nothing(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots)
    before = sites.policy_path(roots, "sitex").stat().st_mtime_ns
    status, out, _ = run(capsys, "deny", "sitex", "other.example")
    assert (status, out) == (0, "sitex: other.example was not allowed. Nothing changed.\n")
    assert sites.policy_path(roots, "sitex").stat().st_mtime_ns == before


def test_deny_rejects_a_bad_host(roots: sites.Roots, capsys: pytest.CaptureFixture[str]) -> None:
    make_site(roots)
    assert run(capsys, "deny", "sitex", "bad host")[0] == 1


def seed(roots: sites.Roots, name: str = "sitex") -> list[Path]:
    make_site(roots, name)
    profile = sites.ensure_profile(roots, name)
    downloads = sites.ensure_downloads(roots, name)
    (profile / "Cookies").write_text("x", encoding="utf-8")
    (downloads / "report.pdf").write_text("x", encoding="utf-8")
    return [sites.policy_path(roots, name), profile, downloads]


class Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_forget_with_yes_deletes_everything_of_that_site_only(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    gone = seed(roots, "sitex")
    kept = seed(roots, "another")
    status, out, _ = run(capsys, "forget", "sitex", "--yes")
    assert (status, out) == (0, "Forgot sitex.\n")
    assert not any(path.exists() for path in gone)
    assert all(path.exists() for path in kept)


def test_forget_deletes_the_hidden_download_folders_too_and_follows_no_link(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    seed(roots, "sitex")
    folder = sites.downloads_path(roots, "sitex")
    outside = tmp_path / "outside.txt"
    outside.write_text("keep", encoding="utf-8")
    for hidden in (".incoming", ".screenshots"):
        (folder / hidden).mkdir()
        (folder / hidden / "file.bin").write_text("x", encoding="utf-8")
        (folder / hidden / "link").symlink_to(outside)
    assert run(capsys, "forget", "sitex", "--yes")[0] == 0
    assert not folder.exists()
    assert outside.read_text(encoding="utf-8") == "keep"


def test_forget_works_with_only_a_profile_left(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    sites.ensure_profile(roots, "orphan")
    assert run(capsys, "forget", "orphan", "--yes")[0] == 0
    assert not sites.profile_path(roots, "orphan").exists()


@pytest.mark.parametrize(
    ("answer", "deleted"), [("y\n", True), ("YES\n", True), ("n\n", False), ("\n", False)]
)
def test_forget_asks_on_a_terminal(
    roots: sites.Roots,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    answer: str,
    *,
    deleted: bool,
) -> None:
    targets = seed(roots)
    monkeypatch.setattr(sys, "stdin", Terminal(answer))
    status, out, _ = run(capsys, "forget", "sitex")
    assert "Forget sitex? This deletes its login, policy and downloads. [y/N]" in out
    assert (status, any(path.exists() for path in targets)) == (
        (0, False) if deleted else (1, True)
    )
    assert ("Nothing was deleted." in out) is not deleted


def test_forget_refuses_without_a_terminal(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    targets = seed(roots)
    monkeypatch.setattr(sys, "stdin", io.StringIO("y\n"))
    status, out, err = run(capsys, "forget", "sitex")
    assert (status, out) == (1, "")
    assert "add --yes" in err
    assert all(path.exists() for path in targets)


def fake_processes(monkeypatch: pytest.MonkeyPatch, *processes: list[str]) -> None:
    monkeypatch.setattr(cli, "_command_lines", lambda: list(processes))


@pytest.mark.parametrize("form", ["equals", "separate", "bare"])
def test_forget_refuses_while_a_process_uses_the_profile(
    roots: sites.Roots,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    form: str,
) -> None:
    targets = seed(roots)
    profile = str(targets[1])
    arguments = {
        "equals": ["chromium", f"--user-data-dir={profile}"],
        "separate": ["bwrap", "--profile", profile],
        "bare": ["tool", profile],
    }[form]
    fake_processes(monkeypatch, ["sleep", "5"], arguments)
    status, _, err = run(capsys, "forget", "sitex", "--yes")
    assert status == 1
    assert "close that session first" in err
    assert all(path.exists() for path in targets)


def test_forget_compares_resolved_paths(
    roots: sites.Roots,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    targets = seed(roots)
    alias = tmp_path / "alias"
    alias.symlink_to(targets[1])
    fake_processes(monkeypatch, ["chromium", f"--user-data-dir={alias}"])
    assert run(capsys, "forget", "sitex", "--yes")[0] == 1


def test_forget_ignores_processes_that_use_other_paths(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    targets = seed(roots)
    other = seed(roots, "another")[1]
    fake_processes(
        monkeypatch,
        [""],
        ["chromium", f"--user-data-dir={other}", "--flag=", f"{targets[1]}/Default"],
    )
    assert run(capsys, "forget", "sitex", "--yes")[0] == 0
    assert not targets[1].exists()


def test_command_lines_reads_a_process_table(tmp_path: Path) -> None:
    (tmp_path / "12").mkdir()
    (tmp_path / "12" / "cmdline").write_bytes(b"chromium\0--user-data-dir=/p\0")
    (tmp_path / "13").mkdir()
    (tmp_path / str(os.getpid())).mkdir()
    (tmp_path / str(os.getpid()) / "cmdline").write_bytes(b"me\0")
    (tmp_path / "self").mkdir()
    assert cli._command_lines(tmp_path) == [["chromium", "--user-data-dir=/p", ""]]  # noqa: SLF001 - reads a fake /proc


def test_forget_sees_a_real_process_using_the_profile(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    targets = seed(roots)
    command = [sys.executable, "-c", "import time; time.sleep(30)", f"--user-data-dir={targets[1]}"]
    with subprocess.Popen(command) as process:  # noqa: S603 - sleep from PATH
        try:
            assert run(capsys, "forget", "sitex", "--yes")[0] == 1
            assert targets[1].exists()
        finally:
            process.kill()
    assert run(capsys, "forget", "sitex", "--yes")[0] == 0


def test_forget_refuses_a_symlinked_profile(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    targets = seed(roots)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "precious").write_text("keep", encoding="utf-8")
    shutil_target = targets[1]
    for child in shutil_target.iterdir():
        child.unlink()
    shutil_target.rmdir()
    shutil_target.symlink_to(outside)
    status, _, err = run(capsys, "forget", "sitex", "--yes")
    assert status == 1
    assert "is a symlink" in err
    assert (outside / "precious").read_text(encoding="utf-8") == "keep"
    assert targets[0].exists()
    assert targets[2].exists()


def test_forget_refuses_when_a_parent_directory_is_a_symlink(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    seed(roots)
    real = tmp_path / "elsewhere"
    downloads = sites.downloads_path(roots, "sitex").parent
    downloads.rename(real)
    downloads.symlink_to(real)
    status, _, err = run(capsys, "forget", "sitex", "--yes")
    assert (status, "is a symlink" in err) == (1, True)
    assert (real / "sitex" / "report.pdf").exists()


def test_forget_refuses_when_the_policy_directory_is_a_symlink(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    seed(roots)
    directory = sites.policy_path(roots, "sitex").parent
    real = tmp_path / "policies"
    directory.rename(real)
    directory.symlink_to(real)
    status, _, err = run(capsys, "forget", "sitex", "--yes")
    assert (status, "is a symlink" in err) == (1, True)
    assert (real / "sitex.json").exists()


def test_forget_removes_a_symlinked_policy_file_without_touching_its_target(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    targets = seed(roots)
    real = tmp_path / "real.json"
    targets[0].rename(real)
    targets[0].symlink_to(real)
    assert run(capsys, "forget", "sitex", "--yes")[0] == 0
    assert not targets[0].is_symlink()
    assert real.exists()


def test_forget_survives_a_file_that_vanishes(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    targets = seed(roots)
    original = Path.unlink

    def vanish(self: Path, *, missing_ok: bool = False) -> None:
        original(self, missing_ok=missing_ok)
        raise FileNotFoundError

    monkeypatch.setattr(Path, "unlink", vanish)
    assert run(capsys, "forget", "sitex", "--yes")[0] == 0
    assert not targets[0].exists()


def test_command_help_names_the_options(capsys: pytest.CaptureFixture[str]) -> None:
    assert "--json" in run(capsys, "sites", "--help")[1]
    assert "--yes" in run(capsys, "forget", "--help")[1]
    with pytest.raises(SystemExit) as exit_info:
        main(["allow", "onlyone"])
    assert exit_info.value.code == 2


def test_daemon_command_runs_the_server(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: list[object] = []

    async def fake_run(server: object, socket_path: Path | None) -> int:
        seen.append((type(server).__name__, socket_path))
        return 0

    monkeypatch.setattr(daemon, "run", fake_run)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    assert main(["daemon", "--socket", str(tmp_path / "d.sock")]) == 0
    assert main(["daemon"]) == 0
    assert seen == [("Daemon", tmp_path / "d.sock"), ("Daemon", None)]


@pytest.mark.parametrize(
    "error",
    [
        daemon.AlreadyRunningError("valetkeyd is already running"),
        sites.RuntimeDirUnavailableError("no runtime dir"),
    ],
)
def test_daemon_command_reports_why_it_cannot_start(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], error: Exception
) -> None:
    async def fake_run(_server: object, _socket_path: Path | None) -> int:
        raise error

    monkeypatch.setattr(daemon, "run", fake_run)
    assert main(["daemon"]) == 1
    assert str(error) in capsys.readouterr().err


# -- systemd units -------------------------------------------------------------------------

SERVICE = cli.unit_template("valetkeyd.service")
SOCKET = cli.unit_template("valetkeyd.socket")

KEPT = [
    "Requires=valetkeyd.socket",
    "After=valetkeyd.socket",
    "Restart=on-failure",
    "NoNewPrivileges=yes",
    "PrivateTmp=yes",
    "PrivateDevices=yes",
    "ProtectSystem=strict",
    "ProtectHome=read-only",
    "ProtectControlGroups=yes",
    "ProtectKernelModules=yes",
    "ProtectClock=yes",
    "ProtectProc=invisible",
    "ProcSubset=pid",
    "RestrictNamespaces=user net pid ipc uts cgroup mnt",
    "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
    "RestrictRealtime=yes",
    "LockPersonality=yes",
    "SystemCallArchitectures=native",
    "SystemCallFilter=~@debug @obsolete @cpu-emulation @raw-io @reboot @swap @module",
    "CapabilityBoundingSet=",
    "UMask=0077",
    "ExecStartPre=+/usr/bin/mkdir -p -m 0700 %S/valetkey %E/valetkey",
    "ReadWritePaths=%S/valetkey %E/valetkey",
    "RuntimeDirectory=valetkey agent-browser",
    "RuntimeDirectoryPreserve=yes",
]
REJECTED = [
    "MemoryDenyWriteExecute",  # Chromium's JIT hangs
    "ProtectKernelTunables",  # bwrap cannot mount /proc
    "ProtectKernelLogs",  # bwrap cannot mount /proc
    "ProtectHostname",  # bwrap cannot set the sandbox hostname
    "RestrictSUIDSGID",  # bwrap fails to start
    "PrivateUsers",  # a user namespace inside a user namespace, and the peer's user ID
    "PrivateIPC",  # a user manager cannot set it up; systemd ignores it with a warning
    "StateDirectory",  # with a config directory of the same name it links state to config
    "ConfigurationDirectory",  # the same compatibility link, and a mode warning
]


def directives(text: str) -> list[str]:
    return [line for line in text.splitlines() if line and not line.startswith(("#", "["))]


@pytest.mark.parametrize("line", KEPT)
def test_service_has_every_decided_directive(line: str) -> None:
    assert line in directives(SERVICE)


@pytest.mark.parametrize("name", REJECTED)
def test_service_leaves_out_the_directives_that_break_the_sandbox(name: str) -> None:
    assert not any(line.startswith(f"{name}=") for line in directives(SERVICE))
    assert not any(
        line.startswith("RestrictNamespaces=") and "yes" in line for line in SERVICE.splitlines()
    )


def test_service_is_socket_activated_and_has_no_install_section() -> None:
    assert "[Install]" not in SERVICE
    assert "ExecStart=@EXECUTABLE@ daemon" in SERVICE


def test_socket_matches_the_daemon_contract() -> None:
    assert directives(SOCKET) == [
        "Description=valetkey daemon socket",
        "ListenStream=%t/valetkey/daemon.sock",
        "SocketMode=0600",
        "DirectoryMode=0700",
        "RemoveOnStop=yes",
        "WantedBy=sockets.target",
    ]


@pytest.mark.parametrize("name", cli.UNIT_NAMES)
def test_units_start_with_the_marker(name: str) -> None:
    assert cli.unit_template(name).startswith(cli.UNIT_MARKER)


def test_render_fills_in_the_executable() -> None:
    text = cli.render_unit("valetkeyd.service", "/home/me/.local/bin/valetkey")
    assert "ExecStart=/home/me/.local/bin/valetkey daemon\n" in text
    assert cli.EXECUTABLE_PLACEHOLDER not in text
    assert cli.render_unit("valetkeyd.socket", "/x") == SOCKET


@pytest.mark.parametrize(
    ("path", "word"),
    [
        ("/usr/bin/valetkey", "/usr/bin/valetkey"),
        ("/home/a b/valetkey", '"/home/a b/valetkey"'),
        ("/home/100%/valetkey", "/home/100%%/valetkey"),
        ("/home/$x/valetkey", "/home/$$x/valetkey"),
        ('/home/a"b/valetkey', '"/home/a\\"b/valetkey"'),
        ("/home/a\\b/valetkey", '"/home/a\\\\b/valetkey"'),
    ],
)
def test_exec_start_word_quotes_what_systemd_would_expand(path: str, word: str) -> None:
    assert cli.exec_start_word(path) == word


@pytest.mark.parametrize("path", ["/a\nb", "/a\0b"])
def test_exec_start_word_refuses_a_path_it_cannot_write(path: str) -> None:
    with pytest.raises(cli.CommandError):
        cli.exec_start_word(path)


def test_valetkey_executable_is_absolute_and_unresolved(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.write_text("", encoding="utf-8")
    link = tmp_path / "bin" / "valetkey"
    link.parent.mkdir()
    link.symlink_to(real)
    assert cli.valetkey_executable(lambda _name: str(link)) == str(link)
    assert cli.valetkey_executable(lambda _name: "bin/valetkey") == str(
        Path("bin/valetkey").absolute()
    )
    with pytest.raises(cli.CommandError, match="not on PATH"):
        cli.valetkey_executable(lambda _name: None)


@pytest.fixture
def units_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(cli, "valetkey_executable", lambda: "/opt/bin/valetkey")
    return tmp_path / "config" / "systemd" / "user"


def test_install_units_writes_both_files_and_prints_the_next_steps(
    units_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    status, out, err = run(capsys, "install-units")
    assert (status, err) == (0, "")
    assert (units_home / "valetkeyd.socket").read_text(encoding="utf-8") == SOCKET
    service = (units_home / "valetkeyd.service").read_text(encoding="utf-8")
    assert "ExecStart=/opt/bin/valetkey daemon\n" in service
    assert f"Wrote {units_home / 'valetkeyd.socket'}" in out
    assert out.splitlines()[-2:] == [
        "    systemctl --user daemon-reload",
        "    systemctl --user enable --now valetkeyd.socket",
    ]


@pytest.mark.usefixtures("units_home")
def test_install_units_says_when_it_overrides_packaged_units(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    packaged = tmp_path / "packaged"
    packaged.mkdir()
    monkeypatch.setattr(cli, "SYSTEM_UNIT_DIRS", (packaged,))
    assert f"units in {packaged}" not in run(capsys, "install-units")[1]
    for name in cli.UNIT_NAMES:
        (packaged / name).write_text("x", encoding="utf-8")
    out = run(capsys, "install-units")[1]
    assert f"Note: the units in {packaged} are replaced by these copies." in out
    assert out.index("Note:") < out.index("To start the daemon")


def test_install_units_replaces_its_own_files(
    units_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run(capsys, "install-units")
    (units_home / "valetkeyd.service").write_text(cli.UNIT_MARKER + " old\n", encoding="utf-8")
    assert run(capsys, "install-units")[0] == 0
    assert "ExecStart=/opt/bin/valetkey daemon" in (units_home / "valetkeyd.service").read_text(
        encoding="utf-8"
    )


def test_install_units_refuses_to_replace_a_file_it_did_not_write(
    units_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    units_home.mkdir(parents=True)
    mine = units_home / "valetkeyd.socket"
    theirs = units_home / "valetkeyd.service"
    theirs.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
    status, out, err = run(capsys, "install-units")
    assert (status, out) == (1, "")
    assert str(theirs) in err
    assert "--force" in err
    assert theirs.read_text(encoding="utf-8") == "[Service]\nExecStart=/bin/true\n"
    assert not mine.exists()


def test_install_units_refuses_a_file_that_is_not_text(
    units_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    units_home.mkdir(parents=True)
    (units_home / "valetkeyd.socket").write_bytes(b"\xff\xfe")
    assert run(capsys, "install-units")[0] == 1


def test_install_units_force_replaces_a_foreign_file(
    units_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    units_home.mkdir(parents=True)
    (units_home / "valetkeyd.service").write_text("mine\n", encoding="utf-8")
    assert run(capsys, "install-units", "--force")[0] == 0
    assert (
        (units_home / "valetkeyd.service").read_text(encoding="utf-8").startswith(cli.UNIT_MARKER)
    )


def test_install_units_dry_run_prints_and_writes_nothing(
    units_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    status, out, _ = run(capsys, "install-units", "--dry-run")
    assert status == 0
    assert f"Would write {units_home / 'valetkeyd.socket'}:" in out
    assert "ExecStart=/opt/bin/valetkey daemon" in out
    assert out.endswith("Nothing was written.\n")
    assert not units_home.exists()


def test_install_units_needs_valetkey_on_the_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    status, _, err = run(capsys, "install-units")
    assert status == 1
    assert "not on PATH" in err


def test_install_units_uses_the_program_found_on_the_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    program = tmp_path / "bin" / "valetkey"
    program.parent.mkdir()
    program.write_text("#!/bin/sh\n", encoding="utf-8")
    program.chmod(0o755)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("PATH", str(program.parent))
    assert run(capsys, "install-units")[0] == 0
    service = tmp_path / "config" / "systemd" / "user" / "valetkeyd.service"
    assert f"ExecStart={program} daemon\n" in service.read_text(encoding="utf-8")


# -- doctor --------------------------------------------------------------------------------

BWRAP_PROBE = "--unshare-all"
System = cli.System


class FakeSystem:
    """Answers the questions ``doctor`` asks from a table."""

    def __init__(self, tmp_path: Path, **overrides: object) -> None:
        self.tools = {
            "bwrap": "/usr/bin/bwrap",
            "chromium": "/usr/bin/chromium",
            "agent-browser": "/usr/bin/agent-browser",
        }
        self.outputs: dict[str, tuple[int, str]] = {
            "/usr/bin/bwrap --version": (0, "bubblewrap 0.13.1\n"),
            "/usr/bin/chromium --version": (0, "Chromium 156.0.8078.47 Arch Linux\n"),
            "/usr/bin/agent-browser --version": (0, "agent-browser 0.39.2\n"),
            "systemctl --user is-active valetkeyd.socket": (3, "inactive\n"),
        }
        self.probe: tuple[int, str] = (0, "")
        self.environ: dict[str, str] = {"XDG_RUNTIME_DIR": "/run/user/1000"}
        self.display: Path | cli.login.DisplayError = Path("/run/user/1000/wayland-1")
        self.units = tmp_path / "units"
        self.system_units: tuple[Path, ...] = ()
        self.calls: list[list[str]] = []
        for key, value in overrides.items():
            setattr(self, key, value)

    def which(self, name: str) -> str | None:
        return self.tools.get(name)

    def run(self, args: Sequence[str]) -> tuple[int, str]:
        self.calls.append(list(args))
        if BWRAP_PROBE in args:
            return self.probe
        return self.outputs.get(" ".join(args), (-1, "no such program"))

    def wayland(self) -> Path:
        if isinstance(self.display, Exception):
            raise self.display
        return self.display

    def system(self) -> cli.System:
        return System(
            which=self.which,
            run=self.run,
            environ=self.environ,
            wayland=self.wayland,
            unit_dirs=(self.units, *self.system_units),
        )


def results(fake: FakeSystem) -> dict[str, tuple[str, str]]:
    return {c.name: (c.status, c.detail) for c in cli.run_checks(fake.system())}


def test_doctor_all_good(tmp_path: Path) -> None:
    fake = FakeSystem(tmp_path)
    assert results(fake) == {
        "bwrap": ("ok", "bwrap 0.13.1"),
        "namespaces": ("ok", "unprivileged user namespaces work"),
        "chromium": ("ok", "chromium 156"),
        "agent-browser": ("ok", "agent-browser 0.39.2"),
        "runtime-dir": ("ok", "XDG_RUNTIME_DIR=/run/user/1000"),
        "display": ("ok", "Wayland display /run/user/1000/wayland-1"),
        "units": ("info", "systemd units not installed; run `valetkey install-units`"),
        "socket": ("info", "valetkeyd.socket is inactive"),
    }
    probe = next(call for call in fake.calls if BWRAP_PROBE in call)
    assert probe[0] == "/usr/bin/bwrap"
    assert probe[-1] == "/usr/bin/true"
    assert all(flag in probe for flag in ("--ro-bind", "--dev", "--proc"))


def test_doctor_bwrap_missing(tmp_path: Path) -> None:
    found = results(FakeSystem(tmp_path, tools={"chromium": "/usr/bin/chromium"}))
    assert found["bwrap"] == ("fail", "bwrap not found; install bubblewrap")
    assert found["namespaces"] == ("fail", "bwrap is missing")


def test_doctor_bwrap_without_a_version(tmp_path: Path) -> None:
    fake = FakeSystem(tmp_path)
    fake.outputs["/usr/bin/bwrap --version"] = (1, "")
    assert results(fake)["bwrap"] == ("ok", "bwrap version unknown")


def test_doctor_namespaces_blocked(tmp_path: Path) -> None:
    fake = FakeSystem(tmp_path, probe=(1, "bwrap: No permissions to create a new namespace\n"))
    assert results(fake)["namespaces"] == (
        "fail",
        "bwrap cannot make a sandbox: bwrap: No permissions to create a new namespace",
    )
    fake.probe = (1, "")
    assert results(fake)["namespaces"][1].endswith("no output")


def test_doctor_chromium_problems(tmp_path: Path) -> None:
    fake = FakeSystem(tmp_path)
    fake.tools.pop("chromium")
    assert results(fake)["chromium"] == ("fail", "chromium not found")
    fake.tools["chromium"] = "/usr/bin/chromium"
    fake.outputs["/usr/bin/chromium --version"] = (0, "garbage\n")
    assert results(fake)["chromium"] == ("fail", "cannot read the version of /usr/bin/chromium")


def test_doctor_agent_browser_problems(tmp_path: Path) -> None:
    fake = FakeSystem(tmp_path)
    fake.tools.pop("agent-browser")
    assert results(fake)["agent-browser"] == ("fail", "agent-browser not found")
    fake.tools["agent-browser"] = "/usr/bin/agent-browser"
    fake.outputs["/usr/bin/agent-browser --version"] = (0, "agent-browser 0.38.9\n")
    status, detail = results(fake)["agent-browser"]
    assert status == "fail"
    assert "too old" in detail
    fake.outputs["/usr/bin/agent-browser --version"] = (0, "nope\n")
    assert results(fake)["agent-browser"] == (
        "fail",
        "cannot read the version of /usr/bin/agent-browser",
    )


@pytest.mark.parametrize("environ", [{}, {"XDG_RUNTIME_DIR": ""}, {"XDG_RUNTIME_DIR": "run"}])
def test_doctor_needs_a_runtime_dir(tmp_path: Path, environ: dict[str, str]) -> None:
    assert results(FakeSystem(tmp_path, environ=environ))["runtime-dir"] == (
        "fail",
        "XDG_RUNTIME_DIR is not set to an absolute path",
    )


def test_doctor_a_missing_display_is_only_a_warning(tmp_path: Path) -> None:
    fake = FakeSystem(tmp_path, display=cli.login.NoDisplayError("no desktop session"))
    status, detail = results(fake)["display"]
    assert status == "warn"
    assert "no desktop session" in detail


def test_doctor_reports_installed_units_and_an_active_socket(tmp_path: Path) -> None:
    fake = FakeSystem(tmp_path)
    fake.units.mkdir()
    for name in cli.UNIT_NAMES:
        (fake.units / name).write_text("x", encoding="utf-8")
    fake.outputs["systemctl --user is-active valetkeyd.socket"] = (0, "active\n")
    found = results(fake)
    assert found["units"] == ("info", f"systemd units installed in {fake.units}")
    assert found["socket"] == ("info", "valetkeyd.socket is active")


def test_doctor_finds_units_a_package_installed(tmp_path: Path) -> None:
    packaged = tmp_path / "usr-lib-systemd-user"
    packaged.mkdir()
    for name in cli.UNIT_NAMES:
        (packaged / name).write_text("x", encoding="utf-8")
    fake = FakeSystem(tmp_path, system_units=(tmp_path / "etc-empty", packaged))
    assert results(fake)["units"] == ("info", f"systemd units installed in {packaged}")
    # One file of the two is not an installation.
    (packaged / "valetkeyd.service").unlink()
    assert results(fake)["units"][1].startswith("systemd units not installed")


def test_doctor_prefers_the_units_in_the_user_directory(tmp_path: Path) -> None:
    packaged = tmp_path / "packaged"
    fake = FakeSystem(tmp_path, system_units=(packaged,))
    for directory in (fake.units, packaged):
        directory.mkdir()
        for name in cli.UNIT_NAMES:
            (directory / name).write_text("x", encoding="utf-8")
    assert results(fake)["units"][1] == f"systemd units installed in {fake.units}"


def test_doctor_when_systemd_cannot_be_reached(tmp_path: Path) -> None:
    fake = FakeSystem(tmp_path)
    fake.outputs["systemctl --user is-active valetkeyd.socket"] = (-1, "no such file")
    assert results(fake)["socket"] == ("info", "systemd user session not reachable")
    fake.outputs["systemctl --user is-active valetkeyd.socket"] = (1, "")
    assert results(fake)["socket"] == ("info", "systemd user session not reachable")
    fake.outputs["systemctl --user is-active valetkeyd.socket"] = (1, "Failed to connect to bus")
    assert results(fake)["socket"] == ("info", "systemd user session not reachable")
    fake.outputs["systemctl --user is-active valetkeyd.socket"] = (4, "inactive\n")
    assert results(fake)["socket"] == ("info", "valetkeyd.socket is inactive")


def test_doctor_command_output_and_exit_status(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSystem(tmp_path, tools={"bwrap": "/usr/bin/bwrap"})
    monkeypatch.setattr(cli, "System", fake.system)
    status, out, _ = run(capsys, "doctor")
    assert status == 1
    lines = out.splitlines()
    assert lines[0] == "ok    bwrap 0.13.1"
    assert "FAIL  chromium not found" in lines
    assert "FAIL  agent-browser not found" in lines
    assert lines[-1] == "info  valetkeyd.socket is inactive"


def test_doctor_exit_status_is_zero_when_only_warnings_remain(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSystem(tmp_path, display=cli.login.NoDisplayError("none"))
    monkeypatch.setattr(cli, "System", fake.system)
    status, out, _ = run(capsys, "doctor")
    assert status == 0
    assert any(line.startswith("warn  ") for line in out.splitlines())


def test_doctor_json_shape(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "System", FakeSystem(tmp_path).system)
    status, out, _ = run(capsys, "doctor", "--json")
    rows = json.loads(out)
    assert status == 0
    assert rows[0] == {"check": "bwrap", "status": "ok", "detail": "bwrap 0.13.1"}
    assert [row["check"] for row in rows] == [
        "bwrap",
        "namespaces",
        "chromium",
        "agent-browser",
        "runtime-dir",
        "display",
        "units",
        "socket",
    ]
    assert {row["status"] for row in rows} <= {"ok", "fail", "warn", "info"}


def test_default_system_asks_the_machine(tmp_path: Path) -> None:
    status, output = cli._run([sys.executable, "-c", "print('hi')"])  # noqa: SLF001 - the default runner
    assert (status, output) == (0, "hi\n")
    assert cli._run([str(tmp_path / "missing")])[0] == -1  # noqa: SLF001
    system = cli.System()
    assert system.which("sh") is not None
    assert system.unit_dirs[0].name == "user"
    assert system.unit_dirs[1:] == cli.SYSTEM_UNIT_DIRS


# -- the units under real systemd ----------------------------------------------------------


def _systemd_user_usable() -> bool:
    if shutil.which("systemd-run") is None or shutil.which("bwrap") is None:
        return False
    state = subprocess.run(
        ["systemctl", "--user", "is-system-running"],  # noqa: S607 - from PATH
        capture_output=True,
        text=True,
        check=False,
    )
    return state.stdout.strip() in {"running", "degraded"}


SKIPPED_PROPERTIES = {
    "ExecStart", "ExecStartPre", "ReadWritePaths", "Type", "Restart", "TimeoutStopSec"
}  # fmt: skip


def hardening_properties() -> list[str]:
    """The sandboxing lines of the service file, as ``systemd-run -p`` arguments."""
    properties: list[str] = []
    for line in directives(SERVICE.split("[Service]")[1]):
        name = line.split("=")[0]
        if name in {
            "ExecStart",
            "ExecStartPre",
            "ReadWritePaths",
            "Type",
            "Restart",
            "TimeoutStopSec",
        }:
            continue
        properties += ["-p", line]
    return properties


@pytest.mark.integration
@pytest.mark.skipif(not _systemd_user_usable(), reason="needs systemd --user and bwrap")
def test_bubblewrap_still_works_under_the_service_hardening() -> None:
    command = [
        "systemd-run", "--user", "--wait", "--pipe", "--collect", "--quiet",
        *hardening_properties(),
        shutil.which("bwrap") or "bwrap", "--unshare-all", "--ro-bind", "/usr", "/usr",
        *sandbox.system_link_args(),
        "--dev", "/dev", "--proc", "/proc", "/usr/bin/true",
    ]  # fmt: skip
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=60)  # noqa: S603
    assert result.returncode == 0, result.stderr


def test_mcp_command_serves_over_stdio(monkeypatch: pytest.MonkeyPatch) -> None:
    served: list[bool] = []
    monkeypatch.setattr(mcp_server, "serve", lambda: served.append(True))
    assert main(["mcp"]) == 0
    assert served == [True]


# -- status and watch ----------------------------------------------------------------------

ACTIVITY = {
    "sessions": [
        {"site": "sitex", "since": "2026-10-26T09:00:00Z", "contained": True, "host": "sitex.com"},
    ],
    "logins": [{"site": "another", "since": "2026-10-26T09:05:00Z"}],
}


class FakeConnection:
    """Stands in for a client connected to the daemon."""

    def __init__(
        self,
        *,
        status: dict[str, Any] | None = None,
        events: Sequence[dict[str, Any]] = (),
        end: BaseException | None = None,
    ) -> None:
        self.status = status
        self.events = events
        self.end = end
        self.asked: list[str] = []

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        return None

    async def call(self, op: str) -> dict[str, Any]:
        self.asked.append(op)
        if isinstance(self.end, cli.client.DaemonError):
            raise self.end
        return self.status or {}

    async def watch(self) -> AsyncIterator[dict[str, Any]]:
        for event in self.events:
            yield event
        if self.end is not None:
            raise self.end


def connect_to(monkeypatch: pytest.MonkeyPatch, connection: FakeConnection | BaseException) -> None:
    async def connect(_path: object = None) -> FakeConnection:
        if isinstance(connection, BaseException):
            raise connection
        return connection

    monkeypatch.setattr(cli.client.Client, "connect", staticmethod(connect))


def not_running() -> cli.client.DaemonError:
    return cli.client.DaemonError("not_running", "valetkeyd is not running (/x: missing)")


def test_status_prints_a_table(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = FakeConnection(status=ACTIVITY)
    connect_to(monkeypatch, connection)
    status, out, err = run(capsys, "status")
    assert (status, err) == (0, "")
    assert out.splitlines() == [
        "KIND     SITE     SINCE                 HOST",
        "session  sitex    2026-10-26T09:00:00Z  sitex.com",
        "login    another  2026-10-26T09:05:00Z  -",
    ]
    assert connection.asked == ["status"]


def test_status_json_is_the_daemons_answer(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    connect_to(monkeypatch, FakeConnection(status=ACTIVITY))
    status, out, _ = run(capsys, "status", "--json")
    assert status == 0
    assert json.loads(out) == ACTIVITY


def test_status_when_nothing_is_open(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    connect_to(monkeypatch, FakeConnection(status={"sessions": [], "logins": []}))
    assert run(capsys, "status") == (0, "No browser sessions or login windows are open.\n", "")


def test_status_without_a_host_shows_a_dash(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    entry = {"site": "sitex", "since": None, "contained": True, "host": None}
    connect_to(monkeypatch, FakeConnection(status={"sessions": [entry], "logins": []}))
    assert run(capsys, "status")[1].splitlines()[1].split() == ["session", "sitex", "-", "-"]


def test_status_without_a_daemon_says_so_and_succeeds(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    connect_to(monkeypatch, not_running())
    assert run(capsys, "status") == (0, "valetkeyd is not running\n", "")
    connect_to(monkeypatch, FakeConnection(end=not_running()))
    assert run(capsys, "status", "--json") == (0, "valetkeyd is not running\n", "")


def test_status_reports_other_errors(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    error = cli.client.DaemonError("internal", "the daemon hit an unexpected error")
    connect_to(monkeypatch, FakeConnection(end=error))
    status, out, err = run(capsys, "status")
    assert (status, out) == (1, "")
    assert err == "valetkey: the daemon hit an unexpected error\n"


def test_status_and_watch_need_a_runtime_directory(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    for command in ("status", "watch"):
        status, out, err = run(capsys, command)
        assert (status, out) == (1, "")
        assert "XDG_RUNTIME_DIR is not set" in err


def test_status_and_watch_never_start_the_daemon(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    assert run(capsys, "status") == (0, "valetkeyd is not running\n", "")
    status, out, err = run(capsys, "watch")
    assert (status, out) == (1, "")
    assert "valetkeyd is not running" in err
    assert list(tmp_path.iterdir()) == []


EVENTS = [
    {"event": "snapshot", "at": "2026-10-26T09:00:00Z", "sessions": [], "logins": []},
    {"event": "session_started", "site": "sitex", "at": "2026-10-26T09:00:01Z"},
]


def test_watch_prints_one_json_line_per_event(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    connect_to(monkeypatch, FakeConnection(events=EVENTS))
    status, out, err = run(capsys, "watch")
    assert (status, err) == (0, "")
    assert [json.loads(line) for line in out.splitlines()] == EVENTS
    assert out.splitlines()[1] == (
        '{"event":"session_started","site":"sitex","at":"2026-10-26T09:00:01Z"}'
    )


def test_watch_ends_quietly_when_the_daemon_stops(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    lost = cli.client.DaemonError("connection_lost", "the connection to valetkeyd was lost")
    connect_to(monkeypatch, FakeConnection(events=EVENTS[:1], end=lost))
    status, out, err = run(capsys, "watch")
    assert (status, err) == (0, "")
    assert len(out.splitlines()) == 1


def test_watch_without_a_daemon_fails(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    connect_to(monkeypatch, not_running())
    status, out, err = run(capsys, "watch")
    assert (status, out) == (1, "")
    assert err.startswith("valetkey: valetkeyd is not running")


def test_watch_reports_a_daemon_error(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    error = cli.client.DaemonError("unknown_op", "no such operation: watch")
    connect_to(monkeypatch, FakeConnection(end=error))
    status, _, err = run(capsys, "watch")
    assert (status, err) == (1, "valetkey: no such operation: watch\n")


def test_watch_stops_quietly_when_interrupted(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    connect_to(monkeypatch, FakeConnection(events=EVENTS[:1], end=KeyboardInterrupt()))
    status, out, _ = run(capsys, "watch")
    assert (status, len(out.splitlines())) == (0, 1)
