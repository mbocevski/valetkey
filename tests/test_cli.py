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

from valetkey import __version__, cli, daemon, mcp_server, sandbox, sessions, sites
from valetkey.cli import main
from valetkey.wayland import MANAGER, WaylandError

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
    host = name.replace(":", "-")
    policy = sites.Policy(name, f"https://app.{host}.com/", allow, excluded, learned)
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
        "SITE   HOST           ALLOWED  EXCLUDED  DENIED  LEARNED               NETWORKS  PROFILE",
        "sitex  app.sitex.com  2        1         0       2026-10-26T09:00:00Z  -         yes",
    ]
    make_site(roots, "another")
    status, out, _ = run(capsys, "sites")
    assert [line.split()[0] for line in out.splitlines()] == ["SITE", "another", "sitex"]
    assert out.splitlines()[1].split()[-3:] == ["never", "-", "no"]


def test_sites_json_shape(roots: sites.Roots, capsys: pytest.CaptureFixture[str]) -> None:
    make_site(roots, "sitex", learned=datetime(2026, 10, 26, 9, 0, tzinfo=UTC))
    make_site(roots, "another")
    sites.ensure_profile(roots, "another")
    _, out, _ = run(capsys, "sites", "--json")
    assert json.loads(out) == [
        {
            "site": "another",
            "account": None,
            "host": "app.another.com",
            "allowed": 1,
            "excluded": 0,
            "denied": 0,
            "learned": None,
            "private_networks": [],
            "profile": True,
        },
        {
            "site": "sitex",
            "account": None,
            "host": "app.sitex.com",
            "allowed": 1,
            "excluded": 0,
            "denied": 0,
            "learned": "2026-10-26T09:00:00Z",
            "private_networks": [],
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
    assert (f"no longer excluding or denying {gone}" in out) is (gone is not None)


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


def test_deny_removes_an_allowed_host_and_denies_it(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots, allow=("sitex.com", "login.okta.com"))
    status, out, _ = run(capsys, "deny", "sitex", "login.okta.com")
    assert status == 0
    assert out.splitlines() == [
        "sitex: login.okta.com is no longer allowed.",
        "sitex: login.okta.com is denied, so a login will not allow it again.",
    ]
    saved = sites.load_policy(roots, "sitex")
    assert (saved.allow, saved.excluded, saved.denied) == (
        ("sitex.com",),
        (),
        ("login.okta.com",),
    )
    assert not sites.allows(saved, "login.okta.com")


def test_deny_blocks_a_host_a_wider_entry_still_covers(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots, allow=("sitex.com", "app.sitex.com"))
    status, out, _ = run(capsys, "deny", "sitex", "app.sitex.com")
    assert status == 0
    assert out.splitlines() == [
        "sitex: app.sitex.com is no longer allowed.",
        "sitex: app.sitex.com is denied, so a login will not allow it again.",
    ]
    saved = sites.load_policy(roots, "sitex")
    assert (saved.allow, saved.denied) == (("sitex.com",), ("app.sitex.com",))
    assert not sites.allows(saved, "app.sitex.com")
    assert sites.allows(saved, "www.sitex.com")


def test_deny_carves_out_a_host_with_no_entry_of_its_own(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots)
    status, out, _ = run(capsys, "deny", "sitex", "ads.sitex.com")
    assert status == 0
    assert "no longer allowed" not in out
    assert sites.load_policy(roots, "sitex").denied == ("ads.sitex.com",)
    status, out, _ = run(capsys, "deny", "sitex", "ads.sitex.com")
    assert out == "sitex: ads.sitex.com was already denied and not allowed. Nothing changed.\n"
    assert sites.load_policy(roots, "sitex").denied == ("ads.sitex.com",)


def test_deny_of_a_host_that_is_already_denied_changes_nothing(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots)
    run(capsys, "deny", "sitex", "other.example")
    before = sites.policy_path(roots, "sitex").stat().st_mtime_ns
    status, out, _ = run(capsys, "deny", "sitex", "other.example")
    assert (status, out) == (
        0,
        "sitex: other.example was already denied and not allowed. Nothing changed.\n",
    )
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


def test_forget_deletes_a_record_a_crash_left_in_the_screenshots_folder(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    seed(roots)
    shots = sites.downloads_path(roots, "sitex") / ".screenshots"
    shots.mkdir(parents=True, exist_ok=True)
    (shots / "fetch-left.har").write_text("{}", encoding="utf-8")
    status, _, _ = run(capsys, "forget", "sitex", "--yes")
    assert status == 0
    assert not shots.exists()
    assert not sites.downloads_path(roots, "sitex").exists()


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
    assert "--private-network" in run(capsys, "allow", "--help")[1]
    with pytest.raises(SystemExit) as exit_info:
        main(["allow"])
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
    "LimitNOFILE=65536",
    "TasksMax=8192",
    "MemoryHigh=50%",
    "MemoryMax=75%",
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
    with pytest.raises(cli.CommandError, match="not on PATH") as info:
        cli.valetkey_executable(lambda _name: None)
    # The routes the README gives, and not a package that nobody has published.
    assert "makepkg -si" in str(info.value)
    assert "uv tool install ." in str(info.value)
    assert "uv tool install valetkey" not in str(info.value)


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
    assert "uv tool install ." in err


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
            "/usr/bin/agent-browser --version": (0, "agent-browser 0.39.4\n"),
            "systemctl --user is-active valetkeyd.socket": (3, "inactive\n"),
        }
        self.probe: tuple[int, str] = (0, "")
        self.environ: dict[str, str] = {"XDG_RUNTIME_DIR": "/run/user/1000"}
        self.display: Path | cli.login.DisplayError = Path("/run/user/1000/wayland-1")
        self.offered: dict[str, int] | WaylandError = {"wl_compositor": 6, MANAGER: 1}
        self.units = tmp_path / "units"
        self.cpu = "x86_64"
        self.fallback: Path | None = None
        self.roots = sites.Roots(tmp_path / "cfg", tmp_path / "state", None)
        self.system_units: tuple[Path, ...] = ()
        self.calls: list[list[str]] = []
        self.remote = False
        self.viewer: Path | cli.display.RemoteDisplayError = tmp_path / "novnc"
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

    def interfaces(self, _socket: Path) -> dict[str, int]:
        if isinstance(self.offered, Exception):
            raise self.offered
        return self.offered

    def viewer_files(self) -> Path:
        if isinstance(self.viewer, Exception):
            raise self.viewer
        return self.viewer

    def system(self) -> cli.System:
        return System(
            which=self.which,
            run=self.run,
            environ=self.environ,
            wayland=self.wayland,
            offered=self.interfaces,
            remote_logins=lambda: self.remote,
            viewer=self.viewer_files,
            machine=lambda: self.cpu,
            runtime_fallback=lambda: self.fallback,
            roots=self.roots,
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
        "agent-browser": ("ok", "agent-browser 0.39.4"),
        "runtime-dir": ("ok", "XDG_RUNTIME_DIR=/run/user/1000"),
        "display": ("ok", "Wayland display /run/user/1000/wayland-1"),
        "security-context": ("ok", "the Wayland compositor restricts the login window"),
        "seccomp": ("ok", "the sandbox refuses 30 system calls a browser has no use for"),
        "units": ("info", "systemd units not installed; run `valetkey install-units`"),
        "socket": ("info", "valetkeyd.socket is inactive"),
    }
    probe = next(call for call in fake.calls if BWRAP_PROBE in call)
    assert probe[0] == "/usr/bin/bwrap"
    assert probe[-1] == "/usr/bin/true"
    assert all(flag in probe for flag in ("--ro-bind", "--dev", "--proc"))


@pytest.mark.parametrize(("cpu", "named"), [("aarch64", "aarch64"), ("", "this CPU")])
def test_doctor_warns_when_the_sandbox_has_no_syscall_filter(
    tmp_path: Path, cpu: str, named: str
) -> None:
    fake = FakeSystem(tmp_path, cpu=cpu)
    assert results(fake)["seccomp"] == (
        "warn",
        f"no syscall filter for {named}; the sandbox runs without one",
    )


def write_config(fake: FakeSystem, text: str, mode: int) -> None:
    path = fake.roots.config / "valetkey" / "config.json"
    path.parent.mkdir(parents=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)


def test_doctor_says_nothing_of_a_config_without_a_command(tmp_path: Path) -> None:
    fake = FakeSystem(tmp_path)
    assert "config" not in results(fake)
    write_config(fake, "{}", 0o600)
    assert "config" not in results(fake)


def test_doctor_accepts_a_private_config(tmp_path: Path) -> None:
    fake = FakeSystem(tmp_path)
    write_config(fake, '{"approve_command": ["/usr/bin/true"]}', 0o644)
    assert results(fake)["config"] == ("ok", "config.json is yours and nobody else can write to it")


@pytest.mark.parametrize("mode", [0o664, 0o666, 0o620, 0o602])
def test_doctor_fails_a_config_others_can_write_to(tmp_path: Path, mode: int) -> None:
    fake = FakeSystem(tmp_path)
    write_config(fake, '{"approve_command": ["/usr/bin/true"]}', mode)
    status, detail = results(fake)["config"]
    assert status == "fail"
    assert "config.json is ignored" in detail
    assert "chmod go-w" in detail


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


def test_doctor_warns_about_a_newer_agent_browser_and_does_not_fail(tmp_path: Path) -> None:
    fake = FakeSystem(tmp_path)
    fake.outputs["/usr/bin/agent-browser --version"] = (0, "agent-browser 0.40.1\n")
    assert results(fake)["agent-browser"] == (
        "warn",
        "agent-browser 0.40.1 is newer than 0.39.4, the version valetkey was tested with",
    )
    for version in ("0.39.0", "0.39.4"):
        fake.outputs["/usr/bin/agent-browser --version"] = (0, f"agent-browser {version}\n")
        assert results(fake)["agent-browser"] == ("ok", f"agent-browser {version}")


def test_doctor_names_the_versions_the_code_holds() -> None:
    text = " ".join((cli.doctor.__doc__ or "").split())
    minimum = sessions.short_version_text(sessions.MIN_VERSION)
    tested = sessions.version_text(sessions.TESTED_VERSION)
    assert f"agent-browser {minimum} or newer" in text
    assert f"newer than {tested}, the version valetkey was tested with" in text


@pytest.mark.parametrize("environ", [{}, {"XDG_RUNTIME_DIR": ""}, {"XDG_RUNTIME_DIR": "run"}])
def test_doctor_needs_a_runtime_dir(tmp_path: Path, environ: dict[str, str]) -> None:
    status, detail = results(FakeSystem(tmp_path, environ=environ))["runtime-dir"]
    assert status == "fail"
    assert "XDG_RUNTIME_DIR is not set to an absolute path" in detail
    assert "no private /run/user directory of yours" in detail


@pytest.mark.parametrize("environ", [{}, {"XDG_RUNTIME_DIR": ""}, {"XDG_RUNTIME_DIR": "run"}])
def test_doctor_says_when_it_uses_the_login_managers_runtime_dir(
    tmp_path: Path, environ: dict[str, str]
) -> None:
    fake = FakeSystem(tmp_path, environ=environ)
    fake.fallback = Path("/run/user/1000")
    status, detail = results(fake)["runtime-dir"]
    assert status == "warn"
    assert "valetkey uses /run/user/1000" in detail
    assert "docs/troubleshooting.md" in detail


def test_doctor_warns_when_the_compositor_cannot_restrict_the_login_window(tmp_path: Path) -> None:
    fake = FakeSystem(tmp_path, offered={"wl_compositor": 6})
    assert results(fake)["security-context"] == (
        "warn",
        cli.login.UNRESTRICTED_SHORT,
    )


def test_doctor_warns_when_the_compositor_cannot_be_asked(tmp_path: Path) -> None:
    fake = FakeSystem(tmp_path, offered=WaylandError("it did not answer"))
    status, detail = results(fake)["security-context"]
    assert (status, detail) == ("warn", "could not ask the Wayland compositor: it did not answer")


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
        "security-context",
        "seccomp",
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
        self.arguments: list[dict[str, Any]] = []

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        return None

    async def call(self, op: str, **args: Any) -> dict[str, Any]:  # noqa: ANN401 - JSON values
        self.asked.append(op)
        self.arguments.append(args)
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
    assert connection.arguments == [{"links": True}]


def test_status_json_is_the_daemons_answer(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    connect_to(monkeypatch, FakeConnection(status=ACTIVITY))
    status, out, _ = run(capsys, "status", "--json")
    assert status == 0
    assert json.loads(out) == ACTIVITY


REMOTE_LOGIN = {
    "site": "sitex",
    "since": "2026-10-26T09:05:00Z",
    "remote": {
        "url": "http://127.0.0.1:4242/TOKEN/vnc.html",
        "port": 4242,
        "ssh": "ssh -L 4242:localhost:4242 box",
    },
}


def test_status_shows_the_link_of_a_login_in_a_browser_and_how_to_reach_it(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = FakeConnection(status={"sessions": [], "logins": [REMOTE_LOGIN]})
    connect_to(monkeypatch, connection)
    status, out, _ = run(capsys, "status")
    assert status == 0
    lines = out.splitlines()
    assert lines[1].split() == ["login", "sitex", "2026-10-26T09:05:00Z", "-"]
    assert lines[-3:] == [
        "The sitex login is shown in a web browser.",
        "On the machine you will use, run: ssh -L 4242:localhost:4242 box",
        "Then open: http://127.0.0.1:4242/TOKEN/vnc.html",
    ]
    assert connection.arguments == [{"links": True}]


def test_status_json_asks_for_no_link_unless_told_to(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    plain = FakeConnection(status=ACTIVITY)
    connect_to(monkeypatch, plain)
    run(capsys, "status", "--json")
    assert plain.arguments == [{"links": False}]
    asked = FakeConnection(status={"sessions": [], "logins": [REMOTE_LOGIN]})
    connect_to(monkeypatch, asked)
    status, out, _ = run(capsys, "status", "--json", "--show-links")
    assert status == 0
    assert asked.arguments == [{"links": True}]
    assert json.loads(out)["logins"][0]["remote"]["url"].endswith("/TOKEN/vnc.html")


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


def test_allow_and_deny_keep_the_login_pages(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots)
    sites.save_policy(
        roots,
        sites.Policy(
            "sitex",
            "https://sitex.com/",
            ("sitex.com",),
            (),
            datetime(2026, 1, 1, tzinfo=UTC),
            ("sitex.com/login",),
        ),
    )
    run(capsys, "allow", "sitex", "login.okta.com")
    assert sites.load_policy(roots, "sitex").login_pages == ("sitex.com/login",)
    run(capsys, "deny", "sitex", "login.okta.com")
    assert sites.load_policy(roots, "sitex").login_pages == ("sitex.com/login",)


# -- private networks ----------------------------------------------------------------------


def test_sites_shows_the_listed_ranges(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots)
    run(capsys, "allow", "sitex", "--private-network", "10.20.0.0/24")
    run(capsys, "allow", "sitex", "--private-network", "fd00:1:2::/48")
    _, out, _ = run(capsys, "sites")
    assert (
        out.splitlines()[1].split()[-2:-1] == ["10.20.0.0/24,"]
        or "10.20.0.0/24, fd00:1:2::/48" in out
    )
    _, out, _ = run(capsys, "sites", "--json")
    assert json.loads(out)[0]["private_networks"] == ["10.20.0.0/24", "fd00:1:2::/48"]


def test_allow_and_deny_a_private_network(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots)
    status, out, _ = run(capsys, "allow", "sitex", "--private-network", "10.20.0.0/24")
    assert (status, out) == (0, "sitex: hosts it allows may now resolve inside 10.20.0.0/24.\n")
    assert sites.load_policy(roots, "sitex").private_networks == ("10.20.0.0/24",)
    before = sites.policy_path(roots, "sitex").stat().st_mtime_ns
    _, out, _ = run(capsys, "allow", "sitex", "--private-network", "10.20.0.0/24")
    assert out == "sitex: 10.20.0.0/24 was already listed.\n"
    assert sites.policy_path(roots, "sitex").stat().st_mtime_ns == before
    _, out, _ = run(capsys, "deny", "sitex", "--private-network", "10.20.0.0/24")
    assert out == "sitex: 10.20.0.0/24 is no longer listed.\n"
    assert sites.load_policy(roots, "sitex").private_networks == ()
    _, out, _ = run(capsys, "deny", "sitex", "--private-network", "10.20.0.0/24")
    assert out == "sitex: 10.20.0.0/24 was not listed.\n"


@pytest.mark.parametrize(
    "network",
    ["10.20.0.0", "10.20.0.1/24", "8.8.8.0/24", "127.0.0.0/8", "169.254.0.0/16", "10.0.0.0/7",
     "0.0.0.0/0", "::1/128", "fe80::/64", "fc00::/7", "::ffff:10.0.0.0/104", "nonsense/8"],
)  # fmt: skip
def test_a_range_that_is_not_private_or_too_wide_is_refused(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str], network: str
) -> None:
    make_site(roots)
    before = sites.policy_path(roots, "sitex").read_text(encoding="utf-8")
    status, _, err = run(capsys, "allow", "sitex", "--private-network", network)
    assert status == 1
    assert err.startswith("valetkey: ")
    assert sites.policy_path(roots, "sitex").read_text(encoding="utf-8") == before


def test_a_host_and_a_range_cannot_be_given_together_or_both_left_out(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots)
    for command in ("allow", "deny"):
        for extra in (["a.test", "--private-network", "10.0.0.0/24"], []):
            status, _, err = run(capsys, command, "sitex", *extra)
            assert (status, "not both" in err) == (1, True)


@pytest.mark.usefixtures("roots")
def test_a_range_change_for_an_unknown_site_fails(capsys: pytest.CaptureFixture[str]) -> None:
    status, _, err = run(capsys, "allow", "nosuch", "--private-network", "10.0.0.0/24")
    assert status == 1
    assert "nosuch" in err


def test_allow_a_host_keeps_the_listed_ranges(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots)
    run(capsys, "allow", "sitex", "--private-network", "10.20.0.0/24")
    run(capsys, "allow", "sitex", "login.okta.com")
    run(capsys, "deny", "sitex", "login.okta.com")
    assert sites.load_policy(roots, "sitex").private_networks == ("10.20.0.0/24",)


# -- add: a site before its first login ----------------------------------------------------


def test_add_writes_a_policy_with_the_start_host_and_the_ranges(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    status, out, _ = run(
        capsys, "add", "intra", "wiki.corp.test/home", "--private-network", "10.20.0.0/24",
        "--private-network", "fd12:3456:789a::/48", "--private-network", "10.20.0.0/24",
    )  # fmt: skip
    assert status == 0
    assert out.splitlines() == [
        "intra: added, starting at https://wiki.corp.test/home.",
        "intra: hosts it allows may resolve inside 10.20.0.0/24.",
        "intra: hosts it allows may resolve inside fd12:3456:789a::/48.",
        "intra: now ask your client to log in to intra.",
    ]
    saved = sites.load_policy(roots, "intra")
    assert saved == sites.Policy(
        "intra",
        "https://wiki.corp.test/home",
        ("wiki.corp.test",),
        (),
        None,
        (),
        ("10.20.0.0/24", "fd12:3456:789a::/48"),
    )


def test_add_without_a_range_is_a_plain_new_site(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    status, out, _ = run(capsys, "add", "plain", "http://app.test/")
    assert (status, out.count("\n")) == (0, 2)
    assert sites.load_policy(roots, "plain").private_networks == ()


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["Bad_Name", "https://a.test/"], "invalid site name"),
        (["UPPER", "https://a.test/"], "invalid site name"),
        (["a" * 60, "https://a.test/"], "invalid site name"),
        (["intra", "ftp://a.test/"], "http or https"),
        (["intra", "https://"], "host"),
        (["intra", "https://a.test/", "--private-network", "8.8.8.0/24"], "not in a private range"),
        (["intra", "https://a.test/", "--private-network", "10.0.0.0/7"], "not in a private range"),
        (["intra", "https://a.test/", "--private-network", "fd00::/47"], "too wide"),
        (["intra", "https://a.test/", "--private-network", "10.0.0.1"], "prefix length"),
    ],
)
def test_add_refuses_bad_input_and_writes_nothing(
    roots: sites.Roots,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
    message: str,
) -> None:
    status, _, err = run(capsys, "add", *arguments)
    assert status == 1
    assert message in err
    assert not list(sites.policy_path(roots, "x").parent.glob("*.json"))


def test_add_refuses_an_existing_site_unless_forced(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots)
    before = sites.policy_path(roots, "sitex").read_text(encoding="utf-8")
    status, _, err = run(capsys, "add", "sitex", "https://other.test/")
    assert status == 1
    assert "already exists" in err
    assert sites.policy_path(roots, "sitex").read_text(encoding="utf-8") == before
    status, _, _ = run(
        capsys, "add", "sitex", "https://other.test/", "--force", "--private-network", "10.0.0.0/24"
    )
    assert status == 0
    saved = sites.load_policy(roots, "sitex")
    assert (saved.start, saved.allow, saved.private_networks) == (
        "https://other.test/",
        ("other.test",),
        ("10.0.0.0/24",),
    )


def test_add_refuses_a_site_that_only_has_a_profile(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    sites.ensure_profile(roots, "orphan")
    status, _, err = run(capsys, "add", "orphan", "https://a.test/")
    assert (status, "already exists" in err) == (1, True)
    status, _, _ = run(capsys, "add", "orphan", "https://a.test/", "--force")
    assert status == 0
    assert sites.profile_path(roots, "orphan").is_dir()


def test_add_needs_a_site_and_a_url(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["add", "onlyone"])
    assert exit_info.value.code == 2
    assert "--private-network" in run(capsys, "add", "--help")[1]


def test_add_accepts_a_site_that_lives_at_an_address(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    status, _, _ = run(
        capsys, "add", "lab", "http://10.20.0.7/", "--private-network", "10.20.0.7/32"
    )
    saved = sites.load_policy(roots, "lab")
    assert (status, saved.allow, saved.private_networks) == (0, ("10.20.0.7",), ("10.20.0.7/32",))


# -- the bridge ----------------------------------------------------------------------------


def test_status_lists_a_connected_bridge(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    activity = ACTIVITY | {"bridges": [{"bridge": "bridge-abc", "since": "2026-10-26T09:10:00Z"}]}
    connect_to(monkeypatch, FakeConnection(status=activity))
    rows = run(capsys, "status")[1].splitlines()
    assert rows[-1].split() == ["bridge", "bridge-abc", "2026-10-26T09:10:00Z", "-"]
    connect_to(monkeypatch, FakeConnection(status=activity))
    assert json.loads(run(capsys, "status", "--json")[1]) == activity


def test_bridge_runs_until_stopped_and_cleans_up(
    roots: sites.Roots, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    async def fake_run(host: str, given: sites.Roots, **options: Any) -> None:  # noqa: ANN401
        seen.update(host=host, roots=given, **options)
        assert not options["stop"].is_set()

    monkeypatch.setattr(cli.bridging, "run_bridge", fake_run)
    monkeypatch.setattr(cli.bridging, "install_stop_signals", lambda stop: seen.update(sig=stop))
    assert main(["bridge", "server1", "--remote-runtime", "/run/user/1000"]) == 0
    assert (seen["host"], seen["roots"]) == ("server1", roots)
    assert seen["remote_runtime"] == Path("/run/user/1000")
    assert seen["sig"] is seen["stop"]
    seen.clear()
    assert main(["bridge", "server1"]) == 0
    assert seen["remote_runtime"] is None


@pytest.mark.usefixtures("roots")
def test_bridge_says_why_it_cannot_run(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["bridge", "-oProxyCommand=x"])  # an option the command does not know
    assert exit_info.value.code == 2
    status, out, err = run(capsys, "bridge", "bad host")
    assert (status, out) == (1, "")
    assert "not a host name" in err
    monkeypatch.delenv("XDG_RUNTIME_DIR")
    status, _, err = run(capsys, "bridge", "server1")
    assert (status, "XDG_RUNTIME_DIR" in err) == (1, True)


def test_bridge_hold_prints_the_runtime_directory_and_makes_the_folder(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    assert roots.runtime is not None
    status, out, _ = run(capsys, "bridge-hold", "--print-runtime")
    assert (status, out) == (0, f"{roots.runtime}\n")
    assert (roots.runtime / "valetkey").is_dir()


def test_bridge_hold_holds_the_named_connection(
    roots: sites.Roots, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    async def fake_hold(name: str, given: sites.Roots, **options: Any) -> int:  # noqa: ANN401
        seen.update(name=name, roots=given, **options)
        return 7

    monkeypatch.setattr(cli.bridging, "hold", fake_hold)
    monkeypatch.setattr(cli.bridging, "install_stop_signals", lambda stop: seen.update(sig=stop))
    assert main(["bridge-hold", "abcdef0123456789"]) == 7
    assert (seen["name"], seen["roots"]) == ("abcdef0123456789", roots)
    assert seen["sig"] is seen["stop"]


@pytest.mark.usefixtures("roots")
def test_bridge_hold_needs_a_name_and_a_good_one(capsys: pytest.CaptureFixture[str]) -> None:
    status, out, err = run(capsys, "bridge-hold")
    assert (status, out) == (1, "")
    assert "connection name" in err
    status, _, err = run(capsys, "bridge-hold", "no/good")
    assert (status, "8 to 64" in err) == (1, True)


def test_bridge_hold_is_not_listed_in_the_help(capsys: pytest.CaptureFixture[str]) -> None:
    out = run(capsys, "--help")[1]
    assert "bridge:" in out
    assert "bridge-hold" not in out


def test_install_units_bridge_writes_only_the_bridge_unit(
    units_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    status, out, err = run(capsys, "install-units", "--bridge")
    assert (status, err) == (0, "")
    assert sorted(p.name for p in units_home.iterdir()) == ["valetkey-bridge@.service"]
    unit = (units_home / "valetkey-bridge@.service").read_text(encoding="utf-8")
    assert unit.startswith(cli.UNIT_MARKER)
    assert "ExecStart=/opt/bin/valetkey bridge %I\n" in unit
    assert "@EXECUTABLE@" not in unit
    assert out.splitlines()[-2:] == [
        "    systemctl --user daemon-reload",
        "    systemctl --user enable --now valetkey-bridge@SERVER.service",
    ]
    assert "replace SERVER" in out


def test_install_units_bridge_dry_run_and_foreign_files(
    units_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    status, out, _ = run(capsys, "install-units", "--bridge", "--dry-run")
    assert (status, "Would write" in out, units_home.exists()) == (0, True, False)
    units_home.mkdir(parents=True)
    foreign = units_home / "valetkey-bridge@.service"
    foreign.write_text("[Service]\n", encoding="utf-8")
    status, _, err = run(capsys, "install-units", "--bridge")
    assert (status, str(foreign) in err) == (1, True)
    assert run(capsys, "install-units", "--bridge", "--force")[0] == 0


@pytest.mark.usefixtures("units_home")
def test_install_units_bridge_notes_a_packaged_unit(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    packaged = tmp_path / "packaged"
    packaged.mkdir()
    (packaged / "valetkey-bridge@.service").write_text("x", encoding="utf-8")
    monkeypatch.setattr(cli, "SYSTEM_UNIT_DIRS", (packaged,))
    assert "the units in" in run(capsys, "install-units", "--bridge")[1]


def test_the_bridge_unit_is_hardened_without_hiding_what_ssh_and_waypipe_need() -> None:
    unit = cli.render_unit("valetkey-bridge@.service", "/usr/bin/valetkey")
    lines = unit.splitlines()
    for line in (
        "NoNewPrivileges=yes",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "SystemCallFilter=@system-service",
        "WantedBy=graphical-session.target",
        "PartOf=graphical-session.target",
        "Restart=on-failure",
        "ExecStart=/usr/bin/valetkey bridge %I",
    ):
        assert line in lines
    # These put a user service in a user namespace, in which ssh refuses root's configuration, or
    # hide the graphics devices that waypipe shares buffers through.
    settings = {line.split("=")[0] for line in lines if "=" in line and not line.startswith("#")}
    assert not settings & {
        "ProtectSystem",
        "ProtectHome",
        "PrivateTmp",
        "PrivateDevices",
        "CapabilityBoundingSet",
        "ReadWritePaths",
        "ProtectKernelTunables",
    }


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze is missing")
def test_systemd_accepts_the_bridge_unit(tmp_path: Path) -> None:
    unit = tmp_path / "valetkey-bridge@.service"
    unit.write_text(cli.render_unit(unit.name, "/usr/bin/true"), encoding="utf-8")
    result = subprocess.run(  # noqa: S603  # fixed argument list
        ["systemd-analyze", "--user", "verify", str(unit)],  # noqa: S607  # resolved from PATH
        capture_output=True,
        text=True,
        check=False,
    )
    unit_problems = [
        line
        for line in result.stderr.splitlines()
        if "valetkey-bridge" in line and "Unknown" in line
    ]
    assert unit_problems == []


def test_doctor_says_nothing_about_remote_logins_while_they_are_off(tmp_path: Path) -> None:
    fake = FakeSystem(tmp_path, viewer=cli.display.RemoteDisplayError("missing"))
    assert "remote-login" not in results(fake)


def test_doctor_checks_what_a_remote_login_needs(tmp_path: Path) -> None:
    fake = FakeSystem(tmp_path, remote=True)
    fake.tools |= {"sway": "/usr/bin/sway", "wayvnc": "/usr/bin/wayvnc"}
    fake.outputs["/usr/bin/wayvnc --version"] = (0, "wayvnc: v0.10.2\n")
    assert results(fake)["remote-login"] == ("ok", "a login with no screen is shown in a browser")
    fake.outputs["/usr/bin/wayvnc --version"] = (0, "wayvnc: v0.8.0\n")
    assert results(fake)["remote-login"] == (
        "fail",
        "wayvnc 0.8 is too old; a login from a browser needs 0.9 or newer",
    )
    fake.tools.pop("sway")
    fake.tools.pop("wayvnc")
    assert results(fake)["remote-login"] == (
        "fail",
        "remote logins are on but sway and wayvnc not found",
    )
    fake.viewer = cli.display.RemoteDisplayError("the noVNC viewer is not installed; run it")
    assert results(fake)["remote-login"] == ("fail", "the noVNC viewer is not installed; run it")


def test_remote_logins_follow_the_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert cli.remote_logins_enabled() is False
    config = tmp_path / "valetkey" / "config.json"
    config.parent.mkdir()
    config.write_text('{"remote_logins": {"novnc": true}}', encoding="utf-8")
    assert cli.remote_logins_enabled() is True
    config.write_text("[]", encoding="utf-8")
    assert cli.remote_logins_enabled() is False


# -- accounts ------------------------------------------------------------------------------


def make_accounts(roots: sites.Roots) -> None:
    make_site(roots, "sitex", allow=("sitex.com",))
    sites.save_policy(
        roots, sites.Policy("sitex:work", "https://work.sitex.com/", ("work.sitex.com",))
    )


def test_a_bare_name_is_refused_for_a_site_with_several_accounts(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_accounts(roots)
    for argv in (
        ("allow", "sitex", "a.test"),
        ("deny", "sitex", "a.test"),
        ("forget", "sitex", "--yes"),
        ("allow", "sitex", "--private-network", "10.0.0.0/8"),
    ):
        assert run(capsys, *argv) == (
            1,
            "",
            "valetkey: sitex has accounts sitex:main, sitex:work. Say which.\n",
        )
    assert sites.load_policy(roots, "sitex").allow == ("sitex.com",)


def test_allow_deny_and_networks_act_on_the_named_account(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_accounts(roots)
    assert run(capsys, "allow", "sitex:work", "login.okta.com")[:2] == (
        0,
        "sitex:work: login.okta.com is allowed.\n",
    )
    assert sites.load_policy(roots, "sitex:work").allow == ("work.sitex.com", "login.okta.com")
    assert run(capsys, "deny", "sitex:work", "login.okta.com")[0] == 0
    assert run(capsys, "allow", "sitex:work", "--private-network", "10.0.0.0/8")[0] == 0
    assert sites.load_policy(roots, "sitex:work").private_networks == ("10.0.0.0/8",)
    assert sites.load_policy(roots, "sitex").private_networks == ()
    assert sites.load_policy(roots, "sitex").allow == ("sitex.com",)


def test_a_bare_name_is_the_only_account_of_a_site(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    sites.save_policy(
        roots, sites.Policy("sitex:work", "https://work.sitex.com/", ("work.sitex.com",))
    )
    status, out, _ = run(capsys, "allow", "sitex", "a.test")
    assert (status, out) == (0, "sitex:work: a.test is allowed.\n")


def test_forget_deletes_one_account_only(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    gone = seed(roots, "sitex:work")
    kept = seed(roots, "sitex")
    assert run(capsys, "forget", "sitex:work", "--yes") == (0, "Forgot sitex:work.\n", "")
    assert not any(path.exists() for path in gone)
    assert all(path.exists() for path in kept)


def test_sites_lists_each_account_with_its_account_field(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_accounts(roots)
    _, out, _ = run(capsys, "sites", "--json")
    assert [(row["site"], row["account"]) for row in json.loads(out)] == [
        ("sitex:main", "main"),
        ("sitex:work", "work"),
    ]
    _, table, _ = run(capsys, "sites")
    assert [line.split()[0] for line in table.splitlines()] == ["SITE", "sitex:main", "sitex:work"]
    assert run(capsys, "allow", "sitex:main", "a.test")[:2] == (0, "sitex: a.test is allowed.\n")


def test_add_makes_another_account_that_starts_with_the_hosts_of_one(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    sites.save_policy(
        roots,
        sites.Policy(
            "sitex",
            "https://sitex.com/",
            ("sitex.com", "login.okta.com"),
            ("ads.sitex.com",),
            datetime(2026, 10, 26, 9, 0, tzinfo=UTC),
            ("sitex.com/signin",),
            ("10.0.0.0/8",),
            ("login.okta.com.evil.test",),
        ),
    )
    status, out, _ = run(
        capsys, "add", "sitex:work", "https://work.sitex.com/", "--copy-hosts-from", "sitex"
    )
    assert status == 0
    assert out.splitlines() == [
        "sitex:work: added, starting at https://work.sitex.com/.",
        "sitex:work: copied 2 allowed and 2 left-out hosts from sitex.",
        "sitex:work: now ask your client to log in to sitex:work.",
    ]
    copy = sites.load_policy(roots, "sitex:work")
    assert copy.allow == ("work.sitex.com", "sitex.com", "login.okta.com")
    assert (copy.excluded, copy.denied) == (("ads.sitex.com",), ("login.okta.com.evil.test",))
    assert copy.private_networks == ()
    assert copy.learned is None
    assert copy.login_pages == ()


def test_add_copy_drops_an_exclusion_the_new_start_host_would_conflict_with(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots, "sitex", allow=("sitex.com",), excluded=("work.sitex.com",))
    assert run(capsys, "add", "sitex:work", "work.sitex.com", "--copy-hosts-from", "sitex")[0] == 0
    copy = sites.load_policy(roots, "sitex:work")
    assert copy.allow == ("work.sitex.com", "sitex.com")
    assert copy.excluded == ()


def test_add_copy_from_a_site_that_is_not_there_writes_nothing(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    status, _, err = run(capsys, "add", "sitex:work", "sitex.com", "--copy-hosts-from", "nosuch")
    assert status == 1
    assert "nosuch" in err
    assert not sites.policy_path(roots, "sitex:work").exists()


# -- one site in full ----------------------------------------------------------------------


def make_full_site(roots: sites.Roots) -> None:
    sites.save_policy(
        roots,
        sites.Policy(
            "sitex",
            "https://app.sitex.com/",
            ("sitex.com", "login.okta.com"),
            ("t.example",),
            datetime(2026, 10, 26, 9, 0, tzinfo=UTC),
            denied=("no.example",),
            private_networks=("10.0.0.0/8",),
        ),
    )
    sites.ensure_profile(roots, "sitex")


def test_sites_with_a_site_prints_every_host_of_its_three_lists(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_full_site(roots)
    make_site(roots, "another")
    status, out, _ = run(capsys, "sites", "sitex")
    assert status == 0
    assert out.splitlines() == [
        "sitex: starts at https://app.sitex.com/",
        "Learned: 2026-10-26T09:00:00Z. Login profile: yes.",
        "Allowed (2):",
        "  sitex.com",
        "  login.okta.com",
        "Excluded (left out by a login) (1):",
        "  t.example",
        "Denied (by you) (1):",
        "  no.example",
        "Private networks (1):",
        "  10.0.0.0/8",
    ]


def test_sites_with_a_site_and_nothing_learned_says_so(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots, "another")
    _, out, _ = run(capsys, "sites", "another")
    assert out.splitlines()[:3] == [
        "another: starts at https://app.another.com/",
        "Learned: never. Login profile: no.",
        "Allowed (1):",
    ]
    assert "Denied (by you) (0):" in out


def test_sites_with_a_site_as_json_is_one_object(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_full_site(roots)
    _, out, _ = run(capsys, "sites", "sitex", "--json")
    assert json.loads(out) == {
        "site": "sitex",
        "account": None,
        "start": "https://app.sitex.com/",
        "host": "app.sitex.com",
        "allow": ["sitex.com", "login.okta.com"],
        "excluded": ["t.example"],
        "denied": ["no.example"],
        "learned": "2026-10-26T09:00:00Z",
        "private_networks": ["10.0.0.0/8"],
        "profile": True,
    }


def test_sites_with_an_account_names_it_and_with_a_bare_name_asks_which(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_accounts(roots)
    _, out, _ = run(capsys, "sites", "sitex:work", "--json")
    assert json.loads(out)["site"] == "sitex:work"
    assert json.loads(out)["account"] == "work"
    _, out, _ = run(capsys, "sites", "sitex:main", "--json")
    assert (json.loads(out)["site"], json.loads(out)["account"]) == ("sitex:main", "main")
    assert run(capsys, "sites", "sitex") == (
        1,
        "",
        "valetkey: sitex has accounts sitex:main, sitex:work. Say which.\n",
    )


def test_sites_with_an_unknown_site_is_an_error(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    make_site(roots)
    status, out, err = run(capsys, "sites", "nosuch")
    assert (status, out) == (1, "")
    assert "nosuch" in err
