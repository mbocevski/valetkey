# SPDX-License-Identifier: Apache-2.0

import io
import json
import os
import runpy
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from valetkey import __version__, cli, daemon, sites
from valetkey.cli import main


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
