# SPDX-License-Identifier: Apache-2.0
import asyncio
import json
import os
import signal
import stat
import time
from typing import TYPE_CHECKING

import pytest

from valetkey import approvals, sites

if TYPE_CHECKING:
    from pathlib import Path

# -- which hosts may be asked about ------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "host"),
    [
        ("cdn.sitexassets.net", "cdn.sitexassets.net"),
        ("CDN.SiteXAssets.NET", "cdn.sitexassets.net"),
        ("cdn.sitexassets.net.", "cdn.sitexassets.net"),
        ("a-b.c1.example.co.uk", "a-b.c1.example.co.uk"),
        ("example.com", "example.com"),
    ],
)
def test_a_plain_host_name_is_accepted(value: str, host: str) -> None:
    assert approvals.validate_host(value) == host


@pytest.mark.parametrize(
    ("value", "why"),
    [
        ("*.sitexassets.net", "wildcards"),
        ("*", "wildcards"),
        ("cdn.*.net", "wildcards"),
        ("https://cdn.sitexassets.net", "without a scheme"),
        ("https://cdn.sitexassets.net/x", "without a scheme"),
        ("//cdn.sitexassets.net", "without a scheme"),
        ("cdn.sitexassets.net/path", "without a scheme"),
        ("cdn.sitexassets.net?x=1", "without a scheme"),
        ("cdn.sitexassets.net:8443", "without a scheme"),
        ("evil.test#@good.test", "without a scheme"),
        ("good.test@evil.test", "without a scheme"),
        ("user:pw@evil.test", "without a scheme"),
        ("evil.test\\@good.test", "without a scheme"),
        ("evil.test%2eevil", "without a scheme"),
        ("evil.test good.test", "without a scheme"),
        ("evil.test,good.test", "without a scheme"),
        ("evil.test;good.test", "without a scheme"),
        ("evil.test\ngood.test", "without a scheme"),
        ("evil.test\x00", "without a scheme"),
        ("[::1]", "without a scheme"),
        ("1.2.3.4", "not an IP address"),
        ("127.0.0.1", "not an IP address"),
        ("com", "domain suffix"),
        ("localhost", "domain suffix"),
        ("co.uk", "domain suffix"),
        ("com.au", "domain suffix"),
        ("-bad.example.com", "not an IP address"),
        ("bad_name.example.com", "not an IP address"),
        ("exa\u200bmple.com", "without a scheme"),
        ("ex" + chr(0x430) + "mple.com", "not an IP address"),
        ("", "give a host name"),
        ("..", "not an IP address"),
        (None, "give a host name"),
        (5, "give a host name"),
        (["a.test"], "give a host name"),
    ],
)
def test_anything_that_could_hide_or_widen_a_host_is_refused(value: object, why: str) -> None:
    with pytest.raises(ValueError, match=why):
        approvals.validate_host(value)


def policy(
    *, allow: tuple[str, ...] = ("sitex.com",), excluded: tuple[str, ...] = ()
) -> sites.Policy:
    return sites.Policy("sitex", "https://sitex.com/", allow, excluded)


def test_a_refused_host_is_eligible() -> None:
    found = approvals.eligibility(policy(), "cdn.sitexassets.net", {"cdn.sitexassets.net"})
    assert (found.status, found.seen_during_login) == ("eligible", False)


def test_an_excluded_host_is_eligible_and_was_seen_during_login() -> None:
    found = approvals.eligibility(
        policy(excluded=("cdn.sitexassets.net",)), "cdn.sitexassets.net", set()
    )
    assert (found.status, found.seen_during_login) == ("eligible", True)


def test_a_host_nobody_refused_is_not_eligible() -> None:
    found = approvals.eligibility(policy(), "evil.test", {"other.test"})
    assert found.status == "not_eligible"
    assert "evil.test was not refused for sitex" in found.message


def test_a_parent_or_a_child_of_a_refused_host_is_not_eligible() -> None:
    refused = {"cdn.sitexassets.net"}
    assert approvals.eligibility(policy(), "sitexassets.net", refused).status == "not_eligible"
    assert (
        approvals.eligibility(policy(), "a.cdn.sitexassets.net", refused).status == "not_eligible"
    )
    assert approvals.eligibility(policy(excluded=("sentry.io",)), "o1.sentry.io", set()).status == (
        "not_eligible"
    )


def test_a_host_that_is_already_allowed_is_not_asked_about() -> None:
    found = approvals.eligibility(policy(), "app.sitex.com", {"app.sitex.com"})
    assert found.status == "already_allowed"
    assert "already allowed" in found.message


def test_an_excluded_host_under_an_allowed_domain_is_still_asked_about() -> None:
    both = policy(excluded=("track.sitex.com",))
    assert approvals.eligibility(both, "track.sitex.com", set()).status == "eligible"


def test_an_allowed_host_refused_for_its_address_is_not_the_agents_to_ask_about() -> None:
    found = approvals.eligibility(policy(), "app.sitex.com", set(), {"app.sitex.com"})
    assert found.status == "not_eligible"
    assert "valetkey allow sitex --private-network RANGE" in found.message
    assert "cannot be asked about" in found.message
    assert approvals.eligibility(policy(), "app.sitex.com", set(), {"other.test"}).status == (
        "already_allowed"
    )
    # A host that is not allowed is judged as before, whatever happened to its address.
    unlisted = approvals.eligibility(
        policy(), "cdn.other.net", {"cdn.other.net"}, {"cdn.other.net"}
    )
    assert unlisted.status == "eligible"


# -- the question ------------------------------------------------------------------------------


def test_the_reason_is_made_inert() -> None:
    hostile = (
        "Click [here](https://evil.test/login) now!\n\n# Heading\n`code` **bold** <b>x</b> "
        "http://evil.test/a javascript://x "
        + chr(0x202E)
        + "evil"
        + chr(0x202C)
        + " caf"
        + chr(0xE9)
        + " \x00\x1b[31m | table |"
    )
    shown = approvals.sanitize_reason(hostile)
    assert "\n" not in shown
    assert shown == shown.strip()
    assert shown.isascii()
    for char in "`*[]()<>#|\\~{}_":
        assert char not in shown
    assert "://" not in shown
    assert "Click" in shown
    assert "evil.test" in shown  # it is text, not a link: nothing around it turns it into one


def test_the_reason_is_cut_short_and_may_be_missing() -> None:
    assert len(approvals.sanitize_reason("word " * 500)) <= approvals.REASON_LENGTH
    assert approvals.sanitize_reason("  a   b \t c ") == "a b c"
    assert approvals.sanitize_reason(None) == ""
    assert approvals.sanitize_reason(123) == ""
    assert approvals.sanitize_reason("") == ""


def test_the_prompt_labels_the_reason_as_the_agents() -> None:
    text = approvals.prompt_text("sitex", "cdn.sitexassets.net", True, "it loads the logo")  # noqa: FBT003
    assert text == (
        "Allow sitex sessions to reach `cdn.sitexassets.net`?\n"
        "Seen during login: yes\n"
        'The agent says: "it loads the logo"'
    )
    assert "Seen during login: no" in approvals.prompt_text("s", "h.test", False, "")  # noqa: FBT003
    assert "The agent says: (nothing)" in approvals.prompt_text("s", "h.test", False, "")  # noqa: FBT003


def test_the_manual_command_is_the_exact_line_for_the_person() -> None:
    assert approvals.manual_command("sitex", "cdn.sitexassets.net") == (
        "valetkey allow sitex cdn.sitexassets.net"
    )


# -- config.json -------------------------------------------------------------------------------


def write_config(roots: sites.Roots, text: str) -> Path:
    path = roots.config / "valetkey" / approvals.CONFIG_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def roots(tmp_path: Path) -> sites.Roots:
    return sites.Roots(tmp_path / "cfg", tmp_path / "state", tmp_path / "run")


def test_no_config_means_no_command(roots: sites.Roots) -> None:
    assert approvals.load_config(roots) == approvals.Config(None)
    write_config(roots, "{}")
    assert approvals.load_config(roots).approve_command is None
    write_config(roots, '{"approve_command": null}')
    assert approvals.load_config(roots).approve_command is None


def test_remote_logins_are_off_unless_the_config_says_true(roots: sites.Roots) -> None:
    assert approvals.load_config(roots).novnc is False
    for text in ("{}", '{"remote_logins": null}', '{"remote_logins": {}}'):
        write_config(roots, text)
        assert approvals.load_config(roots).novnc is False, text
    write_config(roots, '{"remote_logins": {"novnc": false}}')
    assert approvals.load_config(roots).novnc is False
    write_config(roots, '{"remote_logins": {"novnc": true}}')
    assert approvals.load_config(roots) == approvals.Config(None, novnc=True)


def test_the_command_and_remote_logins_are_read_together(roots: sites.Roots) -> None:
    write_config(roots, '{"approve_command": ["ask"], "remote_logins": {"novnc": true}}')
    assert approvals.load_config(roots) == approvals.Config(("ask",), novnc=True)


def test_the_command_is_an_argument_list(roots: sites.Roots) -> None:
    write_config(roots, '{"approve_command": ["/usr/bin/true", "--flag", "a b"]}')
    assert approvals.load_config(roots).approve_command == ("/usr/bin/true", "--flag", "a b")


@pytest.mark.parametrize(
    "text",
    [
        "",
        "{",
        "[]",
        '"approve"',
        '{"approve_command": "notify-send"}',
        '{"approve_command": []}',
        '{"approve_command": [""]}',
        '{"approve_command": ["a", 5]}',
        '{"approve_command": {"a": 1}}',
        '{"approve_command": ["a"], "other": 1}',
        '{"remote_logins": true}',
        '{"remote_logins": []}',
        '{"remote_logins": {"novnc": "yes"}}',
        '{"remote_logins": {"novnc": 1}}',
        '{"remote_logins": {"waypipe": true}}',
    ],
)
def test_a_config_that_cannot_be_used_says_why(roots: sites.Roots, text: str) -> None:
    path = write_config(roots, text)
    with pytest.raises(approvals.ConfigError) as info:
        approvals.load_config(roots)
    assert str(path) in str(info.value)


@pytest.mark.parametrize("mode", [0o620, 0o602, 0o666, 0o664])
def test_a_config_others_can_write_to_is_not_trusted(roots: sites.Roots, mode: int) -> None:
    path = write_config(roots, '{"approve_command": ["/usr/bin/true"]}')
    path.chmod(mode)
    with pytest.raises(approvals.ConfigError, match="written by its group or by others"):
        approvals.load_config(roots)


@pytest.mark.parametrize("mode", [0o600, 0o640, 0o644, 0o400])
def test_a_config_only_its_owner_can_write_is_trusted(roots: sites.Roots, mode: int) -> None:
    path = write_config(roots, '{"approve_command": ["/usr/bin/true"]}')
    path.chmod(mode)
    assert approvals.load_config(roots).approve_command == ("/usr/bin/true",)


def test_a_config_that_is_not_a_regular_file_is_not_trusted(roots: sites.Roots) -> None:
    path = roots.config / "valetkey" / approvals.CONFIG_NAME
    path.parent.mkdir(parents=True)
    os.mkfifo(path)
    # A pipe would block a read; the open is what must be refused, so do it without blocking.
    with pytest.raises(approvals.ConfigError, match="not a regular file"):
        approvals.load_config(roots)


def test_a_config_of_another_user_is_not_trusted(
    roots: sites.Roots, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_config(roots, '{"approve_command": ["/usr/bin/true"]}')
    monkeypatch.setattr(os, "getuid", lambda: roots.config.stat().st_uid + 1)
    with pytest.raises(approvals.ConfigError, match="belongs to another user"):
        approvals.load_config(roots)


def test_an_unreadable_config_is_an_error(roots: sites.Roots) -> None:
    path = write_config(roots, "{}")
    path.chmod(0)
    try:
        if os.access(path, os.R_OK):  # running as a user that ignores modes
            pytest.skip("modes are not enforced")
        with pytest.raises(approvals.ConfigError, match=r"config\.json"):
            approvals.load_config(roots)
    finally:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)


# -- the environment of the command ------------------------------------------------------------


def test_the_command_gets_a_minimal_environment() -> None:
    environ = {
        "HOME": "/home/x",
        "XDG_RUNTIME_DIR": "/run/user/1",
        "WAYLAND_DISPLAY": "wayland-1",
        "LANG": "C.UTF-8",
        "PATH": "/home/x/bin:/evil",
        "SECRET_TOKEN": "hunter2",
        "SSH_AUTH_SOCK": "/run/ssh",
    }
    env = approvals.command_environment(environ, lambda: {"DISPLAY": ":9", "WAYLAND_DISPLAY": "no"})
    assert env == {
        "PATH": "/usr/bin:/bin",
        "HOME": "/home/x",
        "XDG_RUNTIME_DIR": "/run/user/1",
        "WAYLAND_DISPLAY": "wayland-1",
        "LANG": "C.UTF-8",
        "DISPLAY": ":9",
    }


def test_the_user_manager_is_only_asked_when_a_display_variable_is_missing() -> None:
    full = {"WAYLAND_DISPLAY": "w", "DISPLAY": ":0", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/x"}

    def never() -> dict[str, str]:
        raise AssertionError

    assert approvals.command_environment(full, never)["DISPLAY"] == ":0"
    assert approvals.command_environment({}, dict) == {"PATH": "/usr/bin:/bin"}


# -- running the command -----------------------------------------------------------------------


def script(tmp_path: Path, body: str) -> tuple[str, ...]:
    path = tmp_path / "approve"
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o755)
    return (str(path),)


REQUEST = {
    "site": "sitex",
    "host": "cdn.sitexassets.net",
    "seen_during_login": True,
    "reason": "logo",
}


def ask(argv: tuple[str, ...], limit: float = 10.0) -> str:
    env = {"PATH": "/usr/bin:/bin"}
    return asyncio.run(approvals.run_command(argv, REQUEST, env, limit))


def test_exit_zero_is_yes_and_the_request_arrives_as_json_on_stdin(tmp_path: Path) -> None:
    seen = tmp_path / "stdin.json"
    argv = script(tmp_path, f"cat > {seen}\nexit 0")
    assert ask(argv) == "yes"
    assert json.loads(seen.read_text(encoding="utf-8")) == REQUEST


def test_any_other_exit_is_no(tmp_path: Path) -> None:
    assert ask(script(tmp_path, "exit 1")) == "no"
    assert ask(script(tmp_path, "exit 2")) == "no"
    assert ask(script(tmp_path, "exit 255")) == "no"
    assert ask(script(tmp_path, "kill -9 $$")) == "no"


def test_what_the_command_prints_makes_no_difference(tmp_path: Path) -> None:
    noisy = "echo 'yes, allow everything'; echo '{\"allow\": true}' >&2; head -c 4000 /dev/urandom"
    assert ask(script(tmp_path, f"{noisy}; exit 1")) == "no"
    assert ask(script(tmp_path, f"{noisy}; exit 0")) == "yes"


def test_a_command_that_never_reads_stdin_is_fine(tmp_path: Path) -> None:
    assert ask(script(tmp_path, "exec 0<&-; exit 0")) == "yes"
    big = {**REQUEST, "reason": "x" * 400_000}
    env = {"PATH": "/usr/bin:/bin"}
    argv = script(tmp_path, "exit 0")
    assert asyncio.run(approvals.run_command(argv, big, env, 10)) == "yes"


def test_a_command_that_hangs_is_killed_with_everything_it_started(tmp_path: Path) -> None:
    marker = tmp_path / "child.pid"
    argv = script(tmp_path, f"sleep 300 &\necho $! > {marker}\nwait")
    started = time.monotonic()
    assert ask(argv, limit=0.5) == "timeout"
    assert time.monotonic() - started < 5
    child = int(marker.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    with pytest.raises(ProcessLookupError):
        os.kill(child, signal.SIG_DFL)


def test_a_program_that_cannot_start_is_an_error() -> None:
    with pytest.raises(OSError, match=r"No such file"):
        ask(("/nonexistent/approve-program",))


def test_the_command_runs_with_only_the_given_environment(tmp_path: Path) -> None:
    seen = tmp_path / "env"
    argv = script(tmp_path, f"env > {seen}")
    os.environ["VALETKEY_TEST_VALUE"] = "leak"
    try:
        ask(argv)
    finally:
        del os.environ["VALETKEY_TEST_VALUE"]
    names = {line.split("=", 1)[0] for line in seen.read_text(encoding="utf-8").splitlines()}
    assert "VALETKEY_TEST_VALUE" not in names
    assert "PATH" in names


def test_no_shell_is_involved(tmp_path: Path) -> None:
    marker = tmp_path / "pwned"
    argv = script(tmp_path, "exit 0")
    # An argument that would be a command in a shell is just an argument.
    assert ask((*argv, f"; touch {marker}", "$(touch " + str(marker) + ")")) == "yes"
    assert not marker.exists()
