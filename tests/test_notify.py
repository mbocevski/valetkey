# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
import os
import stat
from typing import TYPE_CHECKING, Any

import pytest
from conftest import REAL_NOTIFY_ASK

from valetkey import notify

if TYPE_CHECKING:
    from pathlib import Path

Q = notify.Question("s", "h.test", seen=True, reason="")
ENV = {"PATH": "/usr/bin", "HOME": "/home/me", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/bus"}
ACTIONS = json.dumps({"type": "as", "data": [["actions", "body", "persistence"]]})
NO_ACTIONS = json.dumps({"type": "as", "data": [["body", "persistence"]]})


def script(directory: Path, name: str, body: str) -> Path:
    path = directory / name
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def tools(directory: Path, *, caps: str | None = ACTIONS, send: str = "echo allow") -> Any:  # noqa: ANN401
    """Install fake ``busctl`` and ``notify-send``; the second records its arguments."""
    if caps is not None:
        script(directory, "busctl", f"cat <<'EOF'\n{caps}\nEOF")
    script(directory, "notify-send", f'printf "%s\\n" "$@" > "{directory}/argv"\n{send}')
    return lambda name: str(directory / name) if (directory / name).exists() else None


def run[T](coroutine: Any) -> T:  # noqa: ANN401
    return asyncio.run(asyncio.wait_for(coroutine, 20))


def test_the_command_names_the_site_and_host_and_quotes_the_agent() -> None:
    question = notify.Question("sitex:work", "cdn.example.com", seen=True, reason="it loads")
    argv = notify.command("/usr/bin/notify-send", question, 60)
    assert argv[:6] == [
        "/usr/bin/notify-send",
        "--app-name=valetkey",
        "--urgency=normal",
        "--expire-time=60000",
        "--action=allow=Allow",
        "--action=deny=Deny",
    ]
    assert argv[6] == "--"  # nothing after it can be read as an option
    assert argv[7] == "Allow sitex:work to reach cdn.example.com?"
    assert argv[8] == 'Seen during login: yes\nThe agent says: "it loads"'


def test_a_reason_that_looks_like_an_option_is_only_text() -> None:
    argv = notify.command(
        "n", notify.Question("s", "h.test", seen=False, reason="--action=allow=Evil"), 5
    )
    assert argv.index("--") < argv.index(
        'Seen during login: no\nThe agent says: "--action=allow=Evil"'
    )
    assert notify.command("n", notify.Question("s", "h.test", seen=False, reason=""), 5)[
        8
    ].endswith("(nothing)")


@pytest.mark.parametrize(
    ("send", "expected"),
    [
        ("echo allow", "yes"),
        ("echo deny", "no"),
        ("exit 0", "timeout"),  # closed without pressing a button: expired, never a no
        ("echo -1", "timeout"),
        ("echo something-else", "timeout"),
        ("echo allow; exit 1", "timeout"),
        ("echo deny; exit 3", "timeout"),
    ],
)
def test_only_a_button_press_answers_and_closing_is_never_a_no(
    tmp_path: Path, send: str, expected: str
) -> None:
    which = tools(tmp_path, send=send)
    outcome = run(
        REAL_NOTIFY_ASK(
            notify.Question("sitex", "cdn.example.com", seen=True, reason="x"), ENV, 5, which=which
        )
    )
    assert outcome == expected
    shown = (tmp_path / "argv").read_text(encoding="utf-8")
    assert "--action=allow=Allow" in shown
    assert "cdn.example.com" in shown


def test_a_question_nobody_answers_expires_and_is_stopped(tmp_path: Path) -> None:
    which = tools(tmp_path, send=f'echo $$ > "{tmp_path}/pid"; exec sleep 30')
    outcome = run(
        REAL_NOTIFY_ASK(
            notify.Question("sitex", "cdn.example.com", seen=False, reason=""),
            ENV,
            0.3,
            which=which,
        )
    )
    assert outcome == "timeout"
    pid = int((tmp_path / "pid").read_text(encoding="utf-8"))
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_nothing_is_shown_when_the_daemon_has_no_buttons(tmp_path: Path) -> None:
    which = tools(tmp_path, caps=NO_ACTIONS)
    assert run(REAL_NOTIFY_ASK(Q, ENV, 5, which=which)) == "none"
    assert not (tmp_path / "argv").exists()  # notify-send never ran


@pytest.mark.parametrize(
    "caps", ["not json", "{}", '{"data": []}', json.dumps({"data": [5]}), "exit 1"]
)
def test_a_capability_answer_that_cannot_be_read_means_no_buttons(
    tmp_path: Path, caps: str
) -> None:
    which = tools(tmp_path, caps="")
    script(tmp_path, "busctl", "exit 1" if caps == "exit 1" else f"echo '{caps}'")
    assert run(REAL_NOTIFY_ASK(Q, ENV, 5, which=which)) == "none"


def test_without_notify_send_or_a_way_to_ask_the_daemon_nobody_is_asked(tmp_path: Path) -> None:
    which = tools(tmp_path)

    def without(*names: str) -> Any:  # noqa: ANN401
        return lambda name: None if name in names else which(name)

    assert run(REAL_NOTIFY_ASK(Q, ENV, 5, which=without("notify-send"))) == "none"
    assert run(REAL_NOTIFY_ASK(Q, ENV, 5, which=without("busctl", "gdbus"))) == "none"


def test_gdbus_stands_in_for_busctl(tmp_path: Path) -> None:
    which = tools(tmp_path, caps=None)
    script(
        tmp_path,
        "gdbus",
        f"printf '%s\\n' \"$@\" > \"{tmp_path}/gdbus-argv\"\necho \"(['actions', 'body'],)\"",
    )
    assert run(REAL_NOTIFY_ASK(Q, ENV, 5, which=which)) == "yes"
    arguments = (tmp_path / "gdbus-argv").read_text(encoding="utf-8")
    assert "org.freedesktop.Notifications.GetCapabilities" in arguments
    script(tmp_path, "gdbus", "echo \"(['body'],)\"")
    assert run(REAL_NOTIFY_ASK(Q, ENV, 5, which=which)) == "none"


def test_a_daemon_that_does_not_answer_the_capability_question_in_time_means_no_buttons(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    which = tools(tmp_path)
    script(tmp_path, "busctl", "exec sleep 30")
    monkeypatch.setattr(notify, "CAPABILITY_TIMEOUT", 0.3)
    assert run(REAL_NOTIFY_ASK(Q, ENV, 5, which=which)) == "none"


def test_a_program_that_cannot_start_means_nobody_is_asked(tmp_path: Path) -> None:
    which = tools(tmp_path)
    (tmp_path / "notify-send").write_text("not a program", encoding="utf-8")
    (tmp_path / "notify-send").chmod(0o755)
    assert run(REAL_NOTIFY_ASK(Q, ENV, 5, which=which)) == "none"
    (tmp_path / "busctl").unlink()
    (tmp_path / "busctl").write_text("not a program", encoding="utf-8")
    (tmp_path / "busctl").chmod(0o755)
    assert run(notify.has_actions(ENV, which)) is False
