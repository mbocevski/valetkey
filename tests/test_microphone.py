# SPDX-License-Identifier: Apache-2.0
"""The microphone setting: the policy key, the daemon's questions and answers, what shows it."""

import json
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from test_daemon import (
    FakeNotifier,
    Notifier,
    add_site,
    next_event,
    run,
    serving,
    write_approver,
)

from valetkey import approvals, notify, session_ops, sites
from valetkey.client import DaemonError

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


@pytest.fixture
def roots(short_dir: Path) -> sites.Roots:
    (short_dir / "r").mkdir(mode=0o700)
    return sites.Roots(short_dir / "c", short_dir / "s", short_dir / "r")


def with_microphone(roots: sites.Roots, *, on: bool = True) -> None:
    sites.save_policy(roots, replace(sites.load_policy(roots, "sitex"), microphone=on))


def microphone_of(roots: sites.Roots) -> bool:
    return sites.load_policy(roots, "sitex").microphone


# -- the policy ---------------------------------------------------------------------------


def test_the_microphone_is_off_unless_the_policy_says_so(roots: sites.Roots) -> None:
    add_site(roots)
    assert microphone_of(roots) is False
    # Off is not written, so a file from before the setting is byte for byte what is saved.
    assert "microphone" not in sites.policy_path(roots, "sitex").read_text()
    with_microphone(roots)
    assert json.loads(sites.policy_path(roots, "sitex").read_text())["microphone"] is True
    assert microphone_of(roots) is True
    with_microphone(roots, on=False)
    assert "microphone" not in sites.policy_path(roots, "sitex").read_text()


@pytest.mark.parametrize("value", ["yes", 1, None, []])
def test_a_policy_whose_microphone_is_not_true_or_false_is_refused(
    roots: sites.Roots, value: object
) -> None:
    add_site(roots)
    path = sites.policy_path(roots, "sitex")
    data = json.loads(path.read_text())
    path.write_text(json.dumps(data | {"microphone": value}))
    with pytest.raises(sites.PolicyError, match="microphone must be true or false"):
        sites.load_policy(roots, "sitex")


def test_allowing_and_denying_hosts_keeps_the_microphone(roots: sites.Roots) -> None:
    add_site(roots)
    with_microphone(roots)
    policy = sites.load_policy(roots, "sitex")
    allowed, *_ = sites.allow_host(policy, "cdn.assets.test")
    assert allowed.microphone is True
    assert sites.deny_host(allowed, "cdn.assets.test").microphone is True


# -- the daemon: sessions ---------------------------------------------------------------


def test_only_a_site_with_the_microphone_on_asks_for_it_and_says_so(roots: sites.Roots) -> None:
    add_site(roots, "sitex")
    add_site(roots, "another")
    with_microphone(roots)
    told: list[tuple[str, dict[str, Any]]] = []

    async def announcer(site: str, **options: Any) -> None:  # noqa: ANN401
        told.append((site, options))

    async def scenario() -> None:
        async with (
            serving(roots, announcer=announcer) as rig,
            await rig.connect() as c,
            await rig.connect() as w,
        ):
            stream = w.watch()
            assert (await next_event(stream))["sessions"] == []
            await c.call("open", site="another")
            started = await next_event(stream)
            assert (started["event"], started["site"], started["microphone"]) == (
                "session_started",
                "another",
                False,
            )
            await c.call("open", site="sitex")
            started = await next_event(stream)
            assert (started["site"], started["microphone"]) == ("sitex", True)
            assert rig.factory.microphone == [False, True]
            await stream.aclose()

    run(scenario())
    assert sorted(told, key=lambda item: item[0]) == [
        ("another", {}),
        ("sitex", {"microphone": True}),
    ]


def test_status_says_which_sessions_have_the_microphone_and_where_it_records(
    roots: sites.Roots,
) -> None:
    add_site(roots, "sitex")
    add_site(roots, "another")
    with_microphone(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c, await rig.connect() as w:
            await c.call("open", site="another")
            await c.call("open", site="sitex")
            rig.factory.made[1].capture = {
                "socket": "/s/pulse/native",
                "node": 52,
                "directory": "/s",
            }
            listing = {s["site"]: s for s in (await c.call("status"))["sessions"]}
            assert listing["another"]["microphone"] is False
            assert "capture" not in listing["another"]
            assert listing["sitex"]["microphone"] is True
            assert listing["sitex"]["capture"] == {
                "socket": "/s/pulse/native",
                "node": 52,
                "directory": "/s",
            }
            one = await c.call("status", site="sitex")
            assert (one["microphone"], one["capture"]["node"]) == (True, 52)
            assert (await c.call("status", site="another"))["microphone"] is False
            assert "capture" not in await c.call("status", site="another")
            # watch tells whether each session has it, and never where it records.
            snapshot = await next_event(w.watch())
            assert {s["site"]: s["microphone"] for s in snapshot["sessions"]} == {
                "another": False,
                "sitex": True,
            }
            assert all("capture" not in s for s in snapshot["sessions"])

    run(scenario())


def test_a_session_with_the_microphone_but_nothing_to_report_has_no_capture(
    roots: sites.Roots,
) -> None:
    add_site(roots)
    with_microphone(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            assert rig.factory.made[0].capture is None
            (entry,) = (await c.call("status"))["sessions"]
            assert entry["microphone"] is True
            assert "capture" not in entry
            assert "capture" not in await c.call("status", site="sitex")

    run(scenario())


def test_a_session_that_ends_has_no_microphone_and_the_next_one_follows_the_policy(
    roots: sites.Roots,
) -> None:
    add_site(roots)
    with_microphone(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            with_microphone(roots, on=False)
            # A running session is not changed by the setting.
            await c.call("reload_policy", site="sitex")
            assert (await c.call("status"))["sessions"][0]["microphone"] is True
            await c.call("close", site="sitex")
            assert rig.daemon.registry.state("sitex").microphone is False
            await c.call("open", site="sitex")
            assert rig.factory.microphone == [True, False]
            assert (await c.call("status"))["sessions"][0]["microphone"] is False

    run(scenario())


def test_sites_say_whether_the_microphone_is_on(roots: sites.Roots) -> None:
    add_site(roots, "sitex")
    add_site(roots, "another")
    with_microphone(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            listing = {s["site"]: s["microphone"] for s in (await c.call("sites"))["sites"]}
            assert listing == {"another": False, "sitex": True}

    run(scenario())


def test_a_login_window_is_never_started_with_the_microphone(roots: sites.Roots) -> None:
    add_site(roots)
    with_microphone(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("login", target="sitex")
            assert "microphone" not in rig.logins.options[0]
            assert (await c.call("status"))["logins"] == [
                {"site": "sitex", "since": "2026-10-27T12:00:00Z"}
            ]

    run(scenario())


def test_the_real_announcement_says_when_the_microphone_is_on(
    real_announce: Callable[..., Awaitable[None]],
) -> None:
    messages: list[str] = []

    async def spawn(*args: Any, **_kwargs: Any) -> FakeNotifier:  # noqa: ANN401
        messages.append(args[-1])
        return FakeNotifier()

    run(real_announce("sitex", which=lambda _name: "/x", spawn=spawn))
    run(real_announce("sitex", microphone=True, which=lambda _name: "/x", spawn=spawn))
    assert messages == [
        "valetkey: a browser session for sitex started",
        "valetkey: a browser session for sitex started, with the microphone on",
    ]


def test_the_real_session_factory_passes_the_microphone(
    roots: sites.Roots, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[dict[str, Any]] = []

    def fake_start(*_args: Any, **kwargs: Any) -> str:  # noqa: ANN401
        seen.append(kwargs)
        return "session"

    monkeypatch.setattr(session_ops.sessions.Session, "start", fake_start)
    session_ops.start_session(roots, "sitex", "https://x.test/", Path("/p.sock"), microphone=True)
    assert seen[0]["microphone"] is True


# -- the daemon: the questions ----------------------------------------------------------


def test_the_daemon_says_whether_the_microphone_is_on_and_whether_it_can_ask(
    roots: sites.Roots,
) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            first = await c.call("microphone_check", site="sitex")
            assert first == {"site": "sitex", "enabled": False, "can_ask": False}
            write_approver(roots, "exit 0")
            with_microphone(roots)
            second = await c.call("microphone_check", site="sitex")
            assert second == {"site": "sitex", "enabled": True, "can_ask": True}
            with pytest.raises(DaemonError) as info:
                await c.call("microphone_check", site="nosuch")
            assert info.value.code == "unknown_site"

    run(scenario())


def test_the_approval_command_is_asked_for_the_microphone_with_its_own_request(
    roots: sites.Roots, tmp_path: Path
) -> None:
    add_site(roots)
    seen = tmp_path / "stdin.json"
    write_approver(roots, f"cat > {seen}\nexit 0")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            answer = await c.call(
                "microphone_ask", site="sitex", reason="To join the [call](http://evil.test/)"
            )
            assert answer["result"] == "allowed"
            assert answer["site"] == "sitex"
            assert "now on" in answer["message"]
            assert "from now on" in answer["message"]

    run(scenario())
    assert json.loads(seen.read_text()) == {
        "site": "sitex",
        "permission": "microphone",
        "reason": "To join the call evil.test/",
    }
    assert microphone_of(roots) is True


@pytest.mark.parametrize(
    ("script", "result", "words"),
    [
        ("exit 1", "denied", "said no"),
        ("sleep 30", "expired", "Nobody answered"),
    ],
)
def test_a_no_or_no_answer_leaves_the_microphone_off_and_is_not_remembered(
    roots: sites.Roots, monkeypatch: pytest.MonkeyPatch, script: str, result: str, words: str
) -> None:
    monkeypatch.setattr(approvals, "COMMAND_TIMEOUT", 0.3)
    add_site(roots)
    write_approver(roots, script)

    async def scenario() -> None:
        async with serving(roots, approve_timeout=0.3) as rig, await rig.connect() as c:
            for _ in range(2):  # the second time is asked as well: a no is not sticky
                answer = await c.call("microphone_ask", site="sitex", reason="")
                assert answer["result"] == result
                assert words in answer["message"]
                assert microphone_of(roots) is False
            write_approver(roots, "exit 0")
            assert (await c.call("microphone_ask", site="sitex", reason=""))["result"] == "allowed"

    run(scenario())


def test_a_command_that_cannot_run_and_nobody_to_ask_both_leave_the_command_to_the_person(
    roots: sites.Roots,
) -> None:
    add_site(roots)
    folder = roots.config / "valetkey"
    folder.mkdir(parents=True, exist_ok=True)
    config = folder / "config.json"

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            config.write_text('{"approve_command": ["/nonexistent/program"]}')
            broken = await c.call("microphone_ask", site="sitex", reason="")
            assert broken["result"] == "could_not_ask"
            assert "could not run" in broken["message"]
            assert broken["message"].endswith("Run: valetkey mic sitex on")
            config.write_text('{"notifications": false}')
            nobody = await c.call("microphone_ask", site="sitex", reason="")
            assert nobody["result"] == "could_not_ask"
            assert nobody["message"].endswith("Run: valetkey mic sitex on")
            assert microphone_of(roots) is False

    run(scenario())


@pytest.mark.parametrize(
    ("outcome", "result"),
    [("yes", "allowed"), ("no", "denied"), ("timeout", "expired"), ("none", "could_not_ask")],
)
def test_a_notification_asks_about_the_microphone_when_there_is_no_command(
    roots: sites.Roots, outcome: str, result: str
) -> None:
    add_site(roots)
    notifier = Notifier(outcome)

    async def scenario() -> None:
        async with serving(roots, notifier=notifier) as rig, await rig.connect() as c:
            answer = await c.call("microphone_ask", site="sitex", reason="it **hears**")
            assert answer["result"] == result
            (question, _env, limit) = notifier.asked[0]
            assert (question.site, question.microphone, question.reason) == (
                "sitex",
                True,
                "it hears",
            )
            assert limit == approvals.COMMAND_TIMEOUT

    run(scenario())
    assert microphone_of(roots) is (outcome == "yes")


def test_a_microphone_that_is_on_is_not_asked_about_again(roots: sites.Roots) -> None:
    add_site(roots)
    with_microphone(roots)
    notifier = Notifier("no")

    async def scenario() -> None:
        async with serving(roots, notifier=notifier) as rig, await rig.connect() as c:
            answer = await c.call("microphone_ask", site="sitex", reason="")
            assert answer["result"] == "allowed"
            assert "already on" in answer["message"]

    run(scenario())
    assert notifier.asked == []
    assert microphone_of(roots) is True


def test_a_yes_from_the_clients_interface_turns_it_on_and_only_on_that_channel(
    roots: sites.Roots,
) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            with pytest.raises(DaemonError) as info:
                await c.call("microphone_apply", site="sitex", channel="command")
            assert info.value.code == "bad_request"
            assert microphone_of(roots) is False
            answer = await c.call("microphone_apply", site="sitex", channel="elicitation")
            assert answer["result"] == "allowed"
            assert microphone_of(roots) is True

    run(scenario())


def test_a_running_session_is_told_to_open_again_to_have_the_microphone(
    roots: sites.Roots,
) -> None:
    add_site(roots)

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("open", site="sitex")
            answer = await c.call("microphone_apply", site="sitex", channel="elicitation")
            assert (
                "The running session does not have it: close it, then open it again."
                in (answer["message"])
            )
            assert (await c.call("status"))["sessions"][0]["microphone"] is False

    run(scenario())


# -- the questions in words -----------------------------------------------------------


def test_the_notification_for_the_microphone_names_the_site_and_quotes_the_agent() -> None:
    question = notify.Question("sitex", "", seen=False, reason="to join a call", microphone=True)
    argv = notify.command("/usr/bin/notify-send", question, 60)
    assert argv[-2] == "Turn on the microphone for sitex?"
    assert 'The agent says: "to join a call"' in argv[-1]
    assert "--action=allow=Allow" in argv
    assert "--action=deny=Deny" in argv
    assert not any("--action=keep" in word for word in argv)


def test_the_question_for_the_microphone_in_a_client_says_what_turning_it_on_does() -> None:
    text = approvals.microphone_prompt_text("sitex", "")
    assert text.startswith("Turn on the microphone for sitex sessions?")
    assert "The agent says: (nothing)" in text
    assert "valetkey mic" in text
    assert approvals.manual_microphone_command("sitex:work") == "valetkey mic sitex:work on"
