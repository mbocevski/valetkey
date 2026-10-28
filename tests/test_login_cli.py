# SPDX-License-Identifier: Apache-2.0
"""``valetkey login``: a login window opened from the command line, against a daemon that has a
stand-in for the window."""

import asyncio
from typing import Any

import pytest
from test_daemon import Rig, add_site, eventually, make_history, roots, run, serving

from valetkey import cli, client, sites
from valetkey.cli import main
from valetkey.proxy import SeenHost

__all__ = ["roots"]  # the fixture of the daemon tests, used by name


@pytest.fixture(autouse=True)
def environment(roots: sites.Roots, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the command at the daemon of the test."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(roots.config))
    monkeypatch.setenv("XDG_STATE_HOME", str(roots.state))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(roots.runtime))


async def command(*argv: str) -> int:
    """Run the command in a thread, so that the daemon of the test keeps running."""
    return await asyncio.to_thread(main, list(argv))


async def window_of(rig: Rig, count: int = 1) -> Any:  # noqa: ANN401 - the fake window
    await eventually(lambda: len(rig.logins.windows) >= count)
    return rig.logins.windows[count - 1]


async def finish(window: Any, roots: sites.Roots, urls: list[str]) -> None:  # noqa: ANN401
    """Close the window the way the person does, after a visit to ``urls``."""
    profile = roots.state / "profile"
    history = profile / "Default" / "History"
    history.parent.mkdir(parents=True, exist_ok=True)
    make_history(history, urls)
    await window.close_window(
        [SeenHost("newsite.test", 5), SeenHost("login.okta.test", 2)], profile
    )


def test_a_login_waits_for_the_window_to_close_and_prints_what_it_learned(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    async def scenario() -> None:
        async with serving(roots) as rig:
            task = asyncio.ensure_future(command("login", "https://newsite.test/signin"))
            window = await window_of(rig)
            assert not task.done()  # it waits
            await finish(
                window, roots, ["https://newsite.test/signin", "https://login.okta.test/a"]
            )
            assert await task == 0
            policy = sites.load_policy(roots, "newsite")
            assert policy.allow == ("login.okta.test", "newsite.test")

    run(scenario())
    out = capsys.readouterr().out
    assert "A login window for newsite is open on your screen." in out
    assert "Waiting for the window to close; Ctrl-C ends the login." in out
    assert "Saved your newsite login" in out
    assert "login.okta.test" in out


def test_what_the_window_refused_is_named_after_what_it_learned(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    async def scenario() -> None:
        async with serving(roots) as rig:
            task = asyncio.ensure_future(command("login", "https://newsite.test/signin"))
            window = await window_of(rig)
            window.refused = [("tracker.example", 443, "not allowed"), ("a.example", 8443, "port")]
            await finish(window, roots, ["https://newsite.test/signin"])
            assert await task == 0

    run(scenario())
    out = capsys.readouterr().out
    assert "Saved your newsite login" in out
    assert (
        "The login window refused: tracker.example:443 (not allowed), a.example:8443 (port)." in out
    )


def test_a_long_list_of_refusals_says_how_many_more_there_were() -> None:
    event = {"refused": [{"host": "a.example", "port": 443, "reason": "x"}], "refused_more": 3}
    assert cli._refused_text(event) == "The login window refused: a.example:443 (x) and 3 more."  # noqa: SLF001
    assert cli._refused_text({"refused": [], "refused_more": 0}) == ""  # noqa: SLF001
    assert cli._refused_text({}) == ""  # noqa: SLF001


def test_no_wait_returns_once_the_window_is_open(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            status = await command("login", "newsite.test", "--no-wait")
            assert status == 0
            (window,) = rig.logins.windows
            assert not window.done.is_set()  # still open
            assert (await c.call("sites"))["sites"][0]["state"] == "login"
            await c.call("close", site="newsite")

    run(scenario())
    out = capsys.readouterr().out
    assert "A login window for newsite is open on your screen." in out
    assert "valetkey sites newsite" in out
    assert "Waiting" not in out


def test_a_second_login_for_a_site_with_an_open_window_is_refused(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            assert await command("login", "newsite.test", "--no-wait") == 0
            assert await command("login", "newsite.test") == 1
            assert len(rig.logins.windows) == 1
            await c.call("close", site="newsite")

    run(scenario())
    assert "a login window for newsite is already open" in capsys.readouterr().err


def test_a_window_that_is_closed_by_something_else_ends_without_a_saved_login(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            task = asyncio.ensure_future(command("login", "newsite.test"))
            await window_of(rig)
            await c.call("close", site="newsite")
            assert await task == 1

    run(scenario())
    assert "The newsite login ended without being saved." in capsys.readouterr().out


def test_a_daemon_that_fails_to_say_what_was_learned_is_reported(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    ask = client.Client.call

    async def call(self: client.Client, op: str, **args: Any) -> dict[str, Any]:  # noqa: ANN401
        if op == "sites":
            code = "internal"
            raise client.DaemonError(code, "the daemon hit an unexpected error")
        return await ask(self, op, **args)

    monkeypatch.setattr(client.Client, "call", call)

    async def scenario() -> None:
        async with serving(roots) as rig:
            task = asyncio.ensure_future(command("login", "newsite.test"))
            window = await window_of(rig)
            await finish(window, roots, ["https://newsite.test/signin"])
            assert await task == 1

    run(scenario())
    assert "the daemon hit an unexpected error" in capsys.readouterr().err


def test_a_login_that_could_not_be_saved_exits_with_one(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    async def scenario() -> None:
        async with serving(roots) as rig:
            task = asyncio.ensure_future(command("login", "newsite.test"))
            window = await window_of(rig)
            # A history that cannot be read: the window closed, and nothing could be learned.
            profile = roots.state / "profile"
            (profile / "Default").mkdir(parents=True)
            (profile / "Default" / "History").write_bytes(b"this is not a database")
            await window.close_window([], profile)
            assert await task == 1

    run(scenario())
    assert "could not be saved" in capsys.readouterr().out


def test_ctrl_c_closes_the_window_and_ends_the_login() -> None:
    async def scenario() -> None:
        async with serving(roots_for_cli()) as rig:
            task = asyncio.ensure_future(cli._login_in_the_cli("newsite.test", None, wait=True))  # noqa: SLF001
            window = await window_of(rig)
            task.cancel()  # what Ctrl-C does to the command's task
            with pytest.raises(asyncio.CancelledError):
                await task
            await eventually(lambda: window.cancelled)
            await eventually(lambda: rig.daemon.registry.sites["newsite"].kind == "idle")
            assert not list(sites.known_sites(rig.daemon.roots))  # nothing was saved

    run(scenario())


def roots_for_cli() -> sites.Roots:
    return sites.roots_from_env()


def test_the_command_says_so_when_it_is_interrupted(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def interrupted(coroutine: Any) -> int:  # noqa: ANN401 - the coroutine that is never run
        coroutine.close()
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.asyncio, "run", interrupted)
    assert main(["login", "newsite.test"]) == 1
    assert "The login was ended; nothing was saved." in capsys.readouterr().out


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (client.DaemonError("daemon_start_failed", "valetkeyd exited."), "valetkeyd exited."),
        (sites.RuntimeDirUnavailableError("XDG_RUNTIME_DIR is not set"), "XDG_RUNTIME_DIR"),
    ],
)
def test_a_daemon_that_cannot_be_reached_is_reported(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: Exception,
    message: str,
) -> None:
    def broken(coroutine: Any) -> int:  # noqa: ANN401
        coroutine.close()
        raise error

    monkeypatch.setattr(cli.asyncio, "run", broken)
    assert main(["login", "newsite.test"]) == 1
    assert message in capsys.readouterr().err


def test_a_site_that_is_not_known_is_refused_with_the_daemons_words(
    roots: sites.Roots, capsys: pytest.CaptureFixture[str]
) -> None:
    add_site(roots, "sitex")

    async def scenario() -> None:
        async with serving(roots) as rig:
            assert await command("login", "nosuch") == 1
            assert rig.logins.windows == []

    run(scenario())
    assert "no site named 'nosuch'" in capsys.readouterr().err


def test_an_account_can_be_added_from_the_command(roots: sites.Roots) -> None:
    add_site(roots, "sitex")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            assert await command("login", "sitex", "--account", "work", "--no-wait") == 0
            (entry,) = [s for s in (await c.call("sites"))["sites"] if s["state"] == "login"]
            assert entry["site"] == "sitex:work"
            await c.call("close", site="sitex:work")

    run(scenario())


def test_what_the_command_says_of_a_window_follows_the_daemons_answer() -> None:
    assert cli._login_opened_text({"site": "sitex", "window": "open"}) == [  # noqa: SLF001
        "A login window for sitex is open on your screen."
    ]
    assert cli._login_opened_text(  # noqa: SLF001
        {"site": "sitex", "route": "bridge", "closed_session": True}
    ) == [
        "The running sitex session was closed to open the login.",
        "A login window for sitex is open on your laptop.",
    ]
    remote = {"ssh": "ssh -L 1:localhost:1 server", "url": "http://localhost:1/#x"}
    assert cli._login_opened_text({"site": "sitex", "remote": remote}) == [  # noqa: SLF001
        "The sitex login is shown in a web browser.",
        "On the machine you will use, run: ssh -L 1:localhost:1 server",
        "Then open: http://localhost:1/#x",
    ]
    assert cli._internal_name("sitex:main") == "sitex"  # noqa: SLF001
    assert cli._internal_name("sitex:work") == "sitex:work"  # noqa: SLF001
    assert cli._internal_name("sitex") == "sitex"  # noqa: SLF001
