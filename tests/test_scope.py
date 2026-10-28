# SPDX-License-Identifier: Apache-2.0
"""A connection limited to named sites: ``valetkey mcp --site``, enforced by the daemon."""

from typing import TYPE_CHECKING, Any

import pytest
from mcp import Client as McpClient
from test_daemon import add_site, next_event, roots, run, serving
from test_mcp_server import FakeDaemon, fail, text_of

from valetkey import daemon, mcp_server, sites
from valetkey.cli import main
from valetkey.client import DaemonError
from valetkey.mcp_server import Bridge, build_server
from valetkey.scope import Scope

if TYPE_CHECKING:
    from pathlib import Path


__all__ = ["roots"]  # the fixture of the daemon tests, used by name


# -- the scope ------------------------------------------------------------------------------


def test_a_bare_site_covers_all_its_accounts_and_an_account_covers_one() -> None:
    whole = Scope.parse(["sitex"])
    assert all(whole.covers(name) for name in ("sitex", "sitex:work", "sitex:home"))
    assert not whole.covers("another")
    assert not whole.covers("sitex-2")
    one = Scope.parse(["sitex:work"])
    assert one.covers("sitex:work")
    assert not one.covers("sitex")
    assert not one.covers("sitex:home")
    assert not one.covers("another:work")
    first = Scope.parse(["sitex:main"])
    assert first.covers("sitex")
    assert not first.covers("sitex:work")


def test_a_scope_reads_site_names_and_lists_them_back() -> None:
    parsed = Scope.parse(["sitex", "sitex:work", "sitex", "another:main"])
    assert parsed.entries == (("sitex", None), ("sitex", "work"), ("another", "main"))
    assert parsed.allowed() == "sitex, sitex:work, another:main"


@pytest.mark.parametrize("values", [[], ["Bad Name"], ["sitex:"], [5], ["a:b:c"], ["-x"]])
def test_a_scope_that_is_not_site_names_is_refused(values: list[object]) -> None:
    with pytest.raises(ValueError, match=r"."):
        Scope.parse(values)


def test_the_refusals_name_the_allowed_sites() -> None:
    limited = Scope.parse(["sitex", "sitex:work"])
    error = limited.refusal("other")
    assert (error.code, error.message) == (
        "out_of_scope",
        'site "other" is outside this server\'s scope (allowed: sitex, sitex:work)',
    )
    assert "\n" not in limited.refusal("a\nb" * 50).message
    assert limited.refuse_operation("bridge_register").code == "out_of_scope"


def test_activity_and_events_are_cut_to_the_sites_in_scope() -> None:
    limited = Scope.parse(["sitex"])
    activity = {
        "sessions": [{"site": "sitex"}, {"site": "another"}],
        "logins": [{"site": "another"}, {"site": "sitex:work"}],
        "bridges": [{"bridge": "b"}],
        "at": "now",
    }
    assert limited.filter_activity(activity) == {
        "sessions": [{"site": "sitex"}],
        "logins": [{"site": "sitex:work"}],
        "bridges": [],
        "at": "now",
    }
    assert limited.allows_event({"event": "session_started", "site": "sitex"})
    assert not limited.allows_event({"event": "session_started", "site": "another"})
    assert not limited.allows_event({"event": "bridge_connected", "bridge": "b"})


# -- the daemon -----------------------------------------------------------------------------


def add_account(roots: sites.Roots, name: str) -> None:
    """Save a site or one account of a site, which starts at its site's own address."""
    host = f"{name.partition(':')[0]}.test"
    sites.save_policy(roots, sites.Policy(name, f"https://{host}/", (host,)))


SITE_ARGUMENTS = {
    "host": "cdn.assets.test",
    "hosts": ["cdn.assets.test"],
    "ref": "e1",
    "text": "x",
    "url": "https://another.test/",
    "reason": "let me",
    "approved": True,
    "channel": "command",
}


def test_every_operation_that_names_a_site_refuses_a_site_out_of_scope(
    roots: sites.Roots,
) -> None:
    add_site(roots, "sitex")
    add_site(roots, "another")
    assert {*daemon._SITE_OPS, "sites", "status"} | {"login", "scope"} <= set(  # noqa: SLF001
        daemon.Daemon(roots)._ops  # noqa: SLF001
    ) | {"watch"}

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c, await rig.connect() as free:
            assert await c.call("scope", sites=["sitex"]) == {"allowed": "sitex"}
            for op in sorted({*daemon._SITE_OPS, "sites", "status"}):  # noqa: SLF001
                with pytest.raises(DaemonError) as info:
                    await c.call(op, site="another", **SITE_ARGUMENTS)
                assert info.value.code == "out_of_scope", op
                assert info.value.message == (
                    'site "another" is outside this server\'s scope (allowed: sitex)'
                ), op
            # Nothing was done to the other site, which a connection with no scope still sees.
            assert (await free.call("status"))["sessions"] == []
            assert [s["state"] for s in (await free.call("sites"))["sites"]] == ["idle", "idle"]
            # The site in scope still works.
            assert (await c.call("open", site="sitex"))["site"] == "sitex"

    run(scenario())


def test_a_connection_with_no_scope_is_not_limited(roots: sites.Roots) -> None:
    add_site(roots, "sitex")
    add_site(roots, "another")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            assert {s["site"] for s in (await c.call("sites"))["sites"]} == {"sitex", "another"}
            assert (await c.call("open", site="another"))["site"] == "another"

    run(scenario())


def test_the_site_listing_shows_only_the_sites_in_scope(roots: sites.Roots) -> None:
    add_site(roots, "sitex")
    add_site(roots, "another")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("scope", sites=["sitex"])
            assert [s["site"] for s in (await c.call("sites"))["sites"]] == ["sitex"]
            assert (await c.call("sites", site="sitex"))["sites"][0]["site"] == "sitex"

    run(scenario())


def test_an_operation_that_names_no_site_is_refused_to_a_scope(roots: sites.Roots) -> None:
    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("scope", sites=["sitex"])
            with pytest.raises(DaemonError) as info:
                await c.call("bridge_register", rand="abcdef")
            assert info.value.code == "out_of_scope"
            with pytest.raises(DaemonError) as unknown:
                await c.call("no_such_operation")
            assert unknown.value.code == "unknown_op"

    run(scenario())


def test_the_scope_is_set_once_and_nothing_widens_it(roots: sites.Roots) -> None:
    add_site(roots, "sitex")
    add_site(roots, "another")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("scope", sites=["sitex"])
            for wider in (["sitex", "another"], ["another"], ["sitex"]):
                with pytest.raises(DaemonError) as info:
                    await c.call("scope", sites=wider)
                assert info.value.code == "scope_set"
            with pytest.raises(DaemonError) as refused:
                await c.call("open", site="another")
            assert refused.value.code == "out_of_scope"
            # Another connection has a scope of its own, or none: this one's is not shared.
            async with await rig.connect() as other:
                assert (await other.call("open", site="another"))["site"] == "another"

    run(scenario())


@pytest.mark.parametrize("sites_value", [None, "sitex", [], ["Bad Name"], [5]])
def test_a_scope_that_cannot_be_read_is_refused_and_leaves_the_connection_open(
    roots: sites.Roots, sites_value: object
) -> None:
    add_site(roots, "another")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            with pytest.raises(DaemonError) as info:
                await c.call("scope", sites=sites_value)
            assert info.value.code == "bad_request"
            assert (await c.call("open", site="another"))["site"] == "another"  # no scope yet

    run(scenario())


def test_accounts_in_scope(roots: sites.Roots) -> None:
    add_site(roots, "sitex")
    add_account(roots, "sitex:work")
    add_site(roots, "another")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("scope", sites=["sitex:work"])
            assert [s["site"] for s in (await c.call("sites"))["sites"]] == ["sitex:work"]
            for refused in ("sitex", "sitex:main", "sitex:home", "another"):
                with pytest.raises(DaemonError) as info:
                    await c.call("open", site=refused)
                assert info.value.code == "out_of_scope", refused
            assert (await c.call("open", site="sitex:work"))["site"] == "sitex:work"

    run(scenario())


def test_a_bare_name_that_means_one_of_several_accounts_is_refused_without_listing_them(
    roots: sites.Roots,
) -> None:
    add_site(roots, "sitex")
    add_account(roots, "sitex:work")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("scope", sites=["sitex:work"])
            with pytest.raises(DaemonError) as info:
                await c.call("open", site="sitex")
            assert info.value.code == "out_of_scope"
            assert "sitex:main" not in info.value.message

    run(scenario())


def test_a_site_argument_that_is_not_a_site_name_is_left_to_the_operation_to_refuse(
    roots: sites.Roots,
) -> None:
    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("scope", sites=["sitex"])
            for bad in (5, "Bad Name", None):
                with pytest.raises(DaemonError) as info:
                    await c.call("open", site=bad)
                assert info.value.code == "bad_request", bad

    run(scenario())


def test_a_login_for_a_bare_name_that_means_several_accounts_is_refused_to_a_narrow_scope(
    roots: sites.Roots,
) -> None:
    add_account(roots, "sitex")
    add_account(roots, "sitex:work")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("scope", sites=["sitex:work"])
            with pytest.raises(DaemonError) as info:
                await c.call("login", target="sitex")
            assert info.value.code == "out_of_scope"

    run(scenario())


def test_a_bare_name_that_means_the_only_account_is_judged_by_that_account(
    roots: sites.Roots,
) -> None:
    add_account(roots, "sitex:work")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("scope", sites=["sitex:work"])
            assert (await c.call("open", site="sitex"))["site"] == "sitex:work"
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("scope", sites=["other"])
            with pytest.raises(DaemonError) as info:
                await c.call("open", site="sitex")
            assert info.value.code == "out_of_scope"

    run(scenario())


def test_a_site_in_scope_that_does_not_exist_does_not_list_the_others(
    roots: sites.Roots,
) -> None:
    add_site(roots, "another")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("scope", sites=["ghost"])
            with pytest.raises(DaemonError) as info:
                await c.call("open", site="ghost")
            assert info.value.code == "unknown_site"
            assert "another" not in info.value.message
            assert "ghost" in info.value.message

    run(scenario())


def test_a_login_cannot_make_or_reach_a_site_or_account_out_of_scope(roots: sites.Roots) -> None:
    add_site(roots, "sitex")
    add_site(roots, "another")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("scope", sites=["sitex:work"])
            attempts: list[tuple[str, str | None]] = [
                ("another", None),  # a site that exists, out of scope
                ("https://brand-new.test/", None),  # a site it would make
                ("sitex", "home"),  # another account of the site in scope
                ("sitex", None),  # the account-less one
                ("ghost", None),  # a name that does not exist
                ("another", "work"),
            ]
            for target, account in attempts:
                with pytest.raises(DaemonError) as info:
                    await c.call(
                        "login", target=target, **({"account": account} if account else {})
                    )
                assert info.value.code == "out_of_scope", (target, account)
            assert (await c.call("status"))["logins"] == []
            assert sites.known_sites(roots) == ["another", "sitex"]  # nothing was made
            # The account in scope can be added.
            opened = await c.call("login", target="sitex", account="work")
            assert opened["site"] == "sitex:work"

    run(scenario())


def test_a_login_for_a_whole_site_may_add_an_account_and_reach_its_host(
    roots: sites.Roots,
) -> None:
    add_site(roots, "sitex")
    add_site(roots, "another")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("scope", sites=["sitex"])
            assert (await c.call("login", target="sitex", account="work"))["site"] == "sitex:work"
            await c.call("close", site="sitex:work")
            assert (await c.call("login", target="sitex.test"))["site"] == "sitex"
            with pytest.raises(DaemonError) as info:
                await c.call("login", target="another.test")
            assert info.value.code == "out_of_scope"

    run(scenario())


def test_a_login_that_names_the_account_twice_or_is_unreadable_is_still_refused_as_before(
    roots: sites.Roots,
) -> None:
    add_site(roots, "sitex")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c:
            await c.call("scope", sites=["sitex"])
            for target, account in (
                ("sitex:work", "home"),
                ("ftp://x.test", None),
                ("sitex", "1x"),
            ):
                with pytest.raises(DaemonError) as info:
                    await c.call(
                        "login", target=target, **({"account": account} if account else {})
                    )
                assert info.value.code == "bad_request", (target, account)

    run(scenario())


def test_status_shows_only_the_sites_in_scope(roots: sites.Roots) -> None:
    add_site(roots, "sitex")
    add_site(roots, "another")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c, await rig.connect() as free:
            await free.call("open", site="another")
            await c.call("scope", sites=["sitex"])
            assert (await c.call("status"))["sessions"] == []
            assert [s["site"] for s in (await free.call("status"))["sessions"]] == ["another"]
            await c.call("open", site="sitex")
            assert [s["site"] for s in (await c.call("status"))["sessions"]] == ["sitex"]
            assert (await c.call("status", site="sitex"))["state"] == "session"

    run(scenario())


def test_watch_sends_a_scoped_connection_only_its_sites(roots: sites.Roots) -> None:
    add_site(roots, "sitex")
    add_site(roots, "another")

    async def scenario() -> None:
        async with serving(roots) as rig, await rig.connect() as c, await rig.connect() as w:
            await c.call("open", site="another")
            await w.call("scope", sites=["sitex"])
            stream = w.watch()
            snapshot = await next_event(stream)
            assert snapshot["sessions"] == []
            assert snapshot["bridges"] == []
            await c.call("close", site="another")
            await c.call("open", site="sitex")
            assert await next_event(stream) == {
                "event": "session_started",
                "site": "sitex",
                "microphone": False,
                "source": None,
                "at": snapshot["at"],
            }
            await stream.aclose()

    run(scenario())


# -- the MCP server -------------------------------------------------------------------------


def test_the_bridge_declares_its_scope_before_any_request_and_again_after_a_reconnect(
    short_dir: Path,
) -> None:
    async def scenario() -> None:
        fake = FakeDaemon(short_dir / "d.sock")
        fake.handlers["scope"] = lambda args: {"allowed": ", ".join(args["sites"])}
        fake.handlers["sites"] = lambda _args: {"sites": []}
        async with fake.serving():
            bridge = Bridge(fake.path, scope=["sitex", "another:work"])
            try:
                assert await bridge.call("sites") == {"sites": []}
                assert [r["op"] for r in fake.requests] == ["scope", "sites"]
                assert fake.requests[0]["args"] == {"sites": ["sitex", "another:work"]}
                fake.drop_next = True
                with pytest.raises(DaemonError):
                    await bridge.call("sites")
                await bridge.call("sites")
                assert [r["op"] for r in fake.requests] == [
                    "scope", "sites", "sites", "scope", "sites",
                ]  # fmt: skip
            finally:
                await bridge.close()

    run(scenario())


def test_a_bridge_with_no_scope_declares_nothing(short_dir: Path) -> None:
    async def scenario() -> None:
        fake = FakeDaemon(short_dir / "d.sock")
        fake.handlers["sites"] = lambda _args: {"sites": []}
        async with fake.serving():
            bridge = Bridge(fake.path)
            try:
                await bridge.call("sites")
                assert [r["op"] for r in fake.requests] == ["sites"]
            finally:
                await bridge.close()

    run(scenario())


def test_a_daemon_that_cannot_take_a_scope_makes_the_bridge_fail_not_serve_every_site(
    short_dir: Path,
) -> None:
    async def scenario() -> None:
        fake = FakeDaemon(short_dir / "d.sock")

        def old(_args: dict[str, Any]) -> dict[str, Any]:
            fail("unknown_op", "no such operation: scope")

        def broken(_args: dict[str, Any]) -> dict[str, Any]:
            fail("bad_request", "give at least one site")

        async with fake.serving():
            for handler, code in ((old, "daemon_too_old"), (broken, "bad_request")):
                fake.handlers["scope"] = handler
                bridge = Bridge(fake.path, scope=["sitex"])
                with pytest.raises(DaemonError) as info:
                    await bridge.call("sites")
                assert info.value.code == code
                assert not [r for r in fake.requests if r["op"] == "sites"]
                await bridge.close()

    run(scenario())


def test_serve_passes_the_scope_to_the_bridge(monkeypatch: pytest.MonkeyPatch) -> None:
    built: list[Bridge] = []

    class Stub:
        def run(self, transport: str) -> None:
            assert transport == "stdio"

    def build(bridge: Bridge) -> Stub:
        built.append(bridge)
        return Stub()

    monkeypatch.setattr(mcp_server, "build_server", build)
    mcp_server.serve(scope=["sitex"])
    assert built[0]._scope == ["sitex"]  # noqa: SLF001
    mcp_server.serve()
    assert built[1]._scope is None  # noqa: SLF001


def test_the_command_reads_site_options(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    served: list[Any] = []
    monkeypatch.setattr(mcp_server, "serve", lambda scope=None: served.append(scope))
    assert main(["mcp", "--site", "sitex", "--site", "another:work"]) == 0
    assert served == [["sitex", "another:work"]]
    assert main(["mcp", "--site", "Bad Name"]) == 1
    assert "valetkey:" in capsys.readouterr().err
    assert served == [["sitex", "another:work"]]  # nothing was served


def test_a_scoped_mcp_server_shows_one_site_and_names_the_allowed_ones_to_the_agent(
    roots: sites.Roots,
) -> None:
    add_site(roots, "sitex")
    add_site(roots, "another")

    async def scenario() -> None:
        async with serving(roots) as rig:
            bridge = Bridge(rig.path, scope=["sitex"])
            try:
                async with McpClient(build_server(bridge)) as mcp:
                    listing = text_of(await mcp.call_tool("browser_sites", {}))
                    assert "sitex" in listing
                    assert "another" not in listing
                    refused = await mcp.call_tool("browser_open", {"site": "another"})
                    assert refused.is_error
                    assert (
                        'out_of_scope: site "another" is outside this server\'s scope '
                        "(allowed: sitex)"
                    ) in text_of(refused)
                    login = await mcp.call_tool("browser_login", {"site_or_url": "brand-new.test"})
                    assert login.is_error
                    assert "out_of_scope" in text_of(login)
                    opened = await mcp.call_tool("browser_open", {"site": "sitex"})
                    assert not opened.is_error
            finally:
                await bridge.close()

    run(scenario())
