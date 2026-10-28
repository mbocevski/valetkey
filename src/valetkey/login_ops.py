# SPDX-License-Identifier: Apache-2.0
"""Logins and bridges: the login window, what it learns, and the laptops that can show one.

A login opens a window the person signs in at, and when it closes the hosts it reached are
classified and merged into the site's policy (:meth:`Logins._finisher`). A site with a running
session has it ended first. A bridge is a laptop's waypipe connection, registered by the client
that keeps it open, and a login with no screen here may use the newest one.
"""

import asyncio
import contextlib
import functools
import logging
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from valetkey import approvals, cookies, display, learn, login, sites
from valetkey.protocol import fail, map_error, string_arg
from valetkey.proxy import address_refusal, private_address_allowed, system_resolver

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping, Sequence
    from datetime import datetime
    from pathlib import Path

    from valetkey.client import DaemonError
    from valetkey.protocol import LoginWindow
    from valetkey.registry import Connection, Registry, Site
    from valetkey.scope import Scope
    from valetkey.session_ops import Sessions

logger = logging.getLogger("valetkey.daemon")  # the daemon's one log

type LoginStarter = Callable[..., Awaitable[LoginWindow]]
type DisplayStarter = Callable[..., Awaitable[display.Display]]


_BRIDGE_RAND = re.compile(r"[A-Za-z0-9]{8,64}")


RESOLVE_SECONDS = 10.0
"""The longest to wait for the start host of a login to resolve."""


_MAX_NAMED_HOSTS = 5


@dataclass(frozen=True, slots=True)
class _RegisteredBridge:
    """A laptop's waypipe bridge, reachable on a socket in the runtime directory."""

    name: str
    path: Path
    since: datetime


def _private_note(summary: str | None, site: str, hosts: tuple[str, ...]) -> str:
    """Add to a login's summary the hosts refused for their private address, and what to do."""
    shown = ", ".join(hosts[:_MAX_NAMED_HOSTS])
    more = len(hosts) - _MAX_NAMED_HOSTS
    named = f"{shown} and {more} more" if more > 0 else shown
    note = (
        f"Refused because they are on a private network: {named}. Only the person can allow "
        f"that, with `valetkey allow {site} --private-network RANGE` (the narrowest range that "
        "holds the address); then log in again."
    )
    return f"{summary} {note}" if summary else note


def _closed_for_login(error: Exception) -> DaemonError:
    """Return ``error`` as the daemon would answer it, saying the running session was closed."""
    mapped = map_error(error)
    mapped.details = mapped.details | {"closed_session": True}
    return mapped


def _is_site_name(name: str) -> bool:
    try:
        sites.validate_site_name(name)
    except ValueError:
        return False
    return True


class Logins:
    """The ``login`` and ``bridge_register`` operations, and the login windows they open.

    ``login_starter`` is :func:`valetkey.login.start_login`, ``display_starter`` makes the private
    display of a login shown in a web browser (:func:`valetkey.display.start_display`),
    ``proxy_options`` are extra keyword arguments for the login's proxy, and ``screen_finder``
    looks for the person's screen, to know whether a login window could open before a running
    session is closed for it.
    """

    def __init__(  # noqa: PLR0913 - each is a seam the tests replace
        self,
        registry: Registry,
        sessions: Sessions,
        *,
        login_starter: LoginStarter,
        display_starter: DisplayStarter,
        proxy_options: Mapping[str, Any],
        screen_finder: Callable[[], Path],
        now: Callable[[], datetime],
    ) -> None:
        """Create the operations for the sites of ``registry``."""
        self.registry = registry
        self.sessions = sessions
        self.roots = registry.roots
        self._login_starter = login_starter
        self._display_starter = display_starter
        self._proxy_options = proxy_options
        self._screen_finder = screen_finder
        self._now = now
        self._uid = os.getuid()
        self.bridges: dict[str, _RegisteredBridge] = {}

    async def op_bridge_register(
        self, connection: Connection, args: dict[str, Any]
    ) -> dict[str, Any]:
        """Record a bridge and tie it to this connection, which the caller then keeps open.

        ``rand`` names the bridge ``bridge-<rand>`` and its socket
        ``<runtime>/valetkey/bridge-<rand>.sock``. The daemon builds the path itself, and the
        socket must already be there: a real socket the user owns. Registering a name this
        connection already holds changes nothing, so the caller can repeat it. Another
        connection's name is refused. The bridge is forgotten when the connection closes.
        """
        rand = string_arg(args, "rand")
        if not _BRIDGE_RAND.fullmatch(rand):
            fail("bad_request", "rand must be 8 to 64 letters and digits")
        name = f"bridge-{rand}"
        if name in connection.bridges:
            return {"bridge": name, "registered": False}
        if name in self.bridges:
            fail("bridge_exists", f"{name} is already registered")
        path = sites.runtime_path(self.roots) / f"{name}.sock"
        try:
            found = await asyncio.to_thread(path.lstat)
        except OSError:
            found = None
        if found is None or not stat.S_ISSOCK(found.st_mode) or found.st_uid != self._uid:
            fail("no_socket", f"{path} is not a socket of this user; is the ssh forward up?")
        self.bridges[name] = _RegisteredBridge(name, path, self._now())
        connection.bridges.add(name)
        self.registry.emit("bridge_connected", bridge=name)
        return {"bridge": name, "registered": True}

    def unregister_bridge(self, name: str) -> None:
        """Forget the bridge ``name`` and tell the ``watch`` clients, when its client leaves."""
        del self.bridges[name]
        self.registry.emit("bridge_disconnected", bridge=name)

    def bridge_sockets(self) -> list[Path]:
        """Return the sockets of the registered bridges, the newest last."""
        return [bridge.path for bridge in self.bridges.values()]

    async def op_login(self, connection: Connection, args: dict[str, Any]) -> dict[str, Any]:
        """Answer ``login``: open a login window for the site, and return at once."""
        target = string_arg(args, "target")
        account = args.get("account")
        if account is not None and not isinstance(account, str):
            fail("bad_request", '"account" must be a string')
        await asyncio.to_thread(sites.system_suffixes)  # no list, no login: see SuffixListError
        await self._check_login_scope(connection.scope, target, account)
        site, start = await self._login_target(target, account)
        existing = await self._existing_policy(site)
        await self._refuse_private_start(site, start, existing)
        state = self.registry.state(site)
        async with state.lock:
            closed = state.kind == "session"
            if closed:
                # A login is usually wanted because the saved one expired, with the session
                # still open. Close it the way ``close`` does, but only if a window can open:
                # with no screen to use, the session is left running.
                await self._require_screen()
                await self.sessions.end(state)
            if state.kind == "login":
                fail("login_in_progress", f"a login window for {site} is already open")
            state.kind = "login"
            state.start = start
            state.began = self._now()
            try:
                state.window, state.shown = await self._open_window(
                    state, site, start, existing.private_networks if existing else ()
                )
            except Exception as error:
                state.kind = "idle"
                if closed:
                    raise _closed_for_login(error) from error
                raise
            except BaseException:
                state.kind = "idle"
                raise
            state.since = self._now()
            state.watcher = asyncio.ensure_future(self._watch_login(state, state.window))
            self.registry.emit("login_opened", site)
        result: dict[str, Any] = {"site": self.registry.shown(site), "window": "open"}
        if closed:
            result["closed_session"] = True
        if state.route == "bridge":
            result["route"] = "bridge"
        if state.shown is not None:
            result["remote"] = display.describe(state.shown)
        return result

    async def _require_screen(self) -> None:
        """Raise the login's own refusal unless some route to a login window is there.

        The routes are the person's screen, a connected bridge when the config allows one, and a
        web browser when the config allows that (see :meth:`_open_window`).

        Raises:
            login.DisplayError: when there is none, as opening the window would.

        """
        try:
            await asyncio.to_thread(self._screen_finder)
        except login.DisplayError:
            if await self._bridge_for_login() is None and not await self._novnc_enabled():
                raise

    async def _open_window(
        self, state: Site, site: str, start: str, networks: Sequence[str]
    ) -> tuple[LoginWindow, display.Display | None]:
        """Open the login window on the person's screen, or else somewhere they can reach.

        The order is this machine's own screen, then the laptop at the other end of a connected
        bridge (the ``remote_logins.waypipe`` switch in the config), then a private display that
        a web browser can view (the noVNC switch, see :mod:`valetkey.display`). With none of
        them the login's own refusal is raised. A display is returned with the window, and it
        ends with it; ``state.route`` says which of the three was used.
        """
        options: dict[str, Any] = {
            "proxy_options": self._proxy_options,
            "private_networks": networks,
        }
        finisher = self._finisher(state, start)
        state.route = "local"
        try:
            return await self._login_starter(site, start, self.roots, finisher, **options), None
        except login.DisplayError:
            bridge = await self._bridge_for_login()
            if bridge is not None:
                window = await self._login_starter(
                    site, start, self.roots, finisher, bridge=bridge, **options
                )
                state.route = "bridge"
                return window, None
            if not await self._novnc_enabled():
                raise
        shown = await self._display_starter(self.roots, site)
        try:
            window = await self._login_starter(
                site, start, self.roots, finisher, wayland_socket=shown.wayland_socket, **options
            )
        except BaseException:
            await shown.close()
            raise
        state.route = "novnc"
        return window, shown

    async def _bridge_for_login(self) -> Path | None:
        """Return the socket of the newest connected bridge, if the config allows using one."""
        try:
            enabled = (await asyncio.to_thread(approvals.load_config, self.roots)).waypipe
        except approvals.ConfigError:
            logger.warning("the config is not usable, so a login is not offered on a laptop")
            return None
        sockets = self.bridge_sockets() if enabled else []
        return sockets[-1] if sockets else None

    async def _novnc_enabled(self) -> bool:
        """Tell whether the config lets a login with no screen be shown in a web browser."""
        try:
            return (await asyncio.to_thread(approvals.load_config, self.roots)).novnc
        except approvals.ConfigError:
            logger.warning("the config is not usable, so a login is not offered in a browser")
            return False

    async def _existing_policy(self, site: str) -> sites.Policy | None:
        """Return ``site``'s policy, or ``None`` when it has none yet."""
        try:
            return await asyncio.to_thread(sites.load_policy, self.roots, site)
        except FileNotFoundError:
            return None

    async def _refuse_private_start(
        self, site: str, start: str, existing: sites.Policy | None
    ) -> None:
        """Fail early when ``start`` resolves to a private address the site may not reach.

        The login proxy would refuse it anyway, and the person would be left with a window that
        shows an error. Only the person can list a range, so the error says which command to
        run. A name that does not resolve is left to the browser to report.
        """
        host = sites.host_of(start)
        resolver = self._proxy_options.get("resolver", system_resolver)
        check = self._proxy_options.get("address_check", address_refusal)
        try:
            async with asyncio.timeout(RESOLVE_SECONDS):
                addresses = await resolver(host, 443)
        except OSError, TimeoutError:
            return
        networks = existing.private_networks if existing else ()
        if not any(
            check(address) is not None and not private_address_allowed(address, networks)
            for address in addresses
        ):
            return
        command = (
            f"valetkey allow {site} --private-network RANGE"
            if existing
            else f"valetkey add {site} {start} --private-network RANGE"
        )
        fail(
            "private_address",
            f"{host} resolves to a private address that {site} may not reach. Only the person "
            f"can allow that, for this site only: ask them to run `{command}`, with the "
            "narrowest range that holds its address (one address such as 10.20.0.7/32, or a /24), "
            "and then log in again.",
        )

    async def _check_login_scope(
        self, scope: Scope | None, target: str, account: str | None
    ) -> None:
        """Refuse a login whose account is outside ``scope`` (``None`` has no limit).

        Nothing is read or made before it.

        The account is worked out the way :meth:`_login_target` does, without reading a policy,
        so a refusal says nothing about sites the scope does not cover. A name or a host that
        cannot be read is left to :meth:`_login_target`, which refuses it.
        """
        if scope is None:
            return
        try:
            if "." not in target and self._names_a_site(target):
                site, current = sites.split_site_name(target)
                name = target if account is None or current is not None else None
                if name is None:
                    name = sites.account_name(site, account)
            else:
                base = await asyncio.to_thread(
                    sites.choose_site_name, self.roots, login.normalize_start_url(target)
                )
                name = base if account is None else sites.account_name(base, account)
            resolved = sites.resolve_account(self.roots, name)
        except sites.AmbiguousAccountError:
            raise scope.refusal(target) from None
        except ValueError:
            return
        if not scope.covers(resolved):
            raise scope.refusal(target)

    async def _login_target(self, target: str, account: str | None) -> tuple[str, str]:
        """Return the account name and start URL for a known site name, a host or a URL.

        ``account`` names another account of the site (``sitex`` and ``work`` give ``sitex:work``).
        Without it, a site with one account is that account, and a site with several must be
        named in full. A new account starts at the start URL of one the site already has.
        """
        if "." not in target and self._names_a_site(target):
            return await self._login_known(target, account)
        start = login.normalize_start_url(target)
        base = await asyncio.to_thread(sites.choose_site_name, self.roots, start)
        if account is None:
            return sites.resolve_account(self.roots, base), start
        return sites.account_name(base, account), start

    @staticmethod
    def _names_a_site(target: str) -> bool:
        """Say whether ``target`` is a site, not a host with a port such as ``intranet:8080``."""
        site, _, account = target.partition(sites.ACCOUNT_SEPARATOR)
        if account == sites.FIRST_ACCOUNT:
            return _is_site_name(site)
        return _is_site_name(target)

    async def _login_known(self, target: str, account: str | None) -> tuple[str, str]:
        if account is None:
            name = sites.resolve_account(self.roots, target)
            return name, (await self.registry.load_policy(name)).start
        site, current = sites.split_site_name(target)
        if current is not None:
            fail("bad_request", f"name the account once: {target!r} already has one")
        try:
            name = sites.account_name(site, account)
        except ValueError as error:
            fail("bad_request", str(error))
        try:
            return name, (await asyncio.to_thread(sites.load_policy, self.roots, name)).start
        except FileNotFoundError:
            pass
        accounts = [n for n in sites.known_sites(self.roots) if sites.split_site_name(n)[0] == site]
        if not accounts:
            await self.registry.load_policy(target)  # says that the site is not known
        return name, (await self.registry.load_policy(accounts[0])).start

    def _finisher(self, state: Site, start: str) -> Callable[[list[Any], Path], Awaitable[None]]:
        async def finish(seen: list[Any], profile: Path) -> None:
            try:
                if state.began is None:
                    message = "the time the login began was not recorded"
                    raise RuntimeError(message)  # noqa: TRY301 - handled below, as any failure is
                history = profile / "Default" / "History"
                navigated = await asyncio.to_thread(
                    functools.partial(learn.navigation, history, since=state.began)
                )
                classification = learn.classify(
                    start, [h.host for h in seen], navigated.shown, navigated.passed
                )
                pages: tuple[str, ...] = ()
                with contextlib.suppress(sqlite3.DatabaseError):  # the extra is optional
                    pages = await asyncio.to_thread(
                        functools.partial(learn.login_pages, history, start, since=state.began)
                    )
                try:
                    existing: sites.Policy | None = await asyncio.to_thread(
                        sites.load_policy, self.roots, state.name
                    )
                except FileNotFoundError:
                    existing = None
                own = [sites.registrable_domain(sites.host_of(start)), *classification.owned]
                signed_in = await asyncio.to_thread(
                    functools.partial(
                        cookies.recorded,
                        profile,
                        history,
                        since=state.began,
                        now=self._now(),
                        own=lambda host: sites.host_matches(host, own),
                    )
                )
                policy = learn.merge(
                    existing,
                    classification,
                    start,
                    self._now(),
                    site=state.name,
                    pages=pages,
                    login_cookies=signed_in,
                )
                await asyncio.to_thread(sites.save_policy, self.roots, policy)
            except learn.HistoryError as error:
                # The message is a fixed phrase. What the history said is in the log, never here:
                # the login browser wrote it, so it may be text meant for the agent.
                logger.warning("could not save the login for %s: %s", state.name, error)
                state.summary = f"The {state.name} login could not be saved: {error}."
                return
            except Exception:
                logger.exception("could not save the login for %s", state.name)
                state.summary = (
                    f"The {state.name} login could not be saved. The daemon's log says why."
                )
                return
            state.summary = learn.summary(policy, classification)

        return finish

    async def _watch_login(self, state: Site, window: LoginWindow) -> None:
        try:
            result = await window.wait()
            if result.private_refused:
                state.summary = _private_note(state.summary, state.name, result.private_refused)
        except Exception:
            logger.exception("login for %s failed", state.name)
        finally:
            shown, state.shown = state.shown, None
            if shown is not None:
                await shown.close()
            state.window = None
            state.kind = "idle"
            self.registry.emit("login_closed", state.name)
