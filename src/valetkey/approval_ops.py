# SPDX-License-Identifier: Apache-2.0
"""The operations that widen or narrow a site's key: asking the person to allow or deny a host.

These are the only operations that add a host to a policy or deny one (a finished login, run by
the person at a window, is the other way to add one). See :mod:`valetkey.approvals` for the trust
boundary: the daemon grants or denies a host only on a yes that came from the person, through the
MCP client's own interface or through the approval command or a desktop notification.
"""

import asyncio
import logging
import os
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from valetkey import approvals, notify, sites
from valetkey.protocol import fail
from valetkey.registry import remember_refusals

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping

    from valetkey.registry import Connection, Registry

logger = logging.getLogger("valetkey.daemon")  # the daemon's one log

type Notifier = Callable[..., Awaitable[str]]


_ASK_OUTCOMES = {
    "no": ("denied", "The person said no."),
    "timeout": ("expired", "Nobody answered in time. You may ask again."),
    "none": ("could_not_ask", "Nobody could be asked from here. Run: {manual}"),
    "broken": ("could_not_ask", "The approval command could not run. Run: {manual}"),
}
"""How each way the approval command can end, other than yes, is reported."""


_DENY_OUTCOMES = {
    "no": ("declined", "The person said no. Do not ask again for this host."),
    "timeout": ("expired", "Nobody answered in time. You may ask again."),
    "none": ("could_not_ask", "Nobody could be asked from here. Run: {manual}"),
    "broken": ("could_not_ask", "The approval command could not run. Run: {manual}"),
}
"""How each way the question to deny a host can end, other than yes, is reported."""


_MICROPHONE_OUTCOMES = {
    "no": ("denied", "The person said no."),
    "timeout": ("expired", "Nobody answered in time. You may ask again."),
    "none": ("could_not_ask", "Nobody could be asked from here. Run: {manual}"),
    "broken": ("could_not_ask", "The approval command could not run. Run: {manual}"),
}
"""How each way the question to turn on the microphone can end, other than yes, is reported."""


def _answer(site: str, host: str, result: str, message: str) -> dict[str, Any]:
    return {"site": site, "host": host, "result": result, "message": message}


def _allow_answer(site: str, host: str, found: approvals.Eligibility) -> dict[str, Any]:
    """Answer for a host that is not to be asked about: allowed already, or not eligible."""
    result = "allowed" if found.status == "already_allowed" else "not_eligible"
    return _answer(site, host, result, found.message)


def _deny_answer(site: str, host: str, found: approvals.Eligibility) -> dict[str, Any]:
    """Answer for a host that is not to be asked about: denied already, or not eligible."""
    result = "denied" if found.status == "already_denied" else "not_eligible"
    return _answer(site, host, result, found.message)


class Approvals:
    """The allow and deny operations, with the questions they put to the person.

    ``approve_timeout`` is how long the person gets to answer, ``user_environment`` reads the
    environment a question needs to reach the person's screen, and ``notifier`` (default
    :func:`valetkey.notify.ask`) puts a question in a desktop notification.
    """

    def __init__(
        self,
        registry: Registry,
        *,
        approve_timeout: float,
        user_environment: Callable[[], Mapping[str, str]],
        notifier: Notifier | None,
    ) -> None:
        """Create the operations for the sites of ``registry``."""
        self.registry = registry
        self.roots = registry.roots
        self._approve_timeout = approve_timeout
        self._user_environment = user_environment
        self._notifier = notifier

    async def _eligibility(
        self, site: str, host: object
    ) -> tuple[sites.Policy, str, approvals.Eligibility]:
        try:
            name = approvals.validate_host(host)
        except ValueError as error:
            fail("bad_request", str(error))
        policy = await self.registry.load_policy(site)
        state = self.registry.state(site)
        if state.proxy is not None:
            remember_refusals(state, state.proxy)
        return (
            policy,
            name,
            approvals.eligibility(policy, name, state.refused_hosts, state.address_hosts),
        )

    async def op_allow_check(self, _connection: Connection, args: dict[str, Any]) -> dict[str, Any]:
        """Say whether ``host`` may be asked about for a site, and whether the daemon can ask."""
        site = self.registry.site_of(args)
        _policy, host, found = await self._eligibility(site, args.get("host"))
        state = self.registry.state(site)
        return {
            "site": site,
            "host": host,
            "status": found.status,
            "message": found.message,
            "seen_during_login": found.seen_during_login,
            "denied": host in state.denied_hosts,
            "can_ask": await self._approve_command() is not None,
        }

    async def _approve_command(self) -> tuple[str, ...] | None:
        """Return the configured approval command; an unusable config counts as none."""
        try:
            return (await asyncio.to_thread(approvals.load_config, self.roots)).approve_command
        except approvals.ConfigError:
            logger.exception("config.json cannot be used")
            return None

    async def op_allow_apply(self, _connection: Connection, args: dict[str, Any]) -> dict[str, Any]:
        """Grant ``host`` because the MCP client's interface returned a yes.

        The daemon takes the word of the MCP server process for it (see :mod:`approvals`). The
        host must still be eligible: refused, or excluded.
        """
        site = self.registry.site_of(args)
        if args.get("channel") != "elicitation":
            fail("bad_request", 'this operation is for the "elicitation" channel')
        policy, host, found = await self._eligibility(site, args.get("host"))
        if found.status != "eligible":
            return _allow_answer(site, host, found)
        return await self._grant(site, host, policy)

    async def op_allow_ask(self, _connection: Connection, args: dict[str, Any]) -> dict[str, Any]:
        """Ask through the approval command, and grant if it exits with status 0."""
        site = self.registry.site_of(args)
        reason = approvals.sanitize_reason(args.get("reason"))
        state = self.registry.state(site)
        async with state.ask_lock:
            policy, host, found = await self._eligibility(site, args.get("host"))
            if found.status != "eligible":
                return _allow_answer(site, host, found)
            if host in state.denied_hosts:
                return _answer(site, host, "denied", "The person already said no.")
            outcome = await self._consult(site, host, found.seen_during_login, reason)
            if outcome == "yes":
                return await self._grant(site, host, policy)
            if outcome == "no":
                state.denied_hosts.add(host)
            result, message = _ASK_OUTCOMES[outcome]
            return _answer(
                site, host, result, message.format(manual=approvals.manual_command(site, host))
            )

    async def _consult(
        self,
        site: str,
        host: str,
        seen: bool,  # noqa: FBT001
        reason: str,
        *,
        deny: bool = False,
    ) -> str:
        """Run the approval command and return ``yes``, ``no``, ``timeout``, ``none`` or ``broken``.

        ``none`` means nobody could be asked: no command is configured (or its config is unusable)
        and no notification can ask either, ``broken`` that the command could not be started. A
        command that exits with :data:`approvals.EXIT_COULD_NOT_ASK` could not ask, so the
        notification asks instead, and one that exits with :data:`approvals.EXIT_NOBODY_ANSWERED`
        is a ``timeout``. With ``deny`` the question is whether to deny a host the site may
        reach: the request then has ``"action": "deny"`` and ``seen_during_login`` says the host
        was left out at login, and yes (exit status 0) denies it.
        """
        command = await self._approve_command()
        env = await asyncio.to_thread(
            approvals.command_environment, os.environ, self._user_environment
        )
        question = notify.Question(site, host, seen=seen, reason=reason, deny=deny)
        if command is None:
            return await self._notify(question, env)
        request: dict[str, Any] = {
            "site": site,
            "permission": "host",
            "host": host,
            "seen_during_login": seen,
            "reason": reason,
        }
        if deny:
            request["action"] = "deny"
        return await self._run_approver(command, request, env, question)

    async def _consult_microphone(self, site: str, reason: str) -> str:
        """Ask whether to turn the microphone on; the outcomes are those of :meth:`_consult`.

        The request has ``"permission": "microphone"`` and no ``host``.
        """
        command = await self._approve_command()
        env = await asyncio.to_thread(
            approvals.command_environment, os.environ, self._user_environment
        )
        question = notify.Question(site, "", seen=False, reason=reason, microphone=True)
        if command is None:
            return await self._notify(question, env)
        request = {"site": site, "permission": "microphone", "reason": reason}
        return await self._run_approver(command, request, env, question)

    async def _run_approver(
        self,
        command: tuple[str, ...],
        request: dict[str, Any],
        env: Mapping[str, str],
        question: notify.Question,
    ) -> str:
        """Run the approval command; one that could not ask hands the question to a notification."""
        try:
            answer = await approvals.run_command(command, request, env, self._approve_timeout)
        except OSError as error:
            logger.warning("the approval command could not run: %s", error)
            return "broken"
        if answer == "unavailable":
            logger.info("the approval command could not ask, so a notification asks")
            return await self._notify(question, env)
        return answer

    async def _notify(self, question: notify.Question, env: Mapping[str, str]) -> str:
        """Ask with a desktop notification when nothing else can; ``none`` if that is not on.

        A person can switch it off with ``"notifications": false`` in the config file. A config
        that cannot be read leaves it on, since that is the default.
        """
        try:
            wanted = (await asyncio.to_thread(approvals.load_config, self.roots)).notifications
        except approvals.ConfigError:
            wanted = True
        if not wanted:
            return "none"
        ask = self._notifier or notify.ask
        return await ask(question, env, self._approve_timeout)

    async def op_microphone_check(
        self, _connection: Connection, args: dict[str, Any]
    ) -> dict[str, Any]:
        """Say whether the microphone is on for a site already, and whether the daemon can ask."""
        site = self.registry.site_of(args)
        policy = await self.registry.load_policy(site)
        return {
            "site": site,
            "enabled": policy.microphone,
            "can_ask": await self._approve_command() is not None,
        }

    async def op_microphone_apply(
        self, _connection: Connection, args: dict[str, Any]
    ) -> dict[str, Any]:
        """Turn the microphone on because the MCP client's interface returned a yes."""
        site = self.registry.site_of(args)
        if args.get("channel") != "elicitation":
            fail("bad_request", 'this operation is for the "elicitation" channel')
        return await self._enable_microphone(site)

    async def op_microphone_ask(
        self, _connection: Connection, args: dict[str, Any]
    ) -> dict[str, Any]:
        """Ask through the approval command or a notification, and turn it on if the answer is yes.

        A no is not remembered: the agent may ask again, and the person can say no again.
        """
        site = self.registry.site_of(args)
        reason = approvals.sanitize_reason(args.get("reason"))
        state = self.registry.state(site)
        async with state.ask_lock:
            if (await self.registry.load_policy(site)).microphone:
                return await self._enable_microphone(site)
            outcome = await self._consult_microphone(site, reason)
            if outcome == "yes":
                return await self._enable_microphone(site)
            result, message = _MICROPHONE_OUTCOMES[outcome]
            manual = approvals.manual_microphone_command(site)
            return {"site": site, "result": result, "message": message.format(manual=manual)}

    async def _enable_microphone(self, site: str) -> dict[str, Any]:
        """Turn the microphone on for the site, save the policy, and say when it takes effect."""
        policy = await self.registry.load_policy(site)
        if policy.microphone:
            message = f"The microphone is already on for {site}."
        else:
            await asyncio.to_thread(sites.save_policy, self.roots, replace(policy, microphone=True))
            logger.info("turned on the microphone for %s", site)
            message = f"The microphone is now on for {site}."
        if self.registry.state(site).kind == "session":
            message += " The running session does not have it: close it, then open it again."
        else:
            message += " It applies to sessions from now on."
        return {"site": site, "result": "allowed", "message": message}

    async def _deny_eligibility(
        self, site: str, host: object
    ) -> tuple[sites.Policy, str, approvals.Eligibility]:
        try:
            name = approvals.validate_host(host)
        except ValueError as error:
            fail("bad_request", str(error))
        policy = await self.registry.load_policy(site)
        return policy, name, approvals.deny_eligibility(policy, name)

    async def op_deny_check(self, _connection: Connection, args: dict[str, Any]) -> dict[str, Any]:
        """Say whether ``host`` may be asked about for denying, and whether the daemon can ask."""
        site = self.registry.site_of(args)
        _policy, host, found = await self._deny_eligibility(site, args.get("host"))
        return {
            "site": site,
            "host": host,
            "status": found.status,
            "message": found.message,
            "left_out": found.seen_during_login,
            "kept": host in self.registry.state(site).kept_hosts,
            "can_ask": await self._approve_command() is not None,
        }

    async def op_deny_apply(self, _connection: Connection, args: dict[str, Any]) -> dict[str, Any]:
        """Deny ``host`` because the MCP client's interface returned a yes (see ``allow_apply``)."""
        site = self.registry.site_of(args)
        if args.get("channel") != "elicitation":
            fail("bad_request", 'this operation is for the "elicitation" channel')
        policy, host, found = await self._deny_eligibility(site, args.get("host"))
        if found.status != "eligible":
            return _deny_answer(site, host, found)
        return await self._revoke(site, host, policy)

    async def op_deny_ask(self, _connection: Connection, args: dict[str, Any]) -> dict[str, Any]:
        """Ask through the approval command or a notification, and deny if the answer is yes."""
        site = self.registry.site_of(args)
        reason = approvals.sanitize_reason(args.get("reason"))
        state = self.registry.state(site)
        async with state.ask_lock:
            policy, host, found = await self._deny_eligibility(site, args.get("host"))
            if found.status != "eligible":
                return _deny_answer(site, host, found)
            if host in state.kept_hosts:
                return _answer(site, host, "declined", "The person already said no.")
            outcome = await self._consult(site, host, found.seen_during_login, reason, deny=True)
            if outcome == "yes":
                return await self._revoke(site, host, policy)
            if outcome == "no":
                state.kept_hosts.add(host)
            result, message = _DENY_OUTCOMES[outcome]
            manual = approvals.manual_deny_command(site, host)
            return _answer(site, host, result, message.format(manual=manual))

    async def _revoke(self, site: str, host: str, policy: sites.Policy) -> dict[str, Any]:
        """Deny ``host`` for the site, save the policy and give it to the live proxy."""
        changed = sites.deny_host(policy, host)
        await asyncio.to_thread(sites.save_policy, self.roots, changed)
        state = self.registry.state(site)
        if state.proxy is not None:
            state.proxy.update_policy(changed)
        logger.info("denied %s for %s", host, site)
        message = (
            f"{host} is now denied for {site}. It no longer loads, and later logins will not "
            "allow it again."
        )
        return _answer(site, host, "denied", message)

    async def _grant(self, site: str, host: str, policy: sites.Policy) -> dict[str, Any]:
        """Add ``host`` to the site's policy, save it, and give it to the live proxy."""
        changed, _added, _removed = sites.allow_host(policy, host)
        await asyncio.to_thread(sites.save_policy, self.roots, changed)
        state = self.registry.state(site)
        if state.proxy is not None:
            state.proxy.update_policy(changed)
        logger.info("allowed %s for %s", host, site)
        return _answer(site, host, "allowed", f"{host} is now allowed for {site}.")
