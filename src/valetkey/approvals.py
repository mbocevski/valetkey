# SPDX-License-Identifier: Apache-2.0
"""Asking the person before a site's key is widened.

A session reaches only the hosts its policy allows. When a page needs another host, the agent
may *ask* for it with ``browser_allow``. Nothing here lets the agent grant anything: a host is
added to a policy only after a person said yes, through one of two channels.

* **Elicitation**, in the ``valetkey mcp`` process. The MCP client shows the question in its own
  interface and sends the answer back to that process. If the client declared the capability,
  this is asked first.
* **An approval command** from ``$XDG_CONFIG_HOME/valetkey/config.json``, run by the daemon:
  ``{"approve_command": ["/path/to/program", "arg"]}``. It gets one line of JSON on stdin,
  ``{"site": ..., "host": ..., "seen_during_login": ..., "reason": ...}``, and exit status 0
  means yes. Any other status means no, running too long (60 seconds) counts as unanswered, and
  nothing it prints is ever shown to the model.

If neither can be used, the agent is told to hand the person the exact command to run:
``valetkey allow SITE HOST``.

**Trust boundary.** The daemon cannot see the MCP client's interface, so for the elicitation
channel it has to take the word of the ``valetkey mcp`` process that the person accepted: the
daemon's ``allow_apply`` operation grants on that say-so. That is the same trust the daemon
already gives every process of the same user (it checks the peer's user id on the socket, and
nothing more). The agent has no way to reach that operation: the only tool that calls it does so
after the client's interface returned an acceptance, and no tool takes a "the person said yes"
argument from the model. Processes of the same user, including any shell the agent might have,
can edit the policy files with ``valetkey allow`` anyway; valetkey defends against page content
steering the browser tools, not against the user's own shell.

Only a host that was actually refused can be asked about (see :func:`eligibility`), so a steered
agent cannot flood the person with questions about arbitrary hosts.
"""

import asyncio
import contextlib
import json
import os
import re
import signal
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from valetkey import sites

if TYPE_CHECKING:
    from collections.abc import Callable, Collection, Mapping

    from valetkey.sites import Roots

CONFIG_NAME = "config.json"
COMMAND_TIMEOUT = 60.0
REASON_LENGTH = 240
_CONFIG_KEYS = frozenset({"approve_command"})
_PASSED_ENVIRONMENT = (
    "HOME",
    "XDG_RUNTIME_DIR",
    "WAYLAND_DISPLAY",
    "DISPLAY",
    "DBUS_SESSION_BUS_ADDRESS",
    "LANG",
)
_DISPLAY_ENVIRONMENT = ("WAYLAND_DISPLAY", "DISPLAY", "DBUS_SESSION_BUS_ADDRESS")
_MARKUP = re.compile(r"[`*_\[\]()<>#|~\\{}]")
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")
_NOT_A_HOST = "*/\\@#?:%[]()<>\"' ,;=&"

type Answer = Literal["yes", "no", "timeout"]
type Status = Literal["eligible", "already_allowed", "not_eligible"]


class ConfigError(ValueError):
    """``config.json`` cannot be used."""


def manual_command(site: str, host: str) -> str:
    """Return the command a person can run to allow ``host`` for ``site`` themselves."""
    return f"valetkey allow {site} {host}"


def validate_host(value: object) -> str:
    """Return ``value`` as a host name that may be asked about, or raise ``ValueError``.

    Only a plain host name qualifies: no scheme, path, port, credentials or fragment (so nothing
    can hide a different host in the text), no wildcard, no IP address, no single label like
    ``com`` and no registrable suffix like ``co.uk``. Upper case and a trailing dot are
    normalized away.
    """
    if not isinstance(value, str) or not value:
        message = "give a host name such as cdn.example.com"
        raise ValueError(message)
    if "*" in value:
        message = "wildcards are not allowed; ask for one exact host"
        raise ValueError(message)
    if any(char in _NOT_A_HOST or not char.isprintable() for char in value):
        message = "give only a host name, without a scheme, path, port, credentials or spaces"
        raise ValueError(message)
    host = sites.normalize_host(value)
    if sites.is_ip_literal(host) or not sites.is_plausible_host(host):
        message = "give a host name, not an IP address or anything else"
        raise ValueError(message)
    if "." not in host or host in sites.TWO_LEVEL_SUFFIXES:
        message = "that is a whole domain suffix, not a host; ask for one exact host"
        raise ValueError(message)
    return host


def sanitize_reason(text: object) -> str:
    """Return the agent's ``text`` as a short, plain, single line that is safe to show.

    The text comes from the agent, which a web page may be steering, so it is shown as a claim
    and made inert: only printable ASCII is kept, line breaks and other control characters
    become spaces, anything a chat or form interface could turn into a link, emphasis, code or a
    heading is replaced by a space, and it is cut to :data:`REASON_LENGTH` characters.
    """
    raw = text if isinstance(text, str) else ""
    ascii_only = "".join(c if c.isascii() and c.isprintable() else " " for c in raw)
    plain = _MARKUP.sub(" ", _SCHEME.sub(" ", ascii_only))
    return " ".join(plain.split())[:REASON_LENGTH].rstrip()


def prompt_text(site: str, host: str, seen_during_login: bool, reason: str) -> str:  # noqa: FBT001
    """Return the question shown to the person. ``reason`` must come from :func:`sanitize_reason`.

    The host is in a code span so an interface does not turn it into a link, and the reason is
    labelled as the agent's claim.
    """
    seen = "yes" if seen_during_login else "no"
    claim = f'"{reason}"' if reason else "(nothing)"
    return (
        f"Allow {site} sessions to reach `{host}`?\n"
        f"Seen during login: {seen}\n"
        f"The agent says: {claim}"
    )


# -- eligibility -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Eligibility:
    """Whether a host may be asked about, and why not."""

    status: Status
    message: str
    seen_during_login: bool = False


def eligibility(policy: sites.Policy, host: str, refused: Collection[str]) -> Eligibility:
    """Decide whether ``host`` may be asked about for ``policy``'s site.

    ``refused`` are the hosts the site's proxy refused because the policy did not allow them. A
    host qualifies when it is one of them, or when it is itself an entry of ``excluded`` (seen
    during the login and left out). Anything else is ``not_eligible``, and nobody is asked. A
    host the policy already allows is ``already_allowed``.
    """
    seen = host in policy.excluded
    if sites.allows(policy, host):
        return Eligibility("already_allowed", f"{host} is already allowed.", seen)
    if host in refused or seen:
        return Eligibility("eligible", "", seen)
    return Eligibility(
        "not_eligible",
        f"{host} was not refused for {policy.site} and is not in its excluded list, so it "
        "cannot be asked about. Ask for the exact host a page needed that was refused.",
    )


# -- the approval command --------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Config:
    """What ``config.json`` holds. ``approve_command`` is an argument list, or ``None``."""

    approve_command: tuple[str, ...] | None = None


def load_config(roots: Roots) -> Config:
    """Read ``$XDG_CONFIG_HOME/valetkey/config.json``; a missing file is an empty config.

    Raises:
        ConfigError: when the file is not a JSON object with only known keys, or
            ``approve_command`` is not a non-empty list of non-empty strings.

    """
    path = roots.config / "valetkey" / CONFIG_NAME
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return Config()
    except OSError as error:
        message = f"{path}: {error.strerror or error}"
        raise ConfigError(message) from error
    try:
        data = json.loads(text)
    except ValueError as error:
        message = f"{path}: not valid JSON ({error})"
        raise ConfigError(message) from error
    if not isinstance(data, dict) or not set(data) <= _CONFIG_KEYS:
        message = f"{path}: expected an object with only these keys: {', '.join(_CONFIG_KEYS)}"
        raise ConfigError(message)
    command = data.get("approve_command")
    if command is None:
        return Config()
    if not (
        isinstance(command, list)
        and command
        and all(isinstance(item, str) and item for item in command)
    ):
        message = (
            f"{path}: approve_command must be a list of strings: the program, then its arguments"
        )
        raise ConfigError(message)
    return Config(tuple(command))


def command_environment(
    environ: Mapping[str, str], user_environment: Callable[[], Mapping[str, str]]
) -> dict[str, str]:
    """Return the minimal environment the approval command runs in.

    A fixed ``PATH`` plus the few variables a program needs to show a window: the home and
    runtime directories, the display and the session bus. A display variable the daemon lacks
    (a service often does) is taken from the systemd user manager, as the login window's is.
    """
    env = {"PATH": "/usr/bin:/bin"}
    env.update({name: environ[name] for name in _PASSED_ENVIRONMENT if environ.get(name)})
    if any(name not in env for name in _DISPLAY_ENVIRONMENT):
        manager = user_environment()
        env.update({n: manager[n] for n in _DISPLAY_ENVIRONMENT if n not in env and manager.get(n)})
    return env


async def run_command(
    argv: tuple[str, ...], request: dict[str, Any], env: Mapping[str, str], limit: float
) -> Answer:
    """Run the approval command with ``request`` as JSON on stdin and return its answer.

    No shell is involved: ``argv`` is run as given, in a process group of its own, with its
    output thrown away. ``yes`` is exit status 0, ``no`` is any other status or a death by
    signal, and ``timeout`` is not having exited within ``limit`` seconds, in which case the
    whole process group is killed.

    Raises:
        `OSError`: when the program cannot be started.

    """
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
        env=dict(env),
        start_new_session=True,
    )
    try:
        async with asyncio.timeout(limit):
            await _feed(process, json.dumps(request).encode() + b"\n")
            return "yes" if await process.wait() == 0 else "no"
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        await process.wait()
        return "timeout"


async def _feed(process: asyncio.subprocess.Process, data: bytes) -> None:
    """Write ``data`` to the process and close its stdin; a process that does not read is fine."""
    assert process.stdin is not None  # noqa: S101 - it was created with a pipe
    with contextlib.suppress(BrokenPipeError, ConnectionResetError):
        process.stdin.write(data)
        await process.stdin.drain()
    with contextlib.suppress(BrokenPipeError, ConnectionResetError):
        process.stdin.close()
        await process.stdin.wait_closed()
