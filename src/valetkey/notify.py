# SPDX-License-Identifier: Apache-2.0
"""Ask the person with a desktop notification that has Allow and Deny buttons.

This is the route for a host question when the client cannot show one and no approval command
is set. It needs three things: ``notify-send`` (libnotify), a session bus, and a notification
daemon that offers actions; a daemon without them would show a question nobody can answer. When
any is missing nothing is shown and the answer is ``none``, as with no approval command.

The notification names the site and the host and quotes the agent's reason as a claim. The reason
has already been through :func:`valetkey.approvals.sanitize_reason`, which removes the characters
a notification daemon reads as markup. Only the button the person presses allows anything:
closing the notification, or not answering, is ``timeout`` (the question expired and may be
asked again), never ``no``.
"""

import asyncio
import contextlib
import json
import os
import shutil
import signal
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

ALLOW = "allow"
DENY = "deny"
CAPABILITY = "actions"
CAPABILITY_TIMEOUT = 5.0
"""Seconds to wait for the notification daemon to list what it can do."""
_SERVICE = "org.freedesktop.Notifications"
_PATH = "/org/freedesktop/Notifications"

type Outcome = Literal["yes", "no", "timeout", "none"]


@dataclass(frozen=True, slots=True)
class Question:
    """What is asked: whether ``site`` may reach ``host``, and what is known about it.

    ``reason`` must come from :func:`valetkey.approvals.sanitize_reason`.
    """

    site: str
    host: str
    seen: bool
    reason: str


def command(program: str, question: Question, limit: float) -> list[str]:
    """Return the ``notify-send`` command line for ``question``.

    ``--action`` makes it wait and print the name of the button pressed. The text follows ``--``,
    so nothing in it can be read as an option. The notification expires with the question.
    """
    claim = f'"{question.reason}"' if question.reason else "(nothing)"
    seen = "yes" if question.seen else "no"
    return [
        program,
        "--app-name=valetkey",
        "--urgency=normal",
        f"--expire-time={int(limit * 1000)}",
        f"--action={ALLOW}=Allow",
        f"--action={DENY}=Deny",
        "--",
        f"Allow {question.site} to reach {question.host}?",
        f"Seen during login: {seen}\nThe agent says: {claim}",
    ]


async def _output(argv: list[str], env: Mapping[str, str], limit: float) -> tuple[int, str] | None:
    """Run ``argv`` and return its exit status and standard output, or ``None`` if it ran too long.

    The program has a process group of its own, which is killed on a timeout.

    Raises:
        `OSError`: when the program cannot be started.

    """
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        env=dict(env),
        start_new_session=True,
    )
    try:
        async with asyncio.timeout(limit):
            data, _ = await process.communicate()
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        await process.wait()
        return None
    return process.returncode or 0, data.decode(errors="replace")


async def has_actions(
    env: Mapping[str, str], which: Callable[[str], str | None] = shutil.which
) -> bool:
    """Tell whether a notification daemon on the session bus offers buttons.

    The daemon is asked for its capabilities, with ``busctl`` or else ``gdbus``. Anything that
    goes wrong, including neither tool being installed, means no.
    """
    if (busctl := which("busctl")) is not None:
        argv = [
            busctl,
            "--user",
            "--json=short",
            "call",
            _SERVICE,
            _PATH,
            _SERVICE,
            "GetCapabilities",
        ]
    elif (gdbus := which("gdbus")) is not None:
        argv = [gdbus, "call", "--session", "--dest", _SERVICE, "--object-path", _PATH]
        argv += ["--method", f"{_SERVICE}.GetCapabilities"]
    else:
        return False
    try:
        found = await _output(argv, env, CAPABILITY_TIMEOUT)
    except OSError:
        return False
    if found is None or found[0] != 0:
        return False
    if argv[0] == busctl:
        try:
            return CAPABILITY in json.loads(found[1])["data"][0]
        except ValueError, KeyError, IndexError, TypeError:
            return False
    return f"'{CAPABILITY}'" in found[1]


async def ask(
    question: Question,
    env: Mapping[str, str],
    limit: float,
    *,
    which: Callable[[str], str | None] = shutil.which,
) -> Outcome:
    """Put ``question`` to the person and return how it ended.

    ``yes`` is the Allow button, ``no`` the Deny button, ``timeout`` is a notification closed or
    left alone for ``limit`` seconds, and ``none`` means nobody could be asked this way. ``env`` is
    the environment of the person's session (see :func:`valetkey.approvals.command_environment`).
    """
    program = which("notify-send")
    if program is None or not await has_actions(env, which):
        return "none"
    try:
        found = await _output(command(program, question, limit), env, limit)
    except OSError:
        return "none"
    if found is None:
        return "timeout"
    chosen = found[1].strip()
    if found[0] == 0 and chosen == ALLOW:
        return "yes"
    if found[0] == 0 and chosen == DENY:
        return "no"
    return "timeout"
