# SPDX-License-Identifier: Apache-2.0
"""The daemon's protocols and its wire format: requests, responses and errors.

``Request`` is one parsed line, and :func:`ok_response` and :func:`error_response` are the lines
that answer it. :class:`BrowserSession` and :class:`LoginWindow` are what the daemon needs of a
session and of a login, so tests can replace both. See :mod:`valetkey.client` for the wire format
as a client sees it.
"""

import contextlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NoReturn, Protocol

from valetkey import clicks, login, sessions, sites
from valetkey.client import DaemonError

if TYPE_CHECKING:
    import asyncio
    from pathlib import Path


_NOT_JSON = "the request is not valid JSON"


class BrowserSession(Protocol):
    """What the daemon needs of a session. :class:`valetkey.sessions.Session` provides it."""

    first_page: sessions.Page

    def open(self, url: str) -> sessions.Page:
        """Navigate to ``url``."""

    def snapshot(
        self, *, interactive: bool = True, selector: str | None = None
    ) -> sessions.Snapshot:
        """Return the page's interactive elements, or with ``interactive`` false its whole tree.

        With ``selector``, a CSS selector, only the part of the page under it.
        """

    def snapshot_delta(self, *, interactive: bool, full: bool = False) -> sessions.SnapshotDelta:
        """Return what changed in the page's tree since the last answer, or the whole tree."""

    def title(self) -> str:
        """Return the title of the page."""

    def look(self) -> tuple[str, str]:
        """Return the page's URL and its whole accessibility tree as text."""

    def click(self, ref: str) -> None:
        """Click ``ref``."""

    def password_fields(self) -> int:
        """Count the password fields on the page."""

    def match_count(self, selector: str) -> int:
        """Count the elements that the CSS ``selector`` matches."""

    def clear_requests(self) -> None:
        """Forget the logged network requests."""

    def started_downloads(self) -> list[sessions.Attachment]:
        """List the logged responses that the browser turns into downloads."""

    def press_enter(self) -> None:
        """Press Enter in the focused element."""

    def fill(self, ref: str, text: str) -> None:
        """Fill ``ref`` with ``text``."""

    def current_url(self) -> str:
        """Return the page's URL."""

    def resource_url(self, ref: str) -> str:
        """Return the address that the element ``ref`` stands for."""

    def images(self) -> list[dict[str, Any]]:
        """List the pictures and videos on the page."""

    def fetch(self, url: str) -> sessions.Body | None:
        """Return what ``url`` serves, or ``None`` when the browser saves it by itself."""

    def screenshot(self, name: str = "screenshot.png") -> Path:
        """Save a screenshot and return its path."""

    @property
    def watches_browser(self) -> bool:
        """Whether :meth:`is_alive` looks for the browser's own process in the process table."""

    def is_alive(self, lines: list[list[str]] | None = None) -> bool:
        """Tell whether the browser still runs.

        ``lines`` is the host's process table (see :func:`valetkey.procs.command_lines`), for a
        caller that checks several sessions and reads it once. Without it, a session that
        needs the table reads it itself.
        """

    def close(self) -> None:
        """End the session."""


class LoginWindow(Protocol):
    """What the daemon needs of a login. :class:`valetkey.login.LoginHandle` provides it."""

    async def wait(self) -> login.LoginResult:
        """Wait until the window has closed."""

    async def cancel(self) -> login.LoginResult:
        """End the login without classifying anything."""


@dataclass(frozen=True, slots=True)
class Request:
    """One parsed request line."""

    id: int | str | None
    op: str
    args: dict[str, Any]


def fail(code: str, message: str) -> NoReturn:
    """Raise the error ``code`` with ``message`` to the client."""
    raise DaemonError(code, message)


def parse_fail(message: str, request_id: int | str | None = None) -> NoReturn:
    """Raise a request that cannot be served, with the id to answer with, if one was readable."""
    raise _ParseError(message, request_id)


class _ParseError(DaemonError):
    """A request line that cannot be served; ``request_id`` is the id to answer with, if any."""

    def __init__(self, message: str, request_id: int | str | None = None) -> None:
        super().__init__("bad_request", message)
        self.request_id = request_id


def parse_request(line: bytes) -> Request:
    """Parse one request line.

    Raises:
        DaemonError: with code ``bad_request`` for anything that is not a JSON object with a
            string ``op``, an optional object ``args`` and an optional integer or string ``id``.
            Use :func:`request_id_of` on it to get the id to answer with, when one was readable.

    """
    try:
        data = json.loads(line)
    except ValueError:
        parse_fail(_NOT_JSON)
    if not isinstance(data, dict):
        parse_fail("the request must be a JSON object")
    identifier = data.get("id")
    if isinstance(identifier, bool) or not isinstance(identifier, int | str | None):
        identifier = None
    if not isinstance(data.get("op"), str) or not data["op"]:
        parse_fail('the request needs an "op" string', identifier)
    args = data.get("args", {})
    if not isinstance(args, dict):
        parse_fail('"args" must be an object', identifier)
    return Request(identifier, data["op"], args)


def request_id_of(error: DaemonError) -> int | str | None:
    """Return the request id a parse error carries, or ``None``."""
    return error.request_id if isinstance(error, _ParseError) else None


def encode(message: dict[str, Any]) -> bytes:
    """Return ``message`` as one line of JSON."""
    return json.dumps(message, separators=(",", ":")).encode() + b"\n"


def ok_response(identifier: int | str | None, result: dict[str, Any]) -> bytes:
    """Return the line that answers a request successfully."""
    return encode({"id": identifier, "ok": True, "result": result})


def error_response(identifier: int | str | None, error: DaemonError) -> bytes:
    """Return the line that answers a request with ``error``."""
    return encode({"id": identifier, "ok": False, "error": error.to_json()})


def untrusted(text: str) -> dict[str, Any]:
    """Wrap text that came from a web page, so a client can tell it from the daemon's own."""
    return {"untrusted": True, "text": text}


_ERROR_CODES: tuple[tuple[type[Exception], str], ...] = (
    (login.X11OnlyError, "x11_only"),
    (login.DisplayError, "no_display"),
    (sessions.AgentBrowserError, "browser_error"),
    (sessions.SessionError, "session_failed"),
    (sites.PolicyError, "bad_policy"),
    (sites.SuffixListError, "setup_error"),
    (sites.AmbiguousAccountError, "ambiguous_account"),
    (ValueError, "bad_request"),
)
"""How errors from below become codes. The first match wins, so subclasses come first."""


def map_error(error: Exception) -> DaemonError:
    """Turn an error from a session or the login runner into the error the client sees."""
    if isinstance(error, DaemonError):
        return error
    if isinstance(error, clicks.ClickError):
        return DaemonError(error.code, str(error), error.details)
    for kind, code in _ERROR_CODES:
        if isinstance(error, kind):
            return DaemonError(code, str(error))
    return DaemonError("internal", "the daemon hit an unexpected error")


def refused_entry(refusal: Any) -> dict[str, Any]:  # noqa: ANN401 - a proxy.Refusal
    """Describe one refusal for a client: the host, the port and the reason, nothing else."""
    return {"host": refusal.host, "port": refusal.port, "reason": refusal.reason}


def string_arg(args: dict[str, Any], name: str) -> str:
    """Return the non-empty string ``args[name]``, or fail with ``bad_request``."""
    value = args.get(name)
    if not isinstance(value, str) or not value:
        fail("bad_request", f'"{name}" must be a non-empty string')
    return value


async def send(writer: asyncio.StreamWriter, line: bytes) -> None:
    """Write one line to a client, and ignore a client that has gone."""
    with contextlib.suppress(OSError):
        writer.write(line)
        await writer.drain()
