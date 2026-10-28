# SPDX-License-Identifier: Apache-2.0
"""What went wrong inside a page: its errors, its console and its failed requests.

``browser_console`` answers from agent-browser's buffers (see
:meth:`valetkey.sessions.Session.diagnostics`). Everything in them was written by the page, so
:func:`report` cuts each section and each entry to a limit and marks the text of every entry as
untrusted, the way a snapshot's is. The three sections are:

* **errors:** uncaught exceptions and unhandled rejections, with the message, the stack the page
  gave and the line and column.
* **console:** the messages of level warning and error. Plain logs are left out.
* **requests:** the requests that got no response (they failed, or are still going) and those
  answered with a status of 400 or more. Those to a host the proxy refused are marked.

A section shows the first :data:`MAX_ENTRIES` entries, in the order they happened, and says how
many more there were.
"""

from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from valetkey.protocol import untrusted

if TYPE_CHECKING:
    from collections.abc import Collection, Iterable, Mapping

MAX_ENTRIES = 50
"""The most entries a section shows."""
MAX_ENTRY_CHARACTERS = 500
"""The most characters an entry shows of the page's text."""
_HTTP_ERROR = 400
_MILLISECONDS = 1000
_MAX_KIND = 20


def _clip(value: object) -> str:
    """Return ``value`` as text of at most :data:`MAX_ENTRY_CHARACTERS` characters."""
    text = value if isinstance(value, str) else str(value)
    if len(text) <= MAX_ENTRY_CHARACTERS:
        return text
    return text[:MAX_ENTRY_CHARACTERS] + "…"


def _number(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _section(entries: list[dict[str, Any]], total: int) -> dict[str, Any]:
    return {"total": total, "entries": entries, "left_out": total - len(entries)}


def _host(url: str) -> str | None:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _error(item: dict[str, Any]) -> dict[str, Any]:
    url = item.get("url")
    return {
        "text": untrusted(_clip(item.get("text", ""))),
        "line": _number(item.get("line")),
        "column": _number(item.get("column")),
        "url": untrusted(_clip(url)) if isinstance(url, str) and url else None,
    }


def _message(item: dict[str, Any]) -> dict[str, Any]:
    level = "error" if item.get("type") == "error" else "warning"
    return {"level": level, "text": untrusted(_clip(item.get("text", "")))}


def _request(item: dict[str, Any], now: float, refused: Collection[str]) -> dict[str, Any]:
    url = str(item.get("url") or "")
    started = item.get("timestamp")
    age = (
        max(0, int((now - started) / _MILLISECONDS))
        if isinstance(started, int | float) and not isinstance(started, bool)
        else None
    )
    kind = str(item.get("resourceType") or "")
    host = _host(url)
    return {
        "request": untrusted(_clip(f"{item.get('method') or 'GET'} {url}")),
        "status": _number(item.get("status")),
        "type": kind if kind.isalnum() and len(kind) <= _MAX_KIND else "",
        "age_seconds": age,
        "refused": host is not None and host in refused,
    }


def _failed(item: dict[str, Any]) -> bool:
    status = _number(item.get("status"))
    return status is None or status >= _HTTP_ERROR


def report(
    raw: Mapping[str, Iterable[Any]], *, now_ms: float, refused: Collection[str] = ()
) -> dict[str, Any]:
    """Shape ``raw`` (what the session read) into the answer of ``browser_console``.

    ``now_ms`` is the time in milliseconds since the epoch, to say how long ago a request began,
    and ``refused`` the hosts the proxy has refused for the site.
    """
    errors = [item for item in raw["errors"] if isinstance(item, dict)]
    messages = [item for item in raw["console"] if isinstance(item, dict)]
    requests = [item for item in raw["requests"] if isinstance(item, dict) and _failed(item)]
    return {
        "errors": _section([_error(i) for i in errors[:MAX_ENTRIES]], len(errors)),
        "console": _section([_message(i) for i in messages[:MAX_ENTRIES]], len(messages)),
        "requests": _section(
            [_request(i, now_ms, refused) for i in requests[:MAX_ENTRIES]], len(requests)
        ),
    }
