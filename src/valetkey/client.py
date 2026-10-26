# SPDX-License-Identifier: Apache-2.0
"""The client of ``valetkeyd``: what the MCP adapter and the command-line tool talk through.

The daemon speaks newline-delimited JSON on a Unix socket. A request is
``{"id": 1, "op": "snapshot", "args": {"site": "sitex"}}`` and the answer to it is
``{"id": 1, "ok": true, "result": {...}}`` or
``{"id": 1, "ok": false, "error": {"code": "...", "message": "..."}}``. :class:`Client` sends
requests, matches answers by id, and turns error answers into :class:`DaemonError`. Several
calls may be in flight on one client at once.
"""

import asyncio
import contextlib
import fcntl
import itertools
import json
import os
from typing import TYPE_CHECKING, Any, Self

from valetkey import sites

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator
    from pathlib import Path
    from types import TracebackType

SOCKET_NAME = "daemon.sock"
MAX_LINE_BYTES = 1024 * 1024
"""The longest request line the daemon accepts."""
_LOST = "the connection to valetkeyd was lost"
_READ_LIMIT = 64 * 1024 * 1024
"""The longest answer line the client accepts (a snapshot of a large page)."""


class DaemonError(Exception):
    """The daemon answered a request with an error, or could not be reached.

    ``code`` is a short machine-readable name such as ``unknown_site`` or ``session_running``,
    ``message`` is for people, and ``details`` holds extra fields the daemon sent with it.
    """

    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        """Keep the code, the message and any details."""
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.details = details or {}

    def to_json(self) -> dict[str, Any]:
        """Return the error as it travels in an answer."""
        error: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.details:
            error["details"] = self.details
        return error


def socket_path(roots: sites.Roots | None = None) -> Path:
    """Return where the daemon listens: ``$XDG_RUNTIME_DIR/valetkey/daemon.sock``.

    Raises:
        RuntimeDirUnavailableError: when ``XDG_RUNTIME_DIR`` is unset.

    """
    return sites.runtime_path(roots or sites.roots_from_env()) / SOCKET_NAME


def lock_path(path: Path) -> Path:
    """Return the lock file the daemon holds while it runs on the socket at ``path``."""
    return path.with_name(path.name + ".lock")


def daemon_holds_lock(path: Path | None = None) -> bool:
    """Tell whether a daemon is running on ``path`` (default: :func:`socket_path`).

    This looks at the daemon's lock file and does not connect. Under systemd socket activation,
    connecting to the socket starts the daemon, so a command that must never start one asks
    here first and connects only when this is true. A missing lock file, or one nobody holds,
    means no daemon, and a missing runtime directory is the same.
    """
    try:
        target = lock_path(path or socket_path())
        descriptor = os.open(target, os.O_RDWR)  # no O_CREAT: looking must not leave a file
    except OSError, sites.RuntimeDirUnavailableError:
        return False
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return True
    finally:
        os.close(descriptor)  # also drops a lock taken here
    return False


async def is_running(path: Path | None = None) -> bool:
    """Tell whether a daemon is listening on ``path`` (default: :func:`socket_path`)."""
    try:
        client = await Client.connect(path)
    except DaemonError:
        return False
    await client.close()
    return True


class Client:
    """A connection to the daemon. Get one with :meth:`connect`."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Wrap an open connection; use :meth:`connect` instead of calling this."""
        self._writer = writer
        self._ids = itertools.count(1)
        self._pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self._streams: dict[int, asyncio.Queue[dict[str, Any] | DaemonError]] = {}
        self._reader_task = asyncio.ensure_future(self._read_answers(reader))

    @classmethod
    async def connect(cls, path: Path | None = None) -> Self:
        """Connect to the daemon on ``path`` (default: :func:`socket_path`).

        Raises:
            DaemonError: with code ``not_running`` when nothing listens there.

        """
        target = path or socket_path()
        try:
            reader, writer = await asyncio.open_unix_connection(target, limit=_READ_LIMIT)
        except OSError as error:
            message = f"valetkeyd is not running ({target}: {error.strerror or error})"
            code = "not_running"
            raise DaemonError(code, message) from error
        return cls(reader, writer)

    async def call(self, op: str, **args: Any) -> dict[str, Any]:  # noqa: ANN401 - JSON values
        """Send ``op`` with ``args`` and return the ``result`` of the answer.

        Raises:
            DaemonError: for an error answer (its code and message are the daemon's), or with
                code ``connection_lost`` if the connection ends before the answer arrives.

        """
        identifier = next(self._ids)
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[identifier] = future
        line = json.dumps({"id": identifier, "op": op, "args": args}).encode() + b"\n"
        try:
            self._writer.write(line)
            await self._writer.drain()
        except OSError as error:
            self._pending.pop(identifier, None)
            code = "connection_lost"
            raise DaemonError(code, _LOST) from error
        try:
            return await future
        finally:
            self._pending.pop(identifier, None)

    async def watch(self) -> AsyncGenerator[dict[str, Any]]:
        """Stream what the daemon reports with ``watch``: first a snapshot, then each change.

        Each item is a dictionary with an ``event`` key (``snapshot``, ``session_started``,
        ``session_ended``, ``login_opened`` or ``login_closed``). The connection is used for
        nothing else while this runs. Stop iterating to stop watching; close the client to end it.

        Raises:
            DaemonError: with code ``connection_lost`` when the daemon goes away.

        """
        identifier = next(self._ids)
        queue: asyncio.Queue[dict[str, Any] | DaemonError] = asyncio.Queue()
        self._streams[identifier] = queue
        line = json.dumps({"id": identifier, "op": "watch", "args": {}}).encode() + b"\n"
        try:
            try:
                self._writer.write(line)
                await self._writer.drain()
            except OSError as error:
                code = "connection_lost"
                raise DaemonError(code, _LOST) from error
            while True:
                item = await queue.get()
                if isinstance(item, DaemonError):
                    raise item
                yield item
        finally:
            self._streams.pop(identifier, None)

    async def close(self) -> None:
        """Close the connection. Calls still waiting fail with ``connection_lost``."""
        self._writer.close()
        with contextlib.suppress(OSError):
            await self._writer.wait_closed()
        await asyncio.gather(self._reader_task, return_exceptions=True)

    async def __aenter__(self) -> Self:
        """Return the client; leaving the ``async with`` block closes it."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the connection."""
        await self.close()

    async def _read_answers(self, reader: asyncio.StreamReader) -> None:
        """Hand each answer to the call waiting for it; fail all calls when the stream ends."""
        try:
            while line := await reader.readline():
                self._deliver(line)
        except OSError, ValueError:
            pass  # a broken or oversized stream ends the connection like a closed one
        finally:
            lost = DaemonError("connection_lost", _LOST)
            for future in list(self._pending.values()):
                with contextlib.suppress(asyncio.InvalidStateError):  # already answered
                    future.set_exception(lost)
            for queue in list(self._streams.values()):
                queue.put_nowait(lost)

    def _deliver(self, line: bytes) -> None:
        try:
            answer = json.loads(line)
            future = self._pending.get(answer["id"])
            queue = self._streams.get(answer["id"])
        except ValueError, KeyError, TypeError:
            return  # not an answer to anything this client sent
        if answer.get("ok") is True:
            result = answer.get("result") or {}
            if queue is not None:
                queue.put_nowait(result)
            elif future is not None and not future.done():
                future.set_result(result)
            return
        error = answer.get("error") or {}
        failure = DaemonError(
            str(error.get("code", "error")),
            str(error.get("message", "")),
            error.get("details"),
        )
        if queue is not None:
            queue.put_nowait(failure)
        elif future is not None and not future.done():
            future.set_exception(failure)
