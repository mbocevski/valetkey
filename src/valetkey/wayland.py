# SPDX-License-Identifier: Apache-2.0
"""A small Wayland client, enough to ask the compositor for a security context.

A browser that connects to the compositor's own socket can use every protocol the compositor
offers, including screen capture, virtual keyboards and pointers, and clipboard managers. A
*security context* is a second listening socket that the compositor serves with a restricted set
of protocols. valetkey registers one for each login window and gives the browser that socket, so
the window can show a page and take typing but cannot watch the screen or type for the person.

This module speaks only the part of the wire protocol that needs: the display and registry
objects, the security-context manager, and a roundtrip to be sure the compositor has acted.
Everything the compositor sends is parsed strictly, every wait has a timeout and every file
descriptor is closed on every path, so a broken or silent compositor raises
:class:`WaylandError` and never hangs the caller.

Messages are ``object id (u32) | size << 16 | opcode (u32) | arguments``, little endian, padded
to four bytes. File descriptors travel as ``SCM_RIGHTS`` data on the socket.
"""

import array
import contextlib
import os
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path
    from types import TracebackType

DEFAULT_TIMEOUT = 5.0
"""Seconds to wait for the compositor to connect, answer or accept a request."""
SANDBOX_ENGINE = "valetkey"
MANAGER = "wp_security_context_manager_v1"
_HEADER = struct.Struct("<II")
_U32 = struct.Struct("<I")
_DISPLAY = 1
_MAX_FDS = 16
_MAX_TEXT = 1024
"""The longest string valetkey sends: an application or instance name."""
_LISTEN_BACKLOG = 16
_ID_SIZE = 4
_ERROR_FIXED = 8
"""Bytes before the text of a ``wl_display.error``: the object and the code."""

# The display object: two requests, then two events.
_SYNC, _GET_REGISTRY = 0, 1
_ERROR, _DELETE_ID = 0, 1
# The registry's one request and one event, and the event of a callback.
_BIND, _GLOBAL = 0, 0
_DONE = 0
# The security-context manager has one request that matters here, and the context four.
_CREATE_LISTENER = 1
_SET_SANDBOX_ENGINE, _SET_APP_ID, _SET_INSTANCE_ID, _COMMIT = 1, 2, 3, 4


class WaylandError(RuntimeError):
    """The compositor could not be reached, did not answer, or answered wrongly."""


class SecurityContextUnavailableError(WaylandError):
    """The compositor does not offer ``wp_security_context_manager_v1``."""


def pad(size: int) -> int:
    """Return ``size`` rounded up to a multiple of four."""
    return -(-size // 4) * 4


def encode_string(value: str) -> bytes:
    """Encode ``value`` as a Wayland string: length with the NUL, the bytes, NUL, padding.

    Raises:
        ValueError: when the text holds a NUL or is longer than a name should be.

    """
    raw = value.encode()
    if b"\0" in raw or len(raw) > _MAX_TEXT:
        message = f"not usable as a Wayland name: {value[:40]!r}"
        raise ValueError(message)
    raw += b"\0"
    return _U32.pack(len(raw)) + raw + b"\0" * (pad(len(raw)) - len(raw))


def decode_string(payload: bytes, offset: int) -> tuple[str, int]:
    """Read a Wayland string at ``offset`` and return it with the offset after its padding.

    Raises:
        WaylandError: when it runs past the end, lacks its NUL, or is not UTF-8.

    """
    if offset + 4 > len(payload):
        message = "a message ended inside a string length"
        raise WaylandError(message)
    (length,) = _U32.unpack_from(payload, offset)
    start = offset + 4
    end = start + length
    if length < 1 or pad(end) > len(payload) or payload[end - 1] != 0:
        message = "a message holds a malformed string"
        raise WaylandError(message)
    try:
        text = payload[start : end - 1].decode()
    except UnicodeDecodeError:
        message = "a message holds a string that is not UTF-8"
        raise WaylandError(message) from None
    return text, start + pad(length)


def message(object_id: int, opcode: int, payload: bytes = b"") -> bytes:
    """Return one request: the header followed by the already padded ``payload``."""
    return _HEADER.pack(object_id, ((8 + len(payload)) << 16) | opcode) + payload


class Connection:
    """A connection to a Wayland compositor. Use it as a context manager.

    ``timeout`` bounds every connect and every wait for the compositor, in seconds.
    """

    def __init__(self, path: Path, timeout: float = DEFAULT_TIMEOUT) -> None:
        """Connect to the compositor socket at ``path``.

        Raises:
            WaylandError: when nothing accepts the connection in time.

        """
        self._timeout = timeout
        self._buffer = b""
        self._next_id = 2  # 1 is the display
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.settimeout(timeout)
        try:
            self._socket.connect(str(path))
        except OSError as error:
            self._socket.close()
            text = f"cannot connect to the Wayland compositor at {path}: {error}"
            raise WaylandError(text) from error

    def __enter__(self) -> Self:
        """Return the connection; leaving the block closes it."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the connection."""
        self._socket.close()

    def new_id(self) -> int:
        """Return an unused object id."""
        self._next_id += 1
        return self._next_id - 1

    def send(self, data: bytes, fds: tuple[int, ...] = ()) -> None:
        """Send ``data`` and, with it, copies of the descriptors ``fds``.

        Raises:
            WaylandError: when the compositor has gone away or does not take it in time.

        """
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))] if fds else []
        try:
            self._socket.sendmsg([data], ancillary)
        except OSError as error:
            text = f"cannot send to the Wayland compositor: {error}"
            raise WaylandError(text) from error

    def read(self, deadline: float) -> tuple[int, int, bytes]:
        """Return the next message as ``(object id, opcode, payload)``.

        Raises:
            WaylandError: at the deadline, at end of stream, or for a malformed header.

        """
        while True:
            if len(self._buffer) >= _HEADER.size:
                object_id, word = _HEADER.unpack_from(self._buffer)
                size = word >> 16
                if size < _HEADER.size or size % 4:
                    text = f"the compositor sent a message of {size} bytes"
                    raise WaylandError(text)
                if len(self._buffer) >= size:
                    payload = self._buffer[_HEADER.size : size]
                    self._buffer = self._buffer[size:]
                    return object_id, word & 0xFFFF, payload
            self._fill(deadline)

    def _fill(self, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            message_ = "the Wayland compositor did not answer in time"
            raise WaylandError(message_)
        self._socket.settimeout(remaining)
        try:
            data, ancillary, flags, _ = self._socket.recvmsg(65536, socket.CMSG_SPACE(_MAX_FDS * 4))
        except TimeoutError:
            message_ = "the Wayland compositor did not answer in time"
            raise WaylandError(message_) from None
        except OSError as error:
            text = f"cannot read from the Wayland compositor: {error}"
            raise WaylandError(text) from error
        _close_received(ancillary)  # nothing valetkey asks for comes with a descriptor
        if flags & socket.MSG_CTRUNC:
            message_ = "the compositor sent more descriptors than expected"
            raise WaylandError(message_)
        if not data:
            message_ = "the Wayland compositor closed the connection"
            raise WaylandError(message_)
        self._buffer += data

    def roundtrip(self) -> list[tuple[int, int, bytes]]:
        """Ask the compositor to acknowledge everything sent so far, and return what arrived.

        Raises:
            WaylandError: when the compositor reports an error, closes the connection or does
                not answer within the timeout.

        """
        deadline = time.monotonic() + self._timeout
        callback = self.new_id()
        self.send(message(_DISPLAY, _SYNC, _U32.pack(callback)))
        events: list[tuple[int, int, bytes]] = []
        while True:
            object_id, opcode, payload = self.read(deadline)
            if object_id == _DISPLAY and opcode == _ERROR:
                raise _display_error(payload)
            if object_id == callback and opcode == _DONE:
                return events
            if not (object_id == _DISPLAY and opcode == _DELETE_ID):
                events.append((object_id, opcode, payload))

    def globals(self) -> tuple[int, dict[str, tuple[int, int]]]:
        """Return the registry's object id and its globals as ``{interface: (name, version)}``."""
        registry = self.new_id()
        self.send(message(_DISPLAY, _GET_REGISTRY, _U32.pack(registry)))
        found: dict[str, tuple[int, int]] = {}
        for object_id, opcode, payload in self.roundtrip():
            if object_id == registry and opcode == _GLOBAL:
                if len(payload) < _ID_SIZE:
                    text = "a registry global is too short"
                    raise WaylandError(text)
                (name,) = _U32.unpack_from(payload, 0)
                interface, offset = decode_string(payload, 4)
                if len(payload) != offset + 4:
                    text = "a registry global has the wrong length"
                    raise WaylandError(text)
                (version,) = _U32.unpack_from(payload, offset)
                found[interface] = (name, version)
        return registry, found

    def bind(self, registry: int, name: int, interface: str, version: int) -> int:
        """Bind a global and return the new object's id."""
        object_id = self.new_id()
        payload = _U32.pack(name) + encode_string(interface) + _U32.pack(version)
        self.send(message(registry, _BIND, payload + _U32.pack(object_id)))
        return object_id


def _close_received(ancillary: list[tuple[int, int, bytes]]) -> None:
    """Close every descriptor that arrived, which valetkey never asks for."""
    for level, kind, data in ancillary:
        received = array.array("i")
        received.frombytes(data[: len(data) - len(data) % received.itemsize])
        for descriptor in (
            received if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS) else ()
        ):
            os.close(descriptor)


def _display_error(payload: bytes) -> WaylandError:
    """Describe a ``wl_display.error`` event, or the fact that it was itself malformed."""
    if len(payload) < _ERROR_FIXED:
        return WaylandError("the compositor reported an error that could not be read")
    object_id, code = struct.unpack_from("<II", payload)
    try:
        text, _ = decode_string(payload, _ERROR_FIXED)
    except WaylandError:
        text = "(no readable message)"
    return WaylandError(
        f"the Wayland compositor reported error {code} on object {object_id}: {text}"
    )


def compositor_globals(path: Path, timeout: float = DEFAULT_TIMEOUT) -> dict[str, int]:
    """Return the interfaces the compositor at ``path`` offers, with their versions.

    Raises:
        WaylandError: when the compositor cannot be reached or answers wrongly.

    """
    with Connection(path, timeout) as connection:
        _, found = connection.globals()
    return {interface: version for interface, (_, version) in found.items()}


@dataclass(slots=True)
class SecurityContext:
    """A registered security-context socket. Close it when the window it serves is gone.

    ``path`` is the listening socket to give to the sandboxed client. The compositor serves it
    until the close descriptor hangs up, which :meth:`close` does. Clients already connected
    keep their connections.
    """

    path: Path
    _close_fd: int = field(repr=False)

    def close(self) -> None:
        """Tell the compositor to stop listening, and remove the socket file. Safe to repeat."""
        if self._close_fd >= 0:
            os.close(self._close_fd)
            self._close_fd = -1
        with contextlib.suppress(FileNotFoundError):
            self.path.unlink()


def create_security_context(
    compositor: Path,
    listen_path: Path,
    *,
    app_id: str,
    instance_id: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> SecurityContext:
    """Register a restricted listening socket at ``listen_path`` with the compositor.

    The directory of ``listen_path`` should be private to the user. The compositor lists
    ``valetkey`` as the sandbox engine, with ``app_id`` and ``instance_id``, for every client
    that connects through the socket.

    Raises:
        SecurityContextUnavailableError: when the compositor does not offer the manager.
        WaylandError: when the compositor cannot be reached or does not accept the request.
        ValueError: when a name holds a NUL or is too long.

    """
    names = (SANDBOX_ENGINE, app_id, instance_id)
    encoded = [encode_string(name) for name in names]  # before anything is opened
    with Connection(compositor, timeout) as connection:
        registry, found = connection.globals()
        if MANAGER not in found:
            message_ = f"the Wayland compositor does not offer {MANAGER}"
            raise SecurityContextUnavailableError(message_)
        name, version = found[MANAGER]
        manager = connection.bind(registry, name, MANAGER, min(version, 1))
        context = connection.new_id()
        with _listening_socket(listen_path) as listener:
            read_end, write_end = os.pipe()
            try:
                connection.send(
                    message(manager, _CREATE_LISTENER, _U32.pack(context)),
                    (listener.fileno(), read_end),
                )
                for opcode, data in zip(
                    (_SET_SANDBOX_ENGINE, _SET_APP_ID, _SET_INSTANCE_ID), encoded, strict=True
                ):
                    connection.send(message(context, opcode, data))
                connection.send(message(context, _COMMIT))
                connection.roundtrip()
            except BaseException:
                os.close(write_end)
                with contextlib.suppress(FileNotFoundError):
                    listen_path.unlink()
                raise
            finally:
                os.close(read_end)
    return SecurityContext(listen_path, write_end)


@contextlib.contextmanager
def _listening_socket(path: Path) -> Generator[socket.socket]:
    """Yield a socket listening at ``path`` (mode 0600), closing it on leaving.

    A file left at ``path`` by an earlier run is removed first. The compositor keeps its own copy
    of the descriptor, so the caller's can be closed once the request has been answered.
    """
    with contextlib.suppress(FileNotFoundError):
        path.unlink()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(path))
        path.chmod(0o600)
        listener.listen(_LISTEN_BACKLOG)
    except OSError as error:
        listener.close()
        with contextlib.suppress(OSError):
            path.unlink()
        text = f"cannot listen at {path}: {error}"
        raise WaylandError(text) from error
    try:
        yield listener
    finally:
        listener.close()
