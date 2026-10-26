# SPDX-License-Identifier: Apache-2.0
"""The Wayland client, replayed against a fake compositor that speaks recorded bytes."""

import array
import contextlib
import errno
import os
import select
import socket
import struct
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

import pytest

from valetkey import wayland
from valetkey.wayland import (
    SecurityContextUnavailableError,
    WaylandError,
    decode_string,
    encode_string,
    message,
)

if TYPE_CHECKING:
    from collections.abc import Callable

U32 = struct.Struct("<I")
MANAGER = "wp_security_context_manager_v1"


def u32(value: int) -> bytes:
    return U32.pack(value)


def fd_count() -> int:
    return len(list(Path("/proc/self/fd").iterdir()))


# -- a fake compositor -----------------------------------------------------------------------


class Request:
    def __init__(self, object_id: int, opcode: int, payload: bytes, fds: list[int]) -> None:
        self.object_id, self.opcode, self.payload, self.fds = object_id, opcode, payload, fds


class Peer:
    """The compositor's end of one connection, with what it needs to read requests."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buffer = b""
        self.fds: list[int] = []
        self.owned: list[int] = []

    def read(self) -> Request:
        while len(self.buffer) < 8 or len(self.buffer) < self._size():
            data, ancillary, _flags, _addr = self.sock.recvmsg(4096, socket.CMSG_SPACE(16 * 4))
            if not data:
                raise EOFError
            for _level, _kind, raw in ancillary:
                received = array.array("i")
                received.frombytes(raw[: len(raw) - len(raw) % 4])
                self.fds += list(received)
                self.owned += list(received)
            self.buffer += data
        size = self._size()
        object_id, word = struct.unpack("<II", self.buffer[:8])
        payload, self.buffer = self.buffer[8:size], self.buffer[size:]
        fds, self.fds = self.fds, []
        return Request(object_id, word & 0xFFFF, payload, fds)

    def _size(self) -> int:
        return struct.unpack("<II", self.buffer[:8])[1] >> 16 if len(self.buffer) >= 8 else 8

    def send(self, data: bytes, fds: tuple[int, ...] = ()) -> None:
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))] if fds else []
        self.sock.sendmsg([data], ancillary)

    def handshake(self, interfaces: dict[str, int]) -> int:
        """Offer ``interfaces`` as the registry's globals and answer the sync after them.

        Returns the registry's id.
        """
        registry = U32.unpack(self.read().payload)[0]
        for number, (name, version) in enumerate(interfaces.items(), 1):
            self.send(message(registry, 0, u32(number) + encode_string(name) + u32(version)))
        callback = U32.unpack(self.read().payload)[0]
        self.send(message(callback, 0, u32(0)))
        return registry

    def linger(self) -> None:
        """Wait until the client hangs up, so a message sent last is not lost to a reset."""
        self.sock.settimeout(5)
        with contextlib.suppress(EOFError, OSError):
            while True:
                self.read()

    def acknowledge(self) -> None:
        """Answer the sync that is waiting."""
        request = self.read()
        self.send(message(U32.unpack(request.payload)[0], 0, u32(0)))


class Compositor:
    """Listens on a socket and runs ``script(peer)`` for the first client."""

    def __init__(self, path: Path, script: Callable[[Peer], Any]) -> None:
        self.path = path
        self.result: Any = None
        self.error: BaseException | None = None
        self._listener = socket.socket(socket.AF_UNIX)
        self._listener.bind(str(path))
        self._listener.listen()
        self._script = script
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        connection, _ = self._listener.accept()
        peer = Peer(connection)
        try:
            self.result = self._script(peer)
        except EOFError, ConnectionError:
            pass  # the client left, which the test then judges from its own side
        except BaseException as error:  # noqa: BLE001 - reported to the test thread
            self.error = error
        finally:
            for descriptor in peer.owned:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            connection.close()

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._thread.join(10)
        self._listener.close()
        if self.error is not None:
            raise self.error


@pytest.fixture
def paths(short_dir: Path) -> tuple[Path, Path]:
    return short_dir / "wayland-0", short_dir / "secctx.sock"


def create(compositor: Path, listen: Path, **options: Any) -> wayland.SecurityContext:  # noqa: ANN401
    return wayland.create_security_context(
        compositor, listen, app_id="valetkey-login", instance_id="sitex", timeout=2, **options
    )


# -- the happy path --------------------------------------------------------------------------


def accepting(peer: Peer) -> dict[str, Any]:
    """A compositor that offers the manager and accepts a context."""
    registry = peer.handshake({"wl_compositor": 6, MANAGER: 1})
    seen: dict[str, Any] = {"registry": registry}
    seen["bind"] = peer.read()
    create_listener = peer.read()
    seen["create"] = create_listener
    seen["strings"] = [peer.read() for _ in range(3)]
    seen["commit"] = peer.read()
    listen_fd, close_fd = create_listener.fds
    with socket.socket(fileno=os.dup(listen_fd)) as listener:
        seen["listening"] = listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
    poller = select.poll()
    poller.register(close_fd, select.POLLIN)
    seen["before_hangup"] = poller.poll(0)
    peer.acknowledge()  # the client waits for this, so it cannot have closed the context yet
    return seen


def test_a_security_context_is_registered_with_the_names_and_two_descriptors(
    paths: tuple[Path, Path],
) -> None:
    compositor, listen = paths
    before = fd_count()
    seen: dict[str, Any] = {}

    def script(peer: Peer) -> None:
        nonlocal seen
        seen = accepting(peer)

    with Compositor(compositor, script):
        context = create(compositor, listen)
        assert context.path == listen
        assert listen.is_socket()
        assert oct(listen.stat().st_mode & 0o777) == "0o600"
        context.close()
        context.close()  # again is fine
        assert not listen.exists()
    bind = seen["bind"]
    assert bind.object_id == seen["registry"]
    name, offset = U32.unpack_from(bind.payload)[0], 4
    interface, offset = decode_string(bind.payload, offset)
    assert (interface, U32.unpack_from(bind.payload, offset)[0]) == (MANAGER, 1)
    assert name == 2  # the second global
    assert len(seen["create"].fds) == 2
    assert seen["listening"] == 1  # the first descriptor is a listening socket
    assert [decode_string(r.payload, 0)[0] for r in seen["strings"]] == [
        "valetkey",
        "valetkey-login",
        "sitex",
    ]
    assert [r.opcode for r in seen["strings"]] == [1, 2, 3]
    assert (seen["commit"].opcode, seen["commit"].payload) == (4, b"")
    assert seen["before_hangup"] == []  # the close descriptor is quiet while the window runs
    assert fd_count() == before


def test_closing_the_context_makes_the_close_descriptor_hang_up(paths: tuple[Path, Path]) -> None:
    compositor, listen = paths
    holder: dict[str, Any] = {}

    def script(peer: Peer) -> None:
        holder.update(accepting_until_released(peer))

    release = threading.Event()
    polled = threading.Event()

    def accepting_until_released(peer: Peer) -> dict[str, Any]:
        peer.handshake({MANAGER: 1})
        peer.read()
        create_listener = peer.read()
        for _ in range(4):
            peer.read()
        peer.acknowledge()
        _listen_fd, close_fd = create_listener.fds
        poller = select.poll()
        poller.register(close_fd, select.POLLIN)
        quiet = poller.poll(0)
        polled.set()
        release.wait(5)
        loud = poller.poll(2000)
        return {"quiet": quiet, "loud": loud}

    with Compositor(compositor, script):
        context = create(compositor, listen)
        assert polled.wait(5)  # the compositor has looked at the descriptor while it is quiet
        context.close()
        release.set()
    assert holder["quiet"] == []
    assert holder["loud"]
    assert holder["loud"][0][1] & select.POLLHUP


def test_a_stale_socket_file_is_replaced(paths: tuple[Path, Path]) -> None:
    compositor, listen = paths
    listen.write_text("left over")

    with Compositor(compositor, accepting):
        context = create(compositor, listen)
        assert listen.is_socket()
        context.close()


def test_a_newer_manager_is_bound_at_the_version_valetkey_knows(paths: tuple[Path, Path]) -> None:
    compositor, listen = paths
    versions: list[int] = []

    def script(peer: Peer) -> None:
        peer.handshake({MANAGER: 3})
        bind = peer.read()
        _, offset = decode_string(bind.payload, 4)
        versions.append(U32.unpack_from(bind.payload, offset)[0])
        for _ in range(5):
            peer.read()
        peer.acknowledge()

    with Compositor(compositor, script):
        create(compositor, listen).close()
    assert versions == [1]


def test_events_that_are_not_ours_do_not_get_in_the_way(paths: tuple[Path, Path]) -> None:
    compositor, _ = paths

    def script(peer: Peer) -> None:
        registry = U32.unpack(peer.read().payload)[0]
        callback = U32.unpack(peer.read().payload)[0]
        peer.send(message(1, 1, u32(99)))  # wl_display.delete_id
        peer.send(message(42, 7, b"stranger"))  # an event for an object we never made
        peer.send(message(registry, 0, u32(1) + encode_string("wl_shm") + u32(2)))
        peer.send(message(callback, 0, u32(0)))

    with Compositor(compositor, script):
        assert wayland.compositor_globals(compositor, timeout=2) == {"wl_shm": 2}


def test_globals_list_every_interface_with_its_version(paths: tuple[Path, Path]) -> None:
    compositor, _ = paths

    def script(peer: Peer) -> None:
        peer.handshake({"wl_compositor": 6, "wl_seat": 9, MANAGER: 1})

    with Compositor(compositor, script):
        assert wayland.compositor_globals(compositor, timeout=2) == {
            "wl_compositor": 6,
            "wl_seat": 9,
            MANAGER: 1,
        }


# -- a compositor without the manager --------------------------------------------------------


def test_a_compositor_without_the_manager_raises_a_specific_error(paths: tuple[Path, Path]) -> None:
    compositor, listen = paths
    before = fd_count()

    with (
        Compositor(compositor, lambda peer: peer.handshake({"wl_compositor": 6})),
        pytest.raises(SecurityContextUnavailableError, match=MANAGER),
    ):
        create(compositor, listen)
    assert not listen.exists()  # no socket was made for nothing
    assert fd_count() == before


# -- compositors that go wrong ---------------------------------------------------------------


def after_handshake_error(code: int, text: str) -> Callable[[Peer], None]:
    def script(peer: Peer) -> None:
        peer.handshake({MANAGER: 1})
        for _ in range(7):  # the bind, the listener, three names, the commit and the sync
            peer.read()
        peer.send(message(1, 0, u32(5) + u32(code) + encode_string(text)))
        peer.linger()

    return script


def test_an_error_from_the_compositor_is_raised_with_its_words(paths: tuple[Path, Path]) -> None:
    compositor, listen = paths
    before = fd_count()
    with (
        Compositor(compositor, after_handshake_error(1, "invalid_listen_fd")),
        pytest.raises(WaylandError, match=r"error 1 on object 5: invalid_listen_fd"),
    ):
        create(compositor, listen)
    assert not listen.exists()
    assert fd_count() == before


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"\x01\x00\x00\x00", "could not be read"),
        (u32(5) + u32(2) + u32(9) + b"no nul\0\0", "(no readable message)"),
    ],
)
def test_an_error_that_cannot_be_read_is_still_an_error(
    paths: tuple[Path, Path], payload: bytes, expected: str
) -> None:
    compositor, _ = paths

    def script(peer: Peer) -> None:
        peer.read()
        peer.read()
        peer.send(message(1, 0, payload))
        peer.linger()

    with (
        Compositor(compositor, script),
        pytest.raises(WaylandError, match=expected.replace("(", r"\(").replace(")", r"\)")),
    ):
        wayland.compositor_globals(compositor, timeout=2)


def test_a_compositor_that_never_answers_times_out(paths: tuple[Path, Path]) -> None:
    compositor, listen = paths
    before = fd_count()
    release = threading.Event()

    with Compositor(compositor, lambda _peer: release.wait(5)):
        started = time.monotonic()
        with pytest.raises(WaylandError, match="did not answer in time"):
            wayland.create_security_context(
                compositor, listen, app_id="a", instance_id="b", timeout=0.3
            )
        assert time.monotonic() - started < 3
        release.set()
    assert fd_count() == before


def test_a_compositor_that_hangs_up_is_reported(paths: tuple[Path, Path]) -> None:
    compositor, _ = paths

    def script(peer: Peer) -> None:
        peer.read()
        peer.read()  # both requests were read, so the close is clean

    with Compositor(compositor, script), pytest.raises(WaylandError, match="closed the connection"):
        wayland.compositor_globals(compositor, timeout=2)


class ResettingSocket:
    """Wraps a socket and fails every read as a reset connection does."""

    def __init__(self, wrapped: socket.socket) -> None:
        self._wrapped = wrapped

    def __getattr__(self, name: str) -> Any:  # noqa: ANN401 - whatever the socket has
        return getattr(self._wrapped, name)

    def recvmsg(self, *_args: object) -> None:
        raise ConnectionResetError(errno.ECONNRESET, "Connection reset by peer")


def test_a_connection_that_is_reset_is_reported(paths: tuple[Path, Path]) -> None:
    compositor, _ = paths
    with Compositor(compositor, lambda peer: peer.linger()):
        connection = wayland.Connection(compositor, 2)
        connection._socket = ResettingSocket(connection._socket)  # noqa: SLF001  # ty: ignore[invalid-assignment]
        with connection, pytest.raises(WaylandError, match=r"cannot read.*reset"):
            connection.globals()


def test_a_message_cut_short_by_a_hangup_is_reported(paths: tuple[Path, Path]) -> None:
    compositor, _ = paths

    def script(peer: Peer) -> None:
        peer.read()
        peer.read()
        peer.send(struct.pack("<II", 2, (40 << 16) | 0) + b"short")

    with Compositor(compositor, script), pytest.raises(WaylandError, match="closed the connection"):
        wayland.compositor_globals(compositor, timeout=2)


@pytest.mark.parametrize("size", [0, 4, 7, 13])
def test_a_header_with_an_impossible_size_is_refused(paths: tuple[Path, Path], size: int) -> None:
    compositor, _ = paths

    def script(peer: Peer) -> None:
        peer.read()
        peer.read()
        peer.send(struct.pack("<II", 2, (size << 16) | 0) + b"\0" * 16)
        peer.linger()

    with (
        Compositor(compositor, script),
        pytest.raises(WaylandError, match=f"message of {size} bytes"),
    ):
        wayland.compositor_globals(compositor, timeout=2)


GOOD = encode_string("wl_shm") + u32(2)


@pytest.mark.parametrize(
    ("payload", "problem"),
    [
        (b"", "too short"),
        (u32(1), "inside a string length"),
        (u32(1) + u32(0) + u32(2), "malformed string"),  # a length of zero
        (u32(1) + u32(99) + b"short\0\0\0" + u32(2), "malformed string"),  # past the end
        (u32(1) + u32(6) + b"wl_shm" + b"\0\0" + u32(2), "malformed string"),  # no NUL
        (u32(1) + u32(3) + b"\xff\xfe\0" + b"\0" + u32(2), "not UTF-8"),
        (u32(1) + u32(2), "inside a string length|malformed"),
        (u32(1) + GOOD + b"\0\0\0\0", "wrong length"),
        (u32(1) + encode_string("wl_shm"), "wrong length"),
    ],
)
def test_a_malformed_global_is_refused_not_guessed_at(
    paths: tuple[Path, Path], payload: bytes, problem: str
) -> None:
    compositor, _ = paths

    def script(peer: Peer) -> None:
        registry = U32.unpack(peer.read().payload)[0]
        callback = U32.unpack(peer.read().payload)[0]
        peer.send(message(registry, 0, payload) + message(callback, 0, u32(0)))
        peer.linger()

    with Compositor(compositor, script), pytest.raises(WaylandError, match=problem):
        wayland.compositor_globals(compositor, timeout=2)


def test_a_string_that_ends_inside_its_length_is_refused() -> None:
    with pytest.raises(WaylandError, match="inside a string length"):
        decode_string(b"\x01\x00", 0)


def test_descriptors_the_compositor_sends_are_closed(paths: tuple[Path, Path]) -> None:
    compositor, _ = paths
    before = fd_count()

    def script(peer: Peer) -> None:
        registry = U32.unpack(peer.read().payload)[0]
        callback = U32.unpack(peer.read().payload)[0]
        extra = os.open("/dev/null", os.O_RDONLY)
        try:
            peer.send(message(registry, 0, u32(1) + GOOD), (extra,))
        finally:
            os.close(extra)
        peer.send(message(callback, 0, u32(0)))
        peer.linger()

    with Compositor(compositor, script):
        assert wayland.compositor_globals(compositor, timeout=2) == {"wl_shm": 2}
    assert fd_count() == before


def test_more_descriptors_than_expected_is_an_error_and_leaks_none(
    paths: tuple[Path, Path],
) -> None:
    compositor, _ = paths
    before = fd_count()

    def script(peer: Peer) -> None:
        peer.read()
        peer.read()
        extras = [os.open("/dev/null", os.O_RDONLY) for _ in range(40)]
        try:
            with contextlib.suppress(OSError):  # the kernel may refuse that many at once
                peer.send(message(2, 0, b""), tuple(extras))
        finally:
            for descriptor in extras:
                os.close(descriptor)
        peer.linger()

    with Compositor(compositor, script), pytest.raises(WaylandError):
        wayland.compositor_globals(compositor, timeout=2)
    assert fd_count() == before


# -- the caller's mistakes -------------------------------------------------------------------


def test_a_compositor_that_is_not_there_is_an_error(paths: tuple[Path, Path]) -> None:
    compositor, listen = paths
    before = fd_count()
    with pytest.raises(WaylandError, match="cannot connect"):
        create(compositor, listen)
    assert not listen.exists()
    assert fd_count() == before


@pytest.mark.parametrize("bad", ["has\0nul", "x" * 2000])
def test_names_that_cannot_be_sent_are_refused_before_anything_opens(
    paths: tuple[Path, Path], bad: str
) -> None:
    compositor, listen = paths
    with pytest.raises(ValueError, match="not usable as a Wayland name"):
        wayland.create_security_context(compositor, listen, app_id=bad, instance_id="b")


def test_a_socket_that_cannot_be_made_is_an_error_and_leaks_nothing(
    paths: tuple[Path, Path], short_dir: Path
) -> None:
    compositor, _ = paths
    before = fd_count()

    def script(peer: Peer) -> None:
        peer.handshake({MANAGER: 1})
        peer.linger()

    with Compositor(compositor, script), pytest.raises(WaylandError, match="cannot listen"):
        create(compositor, short_dir / "missing-directory" / "s.sock")
    assert fd_count() == before


def test_a_send_after_the_compositor_left_is_an_error(paths: tuple[Path, Path]) -> None:
    compositor, _ = paths
    with (
        Compositor(compositor, lambda _peer: None),
        wayland.Connection(compositor, 1) as connection,
    ):
        time.sleep(0.3)

        def send_twice() -> None:
            connection.send(b"\0" * 8192)  # the first may still be taken
            connection.send(b"\0" * 8192)  # a hung-up socket fails

        with pytest.raises(WaylandError, match=r"cannot send"):
            send_twice()


def test_encode_and_decode_agree() -> None:
    for text in ("a", "ab", "abc", "abcd", "valetkey-login", "naïve"):
        encoded = encode_string(text)
        assert len(encoded) % 4 == 0
        assert decode_string(encoded, 0) == (text, len(encoded))


def test_a_deadline_that_has_passed_is_not_waited_for(paths: tuple[Path, Path]) -> None:
    compositor, _ = paths
    with (
        Compositor(compositor, lambda peer: peer.linger()),
        wayland.Connection(compositor, 2) as connection,
        pytest.raises(WaylandError, match="did not answer in time"),
    ):
        connection.read(time.monotonic() - 1)
