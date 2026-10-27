# SPDX-License-Identifier: Apache-2.0

import os
import shutil
import stat
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from valetkey import daemon, notify, sites

pytest_plugins = ["pytester", "require_integration"]

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Iterator
    from typing import Any

_REAL_ANNOUNCE = daemon.announce_session
REAL_USER_SESSION = {
    name: os.environ[name]
    for name in ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")
    if name in os.environ
}
"""The person's own runtime directory and session bus, as they were before the tests replaced them.

Only a test that must talk to the systemd user manager, which is where ``systemd-run --user``
goes, takes them back, for that one command."""
REAL_NOTIFY_ASK = notify.ask


@pytest.fixture
def short_dir() -> Iterator[Path]:
    """A short temporary directory: Unix socket paths are limited to about 100 bytes."""
    with tempfile.TemporaryDirectory(prefix="vk-") as directory:
        yield Path(directory)


@pytest.fixture(scope="session")
def runtime_base() -> Iterator[str]:
    """A directory that holds the runtime directories of the tests, removed after the last one."""
    directory = tempfile.mkdtemp(prefix="vk-")
    yield directory
    shutil.rmtree(directory, ignore_errors=True)


SUFFIX_LIST = """\
// A small public suffix list for the tests: the real one is never read.
// ===BEGIN ICANN DOMAINS===
com
org
net
eu
se
io
uk
ac.uk
co.uk
gov.uk
ltd.uk
me.uk
org.uk
plc.uk
au
com.au
edu.au
gov.au
net.au
org.au
nz
co.nz
jp
co.jp
il
co.il
pl
com.pl
// ===BEGIN PRIVATE DOMAINS===
github.io
herokuapp.com
s3.amazonaws.com
"""
"""The list every test sees, so none depends on the one installed on the machine."""


@pytest.fixture(autouse=True)
def suffix_list(monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Point valetkey at a small public suffix list of the tests' own."""
    path = tmp_path_factory.mktemp("suffixes") / "list.dat"
    path.write_text(SUFFIX_LIST, encoding="utf-8")
    monkeypatch.setattr(sites, "PUBLIC_SUFFIX_LIST", path)
    return path


@pytest.fixture(autouse=True)
def runtime_dir(monkeypatch: pytest.MonkeyPatch, runtime_base: str) -> None:
    """Give every test a ``$XDG_RUNTIME_DIR`` of its own.

    A login session sets one and a container often does not, so the tests would otherwise differ
    by machine. Above all they must never reach a daemon that the person running them has
    started in the real one. The tests that need it gone delete it themselves. Nothing is removed
    per test, because a test may have replaced ``os.scandir``, which ``shutil.rmtree`` needs, by
    the time its fixtures are torn down.
    """
    monkeypatch.setenv("XDG_RUNTIME_DIR", tempfile.mkdtemp(prefix="r", dir=runtime_base))


@pytest.fixture(autouse=True)
def no_user_runtime_root(monkeypatch: pytest.MonkeyPatch, runtime_base: str) -> None:
    """Keep the tests away from the real ``/run/user/UID``, which a developer's machine has.

    Without ``XDG_RUNTIME_DIR``, valetkey falls back to it; the tests of that point the root at
    a directory of their own.
    """
    monkeypatch.setattr(sites, "USER_RUNTIME_ROOT", Path(runtime_base) / "no-run-user")


@pytest.fixture(autouse=True)
def announcements(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace the desktop notification of a started session, so no test sends a real one.

    The fixture returns the site names it was asked to announce.
    """
    sent: list[str] = []

    async def record(site: str) -> None:
        sent.append(site)

    monkeypatch.setattr(daemon, "announce_session", record)
    return sent


@pytest.fixture(autouse=True)
def no_notifications(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the tests from putting a question on the screen of a developer's desktop.

    The daemon asks with a desktop notification when nothing else can; here that finds nobody.
    The tests of :mod:`valetkey.notify` use the real function, ``REAL_NOTIFY_ASK``.
    """

    async def nobody(*_args: object, **_kwargs: object) -> str:
        return "none"

    monkeypatch.setattr(notify, "ask", nobody)


_GUARD = """#!/bin/sh
# Stands in for notify-send in the tests: it runs the real one only on a private session bus
# (a socket under the tests' own temporary directories), never on the person's.
case "$DBUS_SESSION_BUS_ADDRESS" in
  "unix:path=PRIVATE"*)
    path=${DBUS_SESSION_BUS_ADDRESS#unix:path=}
    if [ -S "$path" ]; then exec "REAL" "$@"; fi ;;
esac
printf '%s\\n' "notify-send on ${DBUS_SESSION_BUS_ADDRESS:-no session bus}: $*" >> "CALLS"
echo "notify-send is not allowed on a session bus the tests do not own" >&2
exit 1
"""


@pytest.fixture(scope="session")
def notify_guard(runtime_base: str) -> Path | None:
    """A directory with a ``notify-send`` that refuses any bus but a private one, or ``None``.

    The tests start daemons and sessions in other processes, which inherit the environment, so
    the guard has to be on ``PATH``, not a replaced function. It keeps its calls in ``calls``.
    """
    real = shutil.which("notify-send")
    if real is None:
        return None
    directory = Path(runtime_base) / "guard-bin"
    directory.mkdir()
    (directory / "calls").touch()
    script = (
        _GUARD.replace("PRIVATE", tempfile.gettempdir() + "/vk-")
        .replace("REAL", real)
        .replace("CALLS", str(directory / "calls"))
    )
    program = directory / "notify-send"
    program.write_text(script, encoding="utf-8")
    program.chmod(program.stat().st_mode | stat.S_IXUSR)
    return directory


@pytest.fixture(autouse=True)
def no_real_session_bus(
    monkeypatch: pytest.MonkeyPatch, runtime_base: str, notify_guard: Path | None
) -> Iterator[None]:
    """Keep every test process off the person's session bus, and fail a test that goes near it.

    A test that starts a daemon or a session in another process would otherwise inherit
    ``$DBUS_SESSION_BUS_ADDRESS`` and put a notification on the developer's desktop. The address
    points at nothing, so a daemon never fills it in from the systemd user manager either. The
    tests of a real notification daemon give their own, private one. A ``notify-send`` that would
    reach any other bus is stopped (see :func:`notify_guard`), and its call fails the test.
    """
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", f"unix:path={runtime_base}/no-session-bus")
    monkeypatch.setenv("DBUS_SYSTEM_BUS_ADDRESS", f"unix:path={runtime_base}/no-system-bus")
    before = ""
    if notify_guard is not None:
        monkeypatch.setenv("PATH", f"{notify_guard}{os.pathsep}{os.environ.get('PATH', '')}")
        before = (notify_guard / "calls").read_text(encoding="utf-8")
    yield
    if notify_guard is not None:
        calls = (notify_guard / "calls").read_text(encoding="utf-8")
        if calls != before:
            pytest.fail(f"a test notified on a session bus it does not own: {calls[len(before) :]}")


@pytest.fixture
def real_announce() -> Callable[..., Coroutine[Any, Any, None]]:
    """The real :func:`valetkey.daemon.announce_session`, which ``announcements`` replaces."""
    return _REAL_ANNOUNCE
