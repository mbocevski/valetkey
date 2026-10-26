# SPDX-License-Identifier: Apache-2.0

import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from valetkey import daemon, sites

pytest_plugins = ["pytester", "require_integration"]

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Iterator
    from typing import Any

_REAL_ANNOUNCE = daemon.announce_session


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


@pytest.fixture
def real_announce() -> Callable[..., Coroutine[Any, Any, None]]:
    """The real :func:`valetkey.daemon.announce_session`, which ``announcements`` replaces."""
    return _REAL_ANNOUNCE
