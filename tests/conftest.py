# SPDX-License-Identifier: Apache-2.0

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from valetkey import daemon

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
