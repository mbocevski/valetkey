# SPDX-License-Identifier: Apache-2.0

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

pytest_plugins = ["pytester", "require_integration"]

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def short_dir() -> Iterator[Path]:
    """A short temporary directory: Unix socket paths are limited to about 100 bytes."""
    with tempfile.TemporaryDirectory(prefix="vk-") as directory:
        yield Path(directory)
