# SPDX-License-Identifier: Apache-2.0
"""Fetch the pinned noVNC release that the login display serves.

    python tools/fetch_novnc.py [DESTINATION]

``tools/novnc.lock`` holds one line: the release, the SHA-256 of its tarball and where it comes
from. The tarball is downloaded, its digest is checked against the lock, and only then is a
fixed set of its files unpacked into DESTINATION (default: ``src/valetkey/novnc``). A digest that
does not match deletes nothing and unpacks nothing. Other files, and any path that leaves
DESTINATION, are ignored.

noVNC is licensed under the MPL 2.0 (its core) and other permissive licenses (some of its
libraries). ``LICENSE.txt``, ``AUTHORS`` and the license texts it names come with the files, and
the files themselves are not modified, so that the license applies to them as it is. The package
carries the same files and the same texts.
"""

import hashlib
import io
import shutil
import sys
import tarfile
import urllib.request
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

import conventional

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

LOCK = conventional.ROOT / "tools" / "novnc.lock"
DEFAULT_DESTINATION = conventional.ROOT / "src" / "valetkey" / "novnc"
KEEP_DIRECTORIES = ("app", "core", "vendor")
KEEP_FILES = ("vnc.html", "defaults.json", "mandatory.json", "LICENSE.txt", "AUTHORS")
KEEP_LICENSES = "docs"
"""Files in this directory named ``LICENSE*`` are kept: the texts ``LICENSE.txt`` refers to."""
TIMEOUT = 60


class FetchError(Exception):
    """The release could not be fetched, or is not the one that was pinned."""


@dataclass(frozen=True)
class Pin:
    """The release the lock names."""

    version: str
    sha256: str
    url: str


def parse_lock(text: str) -> Pin:
    """Parse the one line of the lock file: ``VERSION SHA256 URL``."""
    lines = [line for line in text.splitlines() if line.strip() and not line.startswith("#")]
    if len(lines) != 1:
        message = "the lock must have exactly one line: VERSION SHA256 URL"
        raise FetchError(message)
    parts = lines[0].split()
    if len(parts) != 3 or len(parts[1]) != 64 or not parts[2].startswith("https://"):  # noqa: PLR2004
        message = "the lock line must be: VERSION SHA256 (64 hex digits) HTTPS-URL"
        raise FetchError(message)
    try:
        int(parts[1], 16)
    except ValueError:
        message = "the SHA-256 in the lock is not hexadecimal"
        raise FetchError(message) from None
    return Pin(parts[0], parts[1].lower(), parts[2])


def wanted(parts: tuple[str, ...]) -> bool:
    """Tell whether the file at ``parts`` (below the release's top directory) is kept."""
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return False
    if len(parts) == 1:
        return parts[0] in KEEP_FILES
    if parts[0] == KEEP_LICENSES:
        return len(parts) == 2 and parts[1].startswith("LICENSE")  # noqa: PLR2004
    return parts[0] in KEEP_DIRECTORIES


def unpack(tarball: bytes, destination: Path) -> int:
    """Unpack the kept files of ``tarball`` into ``destination``; return how many.

    Only regular files are written. Links, devices and every path that is not one of the kept
    names are skipped, so a hostile archive cannot write elsewhere.
    """
    count = 0
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as archive:
        for member in archive:
            parts = PurePosixPath(member.name).parts[1:]  # drop the release's top directory
            if not member.isreg() or not wanted(parts):
                continue
            source = archive.extractfile(member)
            if source is None:  # pragma: no cover - a regular file always has a stream
                continue
            target = destination.joinpath(*parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read())
            count += 1
    return count


def download(url: str) -> bytes:
    """Return the body of ``url``."""
    with urllib.request.urlopen(url, timeout=TIMEOUT) as response:  # noqa: S310 - the lock is HTTPS
        return response.read()


def fetch(pin: Pin, destination: Path, fetcher: Callable[[str], bytes] = download) -> int:
    """Download, verify and unpack the pinned release into ``destination``; return the file count.

    ``destination`` is replaced only after the digest has matched.

    Raises:
        FetchError: when the digest does not match, or no file was kept.

    """
    tarball = fetcher(pin.url)
    digest = hashlib.sha256(tarball).hexdigest()
    if digest != pin.sha256:
        message = f"{pin.url} has SHA-256 {digest}, but the lock pins {pin.sha256}"
        raise FetchError(message)
    staging = destination.with_name(destination.name + ".new")
    shutil.rmtree(staging, ignore_errors=True)
    count = unpack(tarball, staging)
    if not (staging / "vnc.html").is_file():
        shutil.rmtree(staging, ignore_errors=True)
        message = "the release has no vnc.html where it was expected"
        raise FetchError(message)
    shutil.rmtree(destination, ignore_errors=True)
    staging.rename(destination)
    return count


def main(argv: list[str], lock: Path = LOCK, fetcher: Callable[[str], bytes] = download) -> int:
    """Fetch the pinned release into the destination named in ``argv`` (or the default)."""
    if len(argv) > 1:
        print(__doc__, file=sys.stderr)
        return 2
    destination = conventional.ROOT / argv[0] if argv else DEFAULT_DESTINATION
    try:
        pin = parse_lock(lock.read_text())
        count = fetch(pin, destination, fetcher)
    except (FetchError, OSError, tarfile.TarError) as error:
        print(f"fetch_novnc: {error}", file=sys.stderr)
        return 1
    print(f"noVNC {pin.version}: {count} files in {destination}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
