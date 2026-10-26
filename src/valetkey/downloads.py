# SPDX-License-Identifier: Apache-2.0
"""Find out what a site's browser has downloaded, without trusting what the page said.

The browser is started with ``downloads/<site>/.incoming/`` as its download directory (see
:mod:`valetkey.sessions`), a folder only the browser and the daemon use. Chromium turns whatever
name the page suggested into a plain file name there, and writes ``name.crdownload`` while the
download runs. The daemon, here, moves each finished file into ``downloads/<site>/`` under a name
that is free: ``name.ext``, then ``name (2).ext``, and so on. An earlier download is never
replaced, and a page cannot pick a name that lands anywhere else. Nothing is trusted from the
browser's side:

* The move claims the file by renaming it to a private name, then hard-links it into place and
  removes the claim. A link only succeeds if the name is free, so two moves at once, in this
  process or another, cannot collide. A symlink or anything else that is not a regular file is
  refused and removed, never followed.
* Whatever is in the incoming folder that is not a regular file (a symlink, a directory, a pipe)
  is removed each time the daemon files downloads, without following it, and one line is logged
  for each. It could only have been planted there, since the browser writes plain files.
* In the folder the person sees, only regular files directly in it are reported. A symlink is
  never followed and never reported, whatever it points at.
* The kind of a file is guessed from its first bytes (:func:`sniff_mime`), never from its name
  or from what the page claimed. A file is only read (its first bytes), never opened by anything,
  run, or given permissions.

A file that valetkey itself fetched for the agent (``browser_save``) is written into the folder
by :func:`put`, by the same rule: a name is taken only if it was free at that instant, an earlier
file is never replaced, and no link is followed. Its name comes from the address, through
:func:`file_name`, which leaves no path, no control character and no leading dot.

Files are compared by signature (inode, size and modification time). :func:`collect` waits a
bounded time for downloads that are running and for files that are still changing, and reports
what is still running as in progress.
"""

import contextlib
import itertools
import json
import logging
import mimetypes
import os
import shutil
import stat
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal
from urllib.parse import unquote, urlsplit

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

logger = logging.getLogger(__name__)

PARTIAL_SUFFIX = ".crdownload"
CLAIM_PREFIX = ".claim-"
_MAX_NAME_BYTES = 255
SETTLE_SECONDS = 0.5
"""How long to look for a download that has not started yet, right after a click."""
FINISH_SECONDS = 10.0
"""The longest to wait for downloads that are running."""
POLL_SECONDS = 0.2
_HEAD_BYTES = 2048
_TEXT_TYPES = (
    ("<!doctype html", "text/html"),
    ("<html", "text/html"),
    ("<?xml", "application/xml"),
    ("<svg", "image/svg+xml"),
)
_SIGNATURES = (
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"PK\x03\x04", "application/zip"),
    (b"\x1f\x8b", "application/gzip"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    (b"Rar!\x1a\x07", "application/vnd.rar"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage"),
    (b"\x7fELF", "application/x-executable"),
    (b"MZ", "application/x-msdownload"),
    (b"OggS", "audio/ogg"),
    (b"ID3", "audio/mpeg"),
)

type Signature = tuple[int, int, int]
"""Inode, size and modification time in nanoseconds."""


@dataclass(frozen=True, slots=True)
class Download:
    """One file in the downloads directory."""

    name: str
    path: Path
    size: int
    mime: str
    state: Literal["done", "in_progress"]


@dataclass(frozen=True, slots=True)
class Report:
    """What :func:`collect` found.

    ``new`` are finished files that were not there, or were different, when ``seen`` was taken.
    ``in_progress`` are downloads still running. ``everything`` is every finished file, new or
    not, for a full listing. ``seen`` is the state to pass next time.
    """

    new: list[Download]
    in_progress: list[Download]
    everything: list[Download]
    seen: dict[str, Signature]


@dataclass(frozen=True, slots=True)
class Clock:
    """Time, replaceable so waiting can be tested without waiting."""

    monotonic: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep


REAL_CLOCK = Clock()


def sniff_mime(head: bytes) -> str:
    """Guess a media type from the first bytes of a file.

    Binary formats are recognised by their signatures. Anything that is valid UTF-8 text is
    ``text/html``, ``application/xml``, ``image/svg+xml`` or ``application/json`` if it looks
    like one, and ``text/plain`` otherwise. Everything else is ``application/octet-stream``.
    """
    return _binary_type(head) or _text_type(head)


def _binary_type(head: bytes) -> str | None:
    for prefix, mime in _SIGNATURES:
        if head.startswith(prefix):
            return mime
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    if head[4:8] == b"ftyp":
        return "video/mp4"
    return None


def _text_type(head: bytes) -> str:
    try:
        text = head.decode("utf-8")
    except UnicodeDecodeError as error:
        if error.start < len(head) - 4:  # a character cut off at the very end is not an error
            return "application/octet-stream"
        text = head[: error.start].decode("utf-8")
    if "\x00" in text:
        return "application/octet-stream"
    lowered = text.lstrip().lower()
    for prefix, mime in _TEXT_TYPES:
        if lowered.startswith(prefix):
            return mime
    if lowered[:1] in {"{", "["}:
        with contextlib.suppress(ValueError):
            json.loads(text)
            return "application/json"
    return "text/plain"


def _read_head(path: Path) -> bytes | None:
    """Read the first bytes of a regular file, or ``None`` if it is anything else now.

    The file is opened without following a symlink and without blocking, and checked after it
    is open, so a file swapped for a link or a pipe between the listing and here is skipped.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return None
        return os.read(descriptor, _HEAD_BYTES)
    except OSError:
        return None
    finally:
        os.close(descriptor)


def scan(directory: Path) -> dict[str, tuple[Signature, int]]:
    """List the regular files directly in ``directory``: name to signature and size.

    A symlink, a directory, a pipe and anything else that is not a regular file is left out.
    A ``directory`` that is itself a symlink, or that is missing, lists nothing.
    """
    found: dict[str, tuple[Signature, int]] = {}
    try:
        if directory.is_symlink():
            return found
        entries = list(os.scandir(directory))
    except OSError:
        return found
    for entry in entries:
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode):
            found[entry.name] = ((info.st_ino, info.st_size, info.st_mtime_ns), info.st_size)
    return found


def _kind(mode: int) -> str:
    """Name what kind of entry ``mode`` is, for a log line."""
    if stat.S_ISLNK(mode):
        return "symbolic link"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISFIFO(mode):
        return "pipe"
    return "special file"


def clear_irregular(directory: Path) -> list[str]:
    """Remove every entry directly in ``directory`` that is not a regular file, and name them.

    A symlink is unlinked, never followed, so what it pointed at is untouched. A directory is
    removed with what is in it (``shutil.rmtree`` does not follow links either), and a pipe or
    another special file is unlinked. One line is logged for each. A ``directory`` that is itself
    a symlink, or is missing, is left alone. An entry that cannot be removed stays.
    """
    removed: list[str] = []
    try:
        if directory.is_symlink():
            return removed
        entries = list(os.scandir(directory))
    except OSError:
        return removed
    for entry in entries:
        try:
            mode = entry.stat(follow_symlinks=False).st_mode
            if stat.S_ISREG(mode):
                continue
            if stat.S_ISDIR(mode):
                shutil.rmtree(entry.path)
            else:
                Path(entry.path).unlink()
        except OSError:
            continue  # it vanished, or cannot be removed; either way there is nothing to follow
        logger.info("removed %r, a %s, from the incoming downloads folder", entry.name, _kind(mode))
        removed.append(entry.name)
    return removed


def _finished(directory: Path, name: str, size: int) -> Download | None:
    head = _read_head(directory / name)
    if head is None:
        return None
    return Download(name, directory / name, size, sniff_mime(head), "done")


def _running_download(directory: Path, name: str, size: int) -> Download:
    return Download(name, directory / name, size, "application/octet-stream", "in_progress")


def snapshot(directory: Path) -> dict[str, Signature]:
    """Return the signature of every file in ``directory``, to compare against later."""
    return {name: signature for name, (signature, _) in scan(directory).items()}


def _numbered(name: str, number: int) -> str:
    """Return ``name`` for 1 and ``name (2).ext`` and so on after, within the file name limit."""
    if number == 1:
        return name
    stem, dot, extension = name.rpartition(".")
    if not dot or not stem:
        stem, extension = name, ""
    else:
        extension = f".{extension}"
    tag = f" ({number})"
    room = _MAX_NAME_BYTES - len((tag + extension).encode())
    return stem.encode()[:room].decode(errors="ignore") + tag + extension


_NAME_BYTES = 200
"""The most bytes of a name :func:`file_name` makes, so a number can still be added to it."""
_EXTENSIONS = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/avif": ".avif",
    "image/svg+xml": ".svg",
    "video/mp4": ".mp4",
    "video/webm": ".webm",
    "application/pdf": ".pdf",
    "application/json": ".json",
    "text/html": ".html",
    "text/plain": ".txt",
}


_KNOWN = frozenset(_EXTENSIONS.values())


def file_name(url: str, mime: str) -> str:
    """Return a plain file name for what ``url`` serves, whose type is ``mime``.

    The last part of the address's path, decoded, with every path separator, control character
    and leading dot or space removed, cut to a safe length. Without an extension it gets the one
    that the type calls for. An address with no usable part gives ``download``.
    """
    segment = unquote(urlsplit(url).path).rstrip("/").rsplit("/", 1)[-1]
    name = "".join(c for c in segment if c.isprintable() and c not in "/\\").strip(" .")
    name = name.encode()[:_NAME_BYTES].decode(errors="ignore").strip(" .") or "download"
    kind = mime.split(";", maxsplit=1)[0].strip().lower()
    generic = kind in {"", "application/octet-stream"}  # says nothing about the file
    wanted = "" if generic else _EXTENSIONS.get(kind) or mimetypes.guess_extension(kind) or ""
    stem, dot, extension = name.rpartition(".")
    if not dot or not stem:
        return name + wanted
    given = {".jpeg": ".jpg"}.get(f".{extension.lower()}", f".{extension.lower()}")
    # An address says .jpg and the server sends AVIF, as a picture service that picks the format
    # does: the name follows what the file is, when the extension is one of the known ones.
    if wanted and given != wanted and given in _KNOWN:
        return stem + wanted
    return name


def put(directory: Path, name: str, data: bytes) -> Path:
    """Write ``data`` into ``directory`` as ``name``, or the first numbered name that is free.

    The bytes go to a private file beside ``directory`` (in its parent, which the browser cannot
    write) and are hard-linked into place, as in :func:`move_in`, so a name is only taken when it
    was free, an earlier file is never replaced and nothing is followed.
    """
    claim = directory.parent / f"{CLAIM_PREFIX}{uuid.uuid4().hex}"
    descriptor = os.open(claim, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as file:
            file.write(data)
        return _link_free(claim, directory, name)
    finally:
        claim.unlink(missing_ok=True)


def move_in(source: Path, directory: Path) -> Path | None:
    """Move the finished download ``source`` into ``directory`` under a free name.

    Returns the new path, or ``None`` when the file was refused: it is not a regular file (a
    symlink planted in the incoming folder is removed, never followed), it vanished, or it could
    not be linked. An existing file is never replaced.
    """
    claim = source.with_name(f"{CLAIM_PREFIX}{uuid.uuid4().hex}")
    try:
        source.rename(claim)  # one mover wins the file; a link is renamed, not followed
        info = claim.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode):
        claim.unlink(missing_ok=True)
        return None
    try:
        target = _link_free(claim, directory, source.name)
    except OSError:
        with contextlib.suppress(OSError):
            claim.rename(source)  # could not file it: leave it where it was, not lost
        return None
    claim.unlink(missing_ok=True)
    return target


def _link_free(claim: Path, directory: Path, name: str) -> Path:
    """Hard-link ``claim`` into ``directory`` as ``name``, or the first numbered name that is free.

    ``os.link`` fails when the name exists, whatever it is (a file, or a symlink, which it does
    not follow), so a name is only ever taken when it was free at that instant.
    """
    for number in itertools.count(1):
        target = directory / _numbered(name, number)
        try:
            os.link(claim, target, follow_symlinks=False)
        except FileExistsError:
            continue
        return target
    raise AssertionError  # pragma: no cover - the count never ends


def _intake(
    incoming: Path, directory: Path, previous: Mapping[str, Signature]
) -> tuple[dict[str, int], dict[str, Signature], bool]:
    """Move the files in ``incoming`` that have stopped changing into ``directory``.

    Returns the running downloads (name without ``.crdownload`` to size), the signatures seen
    now, and whether any finished-looking file was left because it changed since the last look.
    """
    clear_irregular(incoming)
    listing = scan(incoming)
    running = {
        name.removesuffix(PARTIAL_SUFFIX): size
        for name, (_, size) in listing.items()
        if name.endswith(PARTIAL_SUFFIX)
    }
    waiting = False
    for name, (signature, _) in listing.items():
        if name.endswith(PARTIAL_SUFFIX) or name.startswith(CLAIM_PREFIX):
            continue
        if previous.get(name) == signature:
            move_in(incoming / name, directory)
        else:
            waiting = True
    return running, {name: sig for name, (sig, _) in listing.items()}, waiting


def sweep(incoming: Path, directory: Path) -> None:
    """Move every finished file from ``incoming`` into ``directory``, at once.

    For when the browser is gone and nothing can still be changing: anything left that is not a
    partial download is a finished one. Entries that are not regular files are removed.
    """
    clear_irregular(incoming)
    for name in scan(incoming):
        if not name.endswith(PARTIAL_SUFFIX) and not name.startswith(CLAIM_PREFIX):
            move_in(incoming / name, directory)


def collect(  # noqa: PLR0913  # keyword-only knobs, each with a default
    directory: Path,
    seen: Mapping[str, Signature],
    *,
    incoming: Path | None = None,
    settle: float = 0.0,
    finish: float = FINISH_SECONDS,
    clock: Clock = REAL_CLOCK,
) -> Report:
    """Report what was downloaded into ``directory`` since ``seen`` was taken.

    Finished downloads in ``incoming`` are first moved into ``directory`` (see
    :func:`move_in`). If nothing has changed and nothing is running, look again after ``settle``
    seconds, because a download that was just triggered may not have started yet. If downloads
    are running, or a file is still changing, wait up to ``finish`` seconds. What is still
    running after that is reported as in progress, and is reported as new once it completes.
    """
    previous: dict[str, Signature] = {}
    running: dict[str, int] = {}
    waiting = False

    def look() -> dict[str, tuple[Signature, int]]:
        nonlocal previous, running, waiting
        if incoming is not None:
            running, previous, waiting = _intake(incoming, directory, previous)
        return scan(directory)

    listing = look()
    if settle and not _changed(listing, seen) and not running and not waiting:
        clock.sleep(settle)
        listing = look()
    deadline = clock.monotonic() + finish
    while (running or waiting) and clock.monotonic() < deadline:
        clock.sleep(min(POLL_SECONDS, max(deadline - clock.monotonic(), 0)))
        listing = look()
    everything, new = [], []
    for name, (signature, size) in sorted(listing.items()):
        item = _finished(directory, name, size)
        if item is not None:
            everything.append(item)
            if seen.get(name) != signature:
                new.append(item)
    in_progress = [
        _running_download(directory, name, size) for name, size in sorted(running.items())
    ]
    current = {d.name: listing[d.name][0] for d in everything}
    return Report(new, in_progress, everything, current)


def _changed(listing: Mapping[str, tuple[Signature, int]], seen: Mapping[str, Signature]) -> bool:
    return any(seen.get(name) != signature for name, (signature, _) in listing.items())
