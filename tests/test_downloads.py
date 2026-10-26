# SPDX-License-Identifier: Apache-2.0
import asyncio
import logging
import os
import re
import socket
import stat
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from environment import unusable_reason
from proxy_stub import PageServer

from valetkey import client, daemon, downloads, sites
from valetkey.downloads import Clock, Download, collect, scan, snapshot, sniff_mime

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Iterator

PDF = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n"


# -- what a file is, from its first bytes --------------------------------------------------


@pytest.mark.parametrize(
    ("head", "mime"),
    [
        (PDF, "application/pdf"),
        (b"\x89PNG\r\n\x1a\n\x00\x00", "image/png"),
        (b"\xff\xd8\xff\xe0\x00\x10JFIF", "image/jpeg"),
        (b"GIF89a\x01\x00", "image/gif"),
        (b"GIF87a\x01\x00", "image/gif"),
        (b"PK\x03\x04\x14\x00", "application/zip"),
        (b"\x1f\x8b\x08\x00", "application/gzip"),
        (b"7z\xbc\xaf\x27\x1c\x00\x04", "application/x-7z-compressed"),
        (b"Rar!\x1a\x07\x00", "application/vnd.rar"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00", "application/x-ole-storage"),
        (b"\x7fELF\x02\x01\x01", "application/x-executable"),
        (b"MZ\x90\x00\x03", "application/x-msdownload"),
        (b"OggS\x00\x02", "audio/ogg"),
        (b"ID3\x04\x00", "audio/mpeg"),
        (b"RIFF\x24\x00\x00\x00WEBPVP8 ", "image/webp"),
        (b"\x00\x00\x00\x18ftypmp42", "video/mp4"),
        (b"\x00\x00\x00\x1cftypisom\x00\x00\x02\x00isomiso2mp41", "video/mp4"),
        (b"\x00\x00\x00\x14ftypM4V \x00\x00\x00\x00", "video/mp4"),
        (b"\x00\x00\x00\x14ftypqt  \x00\x00\x00\x00", "video/mp4"),
        (b"\x00\x00\x00\x1cftypavif\x00\x00\x00\x00avifmif1miaf", "image/avif"),
        (b"\x00\x00\x00\x18ftypavis\x00\x00\x00\x00avismsf1", "image/avif"),
        (b"\x00\x00\x00\x1cftypmif1\x00\x00\x00\x00mif1miafavif", "image/avif"),
        (b"\x00\x00\x00\x1cftypmsf1\x00\x00\x00\x00msf1miafavis", "image/avif"),
        (b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1heic", "image/heic"),
        (b"\x00\x00\x00\x18ftypheix\x00\x00\x00\x00mif1heix", "image/heic"),
        (b"\x00\x00\x00\x18ftyphevc\x00\x00\x00\x00msf1hevc", "image/heic"),
        (b"\x00\x00\x00\x18ftypmif1\x00\x00\x00\x00mif1heic", "image/heic"),
        (b"\x00\x00\x00\x14ftypmif1\x00\x00\x00\x00", "image/heic"),
        (b"\x00\x00\x00\x14ftypmsf1\x00\x00\x00\x00", "image/heic"),
        (b"\x00\x00\x00\x10ftypmif1", "image/heic"),
        (b"\x00\x00\x00\x08ftypmif1", "image/heic"),
        (b"\x00\x00\x00\x00ftypmif1\x00\x00\x00\x00avif", "image/avif"),
        (b"\x00\x00\x01\x00ftypmif1\x00\x00\x00\x00mif1heic", "image/heic"),
        (b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mif1avif", "video/mp4"),
        (b"\x00\x00\x00\x0cftypav", "video/mp4"),
        (b"<!DOCTYPE html><title>x</title>", "text/html"),
        (b"  \n<html lang=en>", "text/html"),
        (b'<?xml version="1.0"?><a/>', "application/xml"),
        (b'<svg xmlns="http://www.w3.org/2000/svg"/>', "image/svg+xml"),
        (b'{"a": [1, 2]}', "application/json"),
        (b"[1, 2, 3]", "application/json"),
        (b"{not json", "text/plain"),
        (b"just some words\n", "text/plain"),
        (b"#!/bin/sh\necho hi\n", "text/plain"),
        (b"", "text/plain"),
        (b"\x00\x01\x02\x03 binary", "application/octet-stream"),
        (b"abc\xff\xfe\xfd\xfc\xfb\xfa", "application/octet-stream"),
        (b"text with a cut-off \xe2\x82", "text/plain"),
    ],
)
def test_sniff_mime_reads_the_content(head: bytes, mime: str) -> None:
    assert sniff_mime(head) == mime


def test_a_picture_in_the_video_container_is_listed_as_a_picture(tmp_path: Path) -> None:
    avif = b"\x00\x00\x00\x1cftypavif\x00\x00\x00\x00avifmif1miaf" + b"\x00" * 40
    heic = b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1heic" + b"\x00" * 40
    video = b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00isommp42" + b"\x00" * 40
    (tmp_path / "a.avif").write_bytes(avif)
    (tmp_path / "b.heic").write_bytes(heic)
    (tmp_path / "c.mp4").write_bytes(video)
    found = {d.name: d.mime for d in collect(tmp_path, {}).everything}
    assert found == {"a.avif": "image/avif", "b.heic": "image/heic", "c.mp4": "video/mp4"}


def test_the_name_and_the_claim_of_the_page_do_not_matter(tmp_path: Path) -> None:
    (tmp_path / "invoice.pdf").write_text("this is not a pdf", encoding="utf-8")
    (tmp_path / "notes.txt").write_bytes(PDF)
    found = {d.name: d.mime for d in collect(tmp_path, {}).everything}
    assert found == {"invoice.pdf": "text/plain", "notes.txt": "application/pdf"}


# -- looking at the directory ---------------------------------------------------------------


def test_only_regular_files_in_the_directory_are_listed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret", encoding="utf-8")
    box = tmp_path / "downloads"
    box.mkdir()
    (box / "real.txt").write_text("hello", encoding="utf-8")
    (box / "link.txt").symlink_to(outside / "secret.txt")
    (box / "dirlink").symlink_to(outside)
    (box / "dangling").symlink_to(tmp_path / "missing")
    (box / "subdir").mkdir()
    (box / "subdir" / "nested.txt").write_text("nested", encoding="utf-8")
    os.mkfifo(box / "pipe")
    assert sorted(scan(box)) == ["real.txt"]
    assert [d.name for d in collect(box, {}).everything] == ["real.txt"]
    assert "secret" not in str(collect(box, {}))


def test_a_directory_that_is_a_symlink_or_missing_lists_nothing(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (real / "a.txt").write_text("a", encoding="utf-8")
    (tmp_path / "linked").symlink_to(real)
    assert scan(tmp_path / "linked") == {}
    assert scan(tmp_path / "missing") == {}
    assert snapshot(tmp_path / "linked") == {}


def test_a_file_swapped_for_a_link_after_the_listing_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "secret").write_text("secret", encoding="utf-8")
    (tmp_path / "file.txt").write_text("hello", encoding="utf-8")
    real_scan = downloads.scan

    def scan_then_swap(directory: Path) -> Any:  # noqa: ANN401
        listing = real_scan(directory)
        (directory / "file.txt").unlink()
        (directory / "file.txt").symlink_to(directory / "secret")
        return listing

    monkeypatch.setattr(downloads, "scan", scan_then_swap)
    report = collect(tmp_path, {})
    assert [d.name for d in report.everything] == ["secret"]


def test_a_file_that_vanishes_or_becomes_a_pipe_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "gone.txt").write_text("x", encoding="utf-8")
    (tmp_path / "pipe.txt").write_text("x", encoding="utf-8")
    real_scan = downloads.scan

    def scan_then_change(directory: Path) -> Any:  # noqa: ANN401
        listing = real_scan(directory)
        (directory / "gone.txt").unlink()
        (directory / "pipe.txt").unlink()
        os.mkfifo(directory / "pipe.txt")
        return listing

    monkeypatch.setattr(downloads, "scan", scan_then_change)
    assert collect(tmp_path, {}).everything == []


def test_a_file_that_cannot_be_read_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")

    def broken(_descriptor: int, _size: int) -> bytes:
        raise OSError

    monkeypatch.setattr(downloads.os, "read", broken)
    assert collect(tmp_path, {}).everything == []


def test_an_entry_that_cannot_be_examined_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")

    class Broken:
        name = "b.txt"

        def stat(self, *, follow_symlinks: bool) -> Any:  # noqa: ANN401, ARG002
            raise PermissionError

    real = os.scandir
    monkeypatch.setattr(downloads.os, "scandir", lambda d: [*real(d), Broken()])
    assert sorted(scan(tmp_path)) == ["a.txt"]


def test_nothing_is_changed_by_looking(tmp_path: Path) -> None:
    path = tmp_path / "tool.sh"
    path.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    path.chmod(0o600)
    before = path.stat()
    collect(tmp_path, {})
    after = path.stat()
    assert stat.S_IMODE(after.st_mode) == 0o600
    assert after.st_mtime_ns == before.st_mtime_ns
    assert not after.st_mode & 0o111


def test_names_come_back_exactly_as_they_are_on_disk(tmp_path: Path) -> None:
    names = ["line1\nline2.txt", "a" * 200 + ".bin", 'quote".txt', "-dash.txt", " lead.txt"]
    for name in names:
        (tmp_path / name).write_text(name, encoding="utf-8")
    assert sorted(d.name for d in collect(tmp_path, {}).everything) == sorted(names)
    assert all(d.path.parent == tmp_path for d in collect(tmp_path, {}).everything)


# -- what is new ---------------------------------------------------------------------------


def test_new_files_are_those_not_seen_before(tmp_path: Path) -> None:
    (tmp_path / "old.txt").write_text("old", encoding="utf-8")
    seen = snapshot(tmp_path)
    assert collect(tmp_path, seen).new == []
    (tmp_path / "fresh.txt").write_text("fresh", encoding="utf-8")
    report = collect(tmp_path, seen)
    assert [d.name for d in report.new] == ["fresh.txt"]
    assert report.new[0] == Download("fresh.txt", tmp_path / "fresh.txt", 5, "text/plain", "done")
    assert [d.name for d in report.everything] == ["fresh.txt", "old.txt"]
    again = collect(tmp_path, report.seen)
    assert again.new == []


def test_a_file_replaced_by_a_later_download_counts_as_new(tmp_path: Path) -> None:
    path = tmp_path / "report.txt"
    path.write_text("first", encoding="utf-8")
    seen = snapshot(tmp_path)
    path.unlink()
    path.write_text("second one", encoding="utf-8")
    report = collect(tmp_path, seen)
    assert [(d.name, d.size) for d in report.new] == [("report.txt", 10)]


def test_a_file_changed_in_place_counts_as_new(tmp_path: Path) -> None:
    path = tmp_path / "report.txt"
    path.write_text("first", encoding="utf-8")
    seen = snapshot(tmp_path)
    path.write_text("a longer second", encoding="utf-8")
    assert [d.name for d in collect(tmp_path, seen).new] == ["report.txt"]


def test_files_that_were_deleted_drop_out_of_what_is_seen(tmp_path: Path) -> None:
    path = tmp_path / "a.txt"
    path.write_text("a", encoding="utf-8")
    seen = snapshot(tmp_path)
    path.unlink()
    assert collect(tmp_path, seen).seen == {}


# -- downloads that are still running ------------------------------------------------------


class FakeClock:
    def __init__(self, on_sleep: Any = None) -> None:  # noqa: ANN401
        self.now = 0.0
        self.sleeps: list[float] = []
        self.on_sleep = on_sleep

    def clock(self) -> Clock:
        return Clock(lambda: self.now, self.sleep)

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds
        if self.on_sleep is not None:
            self.on_sleep(self.now)


@pytest.fixture
def folders(tmp_path: Path) -> tuple[Path, Path]:
    """The folder people see, and the incoming folder the browser writes into."""
    box = tmp_path / "downloads"
    incoming = box / ".incoming"
    incoming.mkdir(parents=True)
    return box, incoming


def test_a_finished_download_is_filed_once_it_has_stopped_changing(
    folders: tuple[Path, Path],
) -> None:
    box, incoming = folders
    (incoming / "invoice.pdf").write_bytes(PDF)
    time = FakeClock()
    report = collect(box, {}, incoming=incoming, clock=time.clock())
    assert [(d.name, d.mime) for d in report.new] == [("invoice.pdf", "application/pdf")]
    assert list(incoming.iterdir()) == []
    assert (box / "invoice.pdf").read_bytes() == PDF
    assert time.sleeps  # it looked twice before trusting the size


def test_a_file_that_is_still_growing_is_not_filed_yet(folders: tuple[Path, Path]) -> None:
    box, incoming = folders
    path = incoming / "export.csv"
    path.write_bytes(b"a")
    grown = {"times": 0}

    def grow(_now: float) -> None:
        if grown["times"] < 2:
            grown["times"] += 1
            path.write_bytes(path.read_bytes() + b"b")

    time = FakeClock(grow)
    report = collect(box, {}, incoming=incoming, clock=time.clock())
    assert [d.name for d in report.new] == ["export.csv"]
    assert (box / "export.csv").read_bytes() == b"abb"
    assert len(time.sleeps) >= 3


def test_a_file_that_never_settles_stays_in_the_incoming_folder(folders: tuple[Path, Path]) -> None:
    box, incoming = folders
    path = incoming / "busy.bin"
    path.write_bytes(b"x")

    def always_changing(_now: float) -> None:
        path.write_bytes(path.read_bytes() + b"x")

    report = collect(
        box, {}, incoming=incoming, finish=1.0, clock=FakeClock(always_changing).clock()
    )
    assert report.new == []
    assert path.exists()
    assert list(box.iterdir()) == [incoming]


def test_a_running_download_is_waited_for_and_then_filed(folders: tuple[Path, Path]) -> None:
    box, incoming = folders
    (incoming / "big.bin.crdownload").write_bytes(b"x" * 10)

    def finish(now: float) -> None:
        if now >= 1.0 and (incoming / "big.bin.crdownload").exists():
            (incoming / "big.bin.crdownload").rename(incoming / "big.bin")

    time = FakeClock(finish)
    report = collect(box, {}, incoming=incoming, finish=10, clock=time.clock())
    assert [(d.name, d.state) for d in report.new] == [("big.bin", "done")]
    assert report.in_progress == []
    assert (box / "big.bin").exists()
    assert 1.0 <= time.now < 2.5


def test_a_download_still_running_when_the_time_is_up_is_reported_as_in_progress(
    folders: tuple[Path, Path],
) -> None:
    box, incoming = folders
    (incoming / "big.bin.crdownload").write_bytes(b"x" * 10)
    time = FakeClock()
    report = collect(box, {}, incoming=incoming, finish=1.0, clock=time.clock())
    assert report.new == []
    assert report.in_progress == [
        Download("big.bin", box / "big.bin", 10, "application/octet-stream", "in_progress")
    ]
    assert report.seen == {}
    assert time.now == pytest.approx(1.0)  # bounded: it did not wait longer
    (incoming / "big.bin.crdownload").rename(incoming / "big.bin")
    later = collect(box, report.seen, incoming=incoming, clock=FakeClock().clock())
    assert [d.name for d in later.new] == ["big.bin"]


def test_a_partial_file_is_never_read_or_typed_or_filed(folders: tuple[Path, Path]) -> None:
    box, incoming = folders
    (incoming / "x.pdf.crdownload").write_bytes(PDF)
    report = collect(box, {}, incoming=incoming, finish=0, clock=FakeClock().clock())
    assert report.in_progress[0].mime == "application/octet-stream"
    assert list(box.iterdir()) == [incoming]


def test_a_download_that_has_not_started_is_looked_for_once_after_the_settle_time(
    tmp_path: Path,
) -> None:
    def start(now: float) -> None:
        if now >= 0.5:
            (tmp_path / "late.txt").write_text("late", encoding="utf-8")

    time = FakeClock(start)
    report = collect(tmp_path, {}, settle=0.5, clock=time.clock())
    assert [d.name for d in report.new] == ["late.txt"]
    assert time.sleeps == [0.5]


def test_nothing_is_waited_for_when_something_already_arrived_or_settle_is_zero(
    tmp_path: Path,
) -> None:
    (tmp_path / "here.txt").write_text("here", encoding="utf-8")
    time = FakeClock()
    assert [d.name for d in collect(tmp_path, {}, settle=0.5, clock=time.clock()).new] == [
        "here.txt"
    ]
    assert time.sleeps == []
    quiet = FakeClock()
    collect(tmp_path, snapshot(tmp_path), clock=quiet.clock())
    assert quiet.sleeps == []


# -- filing a download, safely -------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "number", "expected"),
    [
        ("report.pdf", 1, "report.pdf"),
        ("report.pdf", 2, "report (2).pdf"),
        ("report.tar.gz", 3, "report.tar (3).gz"),
        ("README", 2, "README (2)"),
        (".bashrc", 2, ".bashrc (2)"),
        ("trailing.", 2, "trailing (2)."),
    ],
)
def test_numbered_names(name: str, number: int, expected: str) -> None:
    assert downloads._numbered(name, number) == expected  # noqa: SLF001


def test_a_numbered_name_stays_within_the_file_name_limit() -> None:
    long_name = "é" * 120 + ".txt"  # 244 bytes
    for number in (2, 10, 1000):
        numbered = downloads._numbered(long_name, number)  # noqa: SLF001
        assert len(numbered.encode()) <= 255
        assert numbered.endswith(f" ({number}).txt")


def test_a_download_never_replaces_an_earlier_one_of_the_same_name(
    folders: tuple[Path, Path],
) -> None:
    box, incoming = folders
    for body in ("first", "second", "third"):
        (incoming / "invoice.pdf").write_text(body, encoding="utf-8")
        assert downloads.move_in(incoming / "invoice.pdf", box) is not None
    names = sorted(p.name for p in box.iterdir() if p.is_file())
    assert names == ["invoice (2).pdf", "invoice (3).pdf", "invoice.pdf"]
    assert (box / "invoice.pdf").read_text(encoding="utf-8") == "first"
    assert (box / "invoice (2).pdf").read_text(encoding="utf-8") == "second"
    assert (box / "invoice (3).pdf").read_text(encoding="utf-8") == "third"
    assert list(incoming.iterdir()) == []


def test_a_name_taken_by_a_symlink_is_not_used_or_followed(
    folders: tuple[Path, Path], tmp_path: Path
) -> None:
    box, incoming = folders
    secret = tmp_path / "secret.txt"
    secret.write_text("original", encoding="utf-8")
    (box / "planted.txt").symlink_to(secret)
    (incoming / "planted.txt").write_text("downloaded", encoding="utf-8")
    moved = downloads.move_in(incoming / "planted.txt", box)
    assert moved == box / "planted (2).txt"
    assert moved.read_text(encoding="utf-8") == "downloaded"
    assert secret.read_text(encoding="utf-8") == "original"
    assert (box / "planted.txt").is_symlink()


def test_a_symlink_in_the_incoming_folder_is_refused_and_removed_not_followed(
    folders: tuple[Path, Path], tmp_path: Path
) -> None:
    box, incoming = folders
    secret = tmp_path / "secret.txt"
    secret.write_text("original", encoding="utf-8")
    (incoming / "evil.pdf").symlink_to(secret)
    (incoming / "dir.bin").symlink_to(tmp_path)
    assert downloads.move_in(incoming / "evil.pdf", box) is None
    assert downloads.move_in(incoming / "dir.bin", box) is None
    assert list(incoming.iterdir()) == []  # the links are gone
    assert [p.name for p in box.iterdir()] == [".incoming"]
    assert secret.read_text(encoding="utf-8") == "original"
    assert [p.name for p in tmp_path.iterdir() if p.name != "downloads"] == ["secret.txt"]


def test_a_symlink_planted_mid_session_is_refused_by_the_next_look(
    folders: tuple[Path, Path], tmp_path: Path
) -> None:
    box, incoming = folders
    secret = tmp_path / "secret.txt"
    secret.write_text("original", encoding="utf-8")
    (incoming / "real.txt").write_text("real", encoding="utf-8")
    (incoming / "planted.pdf").symlink_to(secret)
    report = collect(box, {}, incoming=incoming, clock=FakeClock().clock())
    assert [d.name for d in report.new] == ["real.txt"]
    assert not (box / "planted.pdf").exists()
    assert not (box / "planted.pdf").is_symlink()
    assert secret.read_text(encoding="utf-8") == "original"


def test_a_file_that_vanished_or_is_a_pipe_is_not_filed(folders: tuple[Path, Path]) -> None:
    box, incoming = folders
    assert downloads.move_in(incoming / "gone.txt", box) is None
    os.mkfifo(incoming / "pipe.txt")
    assert downloads.move_in(incoming / "pipe.txt", box) is None
    assert list(incoming.iterdir()) == []


def test_a_name_taken_between_the_check_and_the_link_is_skipped(
    folders: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Another process takes the free name just before our link: we must take the next one."""
    box, incoming = folders
    (incoming / "race.txt").write_text("ours", encoding="utf-8")
    real_link = os.link
    raced = {"done": False}

    def link_after_a_rival(src: Any, dst: Any, **kwargs: Any) -> None:  # noqa: ANN401
        if not raced["done"]:
            raced["done"] = True
            Path(dst).write_text("the rival", encoding="utf-8")
        real_link(src, dst, **kwargs)

    monkeypatch.setattr(downloads.os, "link", link_after_a_rival)
    moved = downloads.move_in(incoming / "race.txt", box)
    assert moved == box / "race (2).txt"
    assert (box / "race.txt").read_text(encoding="utf-8") == "the rival"
    assert moved.read_text(encoding="utf-8") == "ours"


def test_files_finishing_at_once_with_the_same_name_cannot_collide(
    folders: tuple[Path, Path],
) -> None:
    box, incoming = folders
    count = 24
    sources = []
    for number in range(count):
        folder = incoming / f"d{number}"
        folder.mkdir()
        (folder / "same.txt").write_text(f"body {number}", encoding="utf-8")
        sources.append(folder / "same.txt")
    start = threading.Barrier(count)
    results: list[Path | None] = []

    def mover(source: Path) -> None:
        start.wait()
        results.append(downloads.move_in(source, box))

    threads = [threading.Thread(target=mover, args=(s,)) for s in sources]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert None not in results
    assert len({r for r in results if r is not None}) == count
    bodies = sorted(p.read_text(encoding="utf-8") for p in box.iterdir() if p.is_file())
    assert bodies == sorted(f"body {n}" for n in range(count))


def test_two_movers_of_the_same_file_file_it_once(folders: tuple[Path, Path]) -> None:
    box, incoming = folders
    (incoming / "once.txt").write_text("only", encoding="utf-8")
    start = threading.Barrier(8)
    results: list[Path | None] = []

    def mover() -> None:
        start.wait()
        results.append(downloads.move_in(incoming / "once.txt", box))

    threads = [threading.Thread(target=mover) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert [r for r in results if r is not None] == [box / "once.txt"]
    assert sorted(p.name for p in box.iterdir() if p.is_file()) == ["once.txt"]


def test_a_file_that_cannot_be_linked_stays_where_it_was(
    folders: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    box, incoming = folders
    (incoming / "stuck.txt").write_text("keep me", encoding="utf-8")

    def refuse(*_args: Any, **_kwargs: Any) -> None:  # noqa: ANN401
        raise PermissionError

    monkeypatch.setattr(downloads.os, "link", refuse)
    assert downloads.move_in(incoming / "stuck.txt", box) is None
    assert (incoming / "stuck.txt").read_text(encoding="utf-8") == "keep me"
    assert sorted(p.name for p in incoming.iterdir()) == ["stuck.txt"]


def test_sweep_files_everything_that_is_finished(folders: tuple[Path, Path]) -> None:
    box, incoming = folders
    (incoming / "done.txt").write_text("done", encoding="utf-8")
    (incoming / "half.bin.crdownload").write_text("half", encoding="utf-8")
    (incoming / ".claim-abc").write_text("not ours to file", encoding="utf-8")
    downloads.sweep(incoming, box)
    assert (box / "done.txt").exists()
    assert sorted(p.name for p in incoming.iterdir()) == [".claim-abc", "half.bin.crdownload"]


def plant_everything(incoming: Path, outside: Path) -> None:
    """Put a link, a dangling link, a link to a directory, a directory, a pipe and a socket."""
    (incoming / "link.pdf").symlink_to(outside / "secret.txt")
    (incoming / "dangling").symlink_to(outside / "missing")
    (incoming / "dirlink").symlink_to(outside)
    (incoming / "folder").mkdir()
    (incoming / "folder" / "inner.txt").write_text("inner", encoding="utf-8")
    (incoming / "folder" / "inner-link").symlink_to(outside)
    os.mkfifo(incoming / "pipe")
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(incoming / "sock"))


@pytest.fixture
def outside(tmp_path: Path) -> Path:
    place = tmp_path / "outside"
    place.mkdir()
    (place / "secret.txt").write_text("original", encoding="utf-8")
    (place / "other.txt").write_text("other", encoding="utf-8")
    return place


def logged(caplog: pytest.LogCaptureFixture) -> dict[str, str]:
    """The entries the log says were removed from the incoming folder, with their kind."""
    found = [
        re.fullmatch(r"removed '(.*)', a (.*), from .*", r.getMessage()) for r in caplog.records
    ]
    assert all(found), [r.getMessage() for r in caplog.records]
    return {match[1]: match[2] for match in found if match}


def untouched(outside: Path) -> bool:
    return sorted(p.name for p in outside.iterdir()) == ["other.txt", "secret.txt"] and (
        (outside / "secret.txt").read_text(encoding="utf-8") == "original"
    )


def test_everything_that_is_not_a_regular_file_is_removed_without_being_followed(
    folders: tuple[Path, Path], outside: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _, incoming = folders
    plant_everything(incoming, outside)
    (incoming / "done.txt").write_text("done", encoding="utf-8")
    (incoming / "half.bin.crdownload").write_text("half", encoding="utf-8")
    (incoming / ".claim-abc").write_text("claimed", encoding="utf-8")
    with caplog.at_level(logging.INFO, logger="valetkey.downloads"):
        removed = downloads.clear_irregular(incoming)
    assert sorted(removed) == ["dangling", "dirlink", "folder", "link.pdf", "pipe", "sock"]
    assert sorted(p.name for p in incoming.iterdir()) == [
        ".claim-abc",
        "done.txt",
        "half.bin.crdownload",
    ]
    assert untouched(outside)
    assert logged(caplog) == {
        "link.pdf": "symbolic link",
        "dangling": "symbolic link",
        "dirlink": "symbolic link",
        "folder": "directory",
        "pipe": "pipe",
        "sock": "special file",
    }
    assert len(caplog.records) == 6  # one line for each


def test_a_clear_folder_logs_nothing(
    folders: tuple[Path, Path], caplog: pytest.LogCaptureFixture
) -> None:
    _, incoming = folders
    (incoming / "done.txt").write_text("done", encoding="utf-8")
    with caplog.at_level(logging.INFO, logger="valetkey.downloads"):
        assert downloads.clear_irregular(incoming) == []
    assert caplog.records == []


def test_a_folder_that_is_a_symlink_or_missing_is_left_alone(tmp_path: Path, outside: Path) -> None:
    (outside / "planted").symlink_to(outside / "secret.txt")
    linked = tmp_path / "linked"
    linked.symlink_to(outside)
    assert downloads.clear_irregular(linked) == []
    assert downloads.clear_irregular(tmp_path / "missing") == []
    assert (outside / "planted").is_symlink()


def test_an_entry_that_cannot_be_removed_stays_and_is_not_reported(
    folders: tuple[Path, Path], outside: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, incoming = folders
    (incoming / "link.pdf").symlink_to(outside / "secret.txt")

    def refuse(_path: object, **_options: object) -> None:
        raise PermissionError

    monkeypatch.setattr(Path, "unlink", refuse)
    assert downloads.clear_irregular(incoming) == []
    assert (incoming / "link.pdf").is_symlink()


def test_a_link_planted_mid_session_is_gone_after_the_next_download(
    folders: tuple[Path, Path], outside: Path, caplog: pytest.LogCaptureFixture
) -> None:
    box, incoming = folders
    (incoming / "first.txt").write_text("first", encoding="utf-8")
    first = collect(box, {}, incoming=incoming, clock=FakeClock().clock())
    assert [d.name for d in first.new] == ["first.txt"]
    (incoming / "planted.pdf").symlink_to(outside / "secret.txt")  # the session goes on
    (incoming / "second.txt").write_text("second", encoding="utf-8")
    with caplog.at_level(logging.INFO, logger="valetkey.downloads"):
        second = collect(box, first.seen, incoming=incoming, clock=FakeClock().clock())
    assert [d.name for d in second.new] == ["second.txt"]
    assert list(incoming.iterdir()) == []
    assert not (box / "planted.pdf").exists()
    assert untouched(outside)
    assert logged(caplog) == {"planted.pdf": "symbolic link"}


def test_sweep_also_removes_what_is_not_a_regular_file(
    folders: tuple[Path, Path], outside: Path
) -> None:
    box, incoming = folders
    plant_everything(incoming, outside)
    (incoming / "done.txt").write_text("done", encoding="utf-8")
    downloads.sweep(incoming, box)
    assert list(incoming.iterdir()) == []
    assert (box / "done.txt").exists()
    assert untouched(outside)


def test_the_real_clock_is_the_default() -> None:
    assert downloads.REAL_CLOCK.monotonic() > 0
    downloads.REAL_CLOCK.sleep(0)


# -- a real browser, through the daemon ----------------------------------------------------

_SKIP_REASON = unusable_reason("bwrap", "chromium", "agent-browser")
needs_everything = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")

BODY = b"the invoice, line by line\n"
TRICKS = {
    "/dotdot": 'attachment; filename="../evil.txt"',
    "/absolute": 'attachment; filename="/tmp/valetkey-should-not-exist/abs.txt"',
    "/dots": 'attachment; filename=".."',
    "/threedots": 'attachment; filename="..."',
    "/newline": "attachment; filename*=UTF-8''line1%0Aline2.txt",
    "/backslash": 'attachment; filename="..\\\\evil2.txt"',
    "/hidden": 'attachment; filename=".bashrc"',
    "/script": 'attachment; filename="run.sh"',
    "/planted": 'attachment; filename="planted.txt"',
    "/long": 'attachment; filename="' + "x" * 300 + '.txt"',
}
FILES = {
    "/first": (
        {"Content-Type": "text/plain", "Content-Disposition": 'attachment; filename="same.txt"'},
        b"the first body\n",
    ),
    "/second": (
        {"Content-Type": "text/plain", "Content-Disposition": 'attachment; filename="same.txt"'},
        b"the second body\n",
    ),
    "/invoice": (
        {
            "Content-Type": "application/pdf",
            "Content-Disposition": 'attachment; filename="invoice.txt"',
        },
        BODY,
    ),
    "/really-a-pdf": (
        {"Content-Type": "text/plain", "Content-Disposition": 'attachment; filename="notes.txt"'},
        PDF,
    ),
    **{
        path: (
            {"Content-Type": "text/plain", "Content-Disposition": value},
            f"payload {path}\n".encode(),
        )
        for path, value in TRICKS.items()
    },
}
INDEX = "<h1>Files</h1>" + "".join(f'<a href="{path}">{path}</a><br>' for path in FILES)


@pytest.fixture
def world(short_dir: Path) -> Iterator[tuple[sites.Roots, PageServer]]:
    runtime = short_dir / "rt"
    runtime.mkdir(mode=0o700)
    roots = sites.Roots(short_dir / "cfg", short_dir / "state", runtime)
    sites.save_policy(roots, sites.Policy("demo", "http://site.test/", ("site.test",)))
    with PageServer({"/": INDEX}, files=FILES) as pages:
        yield roots, pages


async def start_daemon(roots: sites.Roots, pages: PageServer) -> daemon.Daemon:
    async def resolve(_host: str, _port: int) -> list[str]:
        return ["127.0.0.1"]

    async def connect(_address: str, _port: int) -> Any:  # noqa: ANN401
        return await asyncio.open_connection(*pages.address)

    options = {"resolver": resolve, "connector": connect, "address_check": lambda _a: None}
    server = daemon.Daemon(roots, proxy_options=options)
    await server.start()
    return server


def run[T](scenario: Any) -> T:  # noqa: ANN401 - any awaitable
    return asyncio.run(asyncio.wait_for(scenario, 180))


async def session(roots: sites.Roots, pages: PageServer) -> AsyncGenerator[Any]:
    server = await start_daemon(roots, pages)
    try:
        async with await client.Client.connect(client.socket_path(roots)) as c:
            await c.call("open", site="demo")
            yield c
    finally:
        await server.shutdown()


@pytest.mark.integration
@needs_everything
def test_a_click_that_downloads_returns_the_path_and_the_file_has_the_bytes(
    world: tuple[sites.Roots, PageServer],
) -> None:
    roots, pages = world
    folder = sites.downloads_path(roots, "demo")

    async def scenario() -> None:
        async for c in session(roots, pages):
            await c.call("snapshot", site="demo")
            got = await c.call("click", site="demo", text="/invoice", role="link")
            (item,) = got["downloads"]["new"]
            path = Path(item["path"]["text"])
            assert path == folder / "invoice.txt"
            content, mode = file_facts(path)
            assert content == BODY
            assert item["size"] == len(BODY)
            # The page said application/pdf; the bytes say text.
            assert item["mime"] == "text/plain"
            assert got["downloads"]["in_progress"] == []
            assert not mode & 0o111

            pdf = await c.call("click", site="demo", text="/really-a-pdf", role="link")
            assert [e["mime"] for e in pdf["downloads"]["new"]] == ["application/pdf"]

            # The same file again does not replace the first one.
            again = await c.call("click", site="demo", text="/invoice", role="link")
            assert [Path(e["path"]["text"]).name for e in again["downloads"]["new"]] == [
                "invoice (2).txt"
            ]
            listing = await c.call("downloads", site="demo")
            assert names_in(listing) == ["invoice (2).txt", "invoice.txt", "notes.txt"]
            assert not any(f["new"] for f in listing["files"])

    run(scenario())


def file_facts(path: Path) -> tuple[bytes, int]:
    return path.read_bytes(), path.stat().st_mode


def is_plain_file_in(path: Path, folder: Path) -> bool:
    """A regular file directly in ``folder``, not a link, with no execute bit."""
    return (
        path.parent == folder
        and path.is_file()
        and not path.is_symlink()
        and not path.stat().st_mode & 0o111
    )


def names_in(listing: dict[str, Any]) -> list[str]:
    return sorted(Path(f["path"]["text"]).name for f in listing["files"])


@pytest.mark.integration
@needs_everything
def test_a_navigation_to_an_attachment_is_reported_as_a_download(
    world: tuple[sites.Roots, PageServer],
) -> None:
    roots, pages = world

    async def scenario() -> None:
        async for c in session(roots, pages):
            result = await c.call("navigate", site="demo", url="http://site.test/invoice")
            assert result["download_only"] is True
            assert [Path(e["path"]["text"]).name for e in result["downloads"]["new"]] == [
                "invoice.txt"
            ]
            assert names_in(await c.call("downloads", site="demo")) == ["invoice.txt"]

    run(scenario())


def plant(folder: Path, outside: Path) -> Path:
    """Put links in the downloads folder: one a download will use, one it will not."""
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("original", encoding="utf-8")
    (folder / "planted.txt").symlink_to(secret)
    (folder / "decoy.txt").symlink_to("/etc/hostname")
    return secret


def check_outcome(folder: Path, outside: Path, secret: Path) -> None:
    assert secret.read_text(encoding="utf-8") == "original"
    assert sorted(p.name for p in folder.parent.iterdir()) == ["demo"]
    assert not Path("/tmp/valetkey-should-not-exist").exists()  # noqa: S108 - a path the page named
    assert not (folder.parent / "evil.txt").exists()
    assert not (folder.parent.parent / "evil.txt").exists()
    # The links are still there, still pointing where they did, and nothing followed them.
    assert (folder / "planted.txt").is_symlink()
    assert (folder / "decoy.txt").is_symlink()
    assert list(outside.iterdir()) == [secret]


@pytest.mark.integration
@needs_everything
def test_path_tricks_land_inside_the_site_folder_and_nothing_escapes(
    world: tuple[sites.Roots, PageServer],
) -> None:
    roots, pages = world
    folder = sites.downloads_path(roots, "demo")
    outside = roots.state.parent / "outside"
    planted: list[Path] = []

    async def scenario() -> None:
        async for c in session(roots, pages):
            planted.append(plant(folder, outside))
            await c.call("snapshot", site="demo")
            reported: list[Path] = []
            unsaved: dict[str, int] = {}
            for path in TRICKS:
                got = await c.call("click", site="demo", text=path, role="link")
                reported += [Path(e["path"]["text"]) for e in got["downloads"]["new"]]
                unsaved[path] = got["downloads"]["unsaved"]
            # The page named a 300-character file; the browser wrote nothing, and we say so.
            assert unsaved["/long"] == 1
            assert sum(unsaved.values()) == 1
            listing = await c.call("downloads", site="demo")
            reported += [Path(f["path"]["text"]) for f in listing["files"]]
            assert reported
            for path in reported:
                assert is_plain_file_in(path, folder), path
            names = {path.name for path in reported}
            assert not names & {"decoy.txt", "planted.txt"}  # a link is never followed or reported
            assert "planted (2).txt" in names  # the name held by a link was not used
            assert "evil.txt" not in names
            assert not any("/" in name or name in {"", ".", ".."} for name in names)
            assert len(names) >= 6

    run(scenario())
    check_outcome(folder, outside, planted[0])


def _listing(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.iterdir())


def _bodies(folder: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in folder.iterdir() if p.is_file()}


@pytest.mark.integration
@needs_everything
def test_two_downloads_with_the_same_name_both_survive(
    world: tuple[sites.Roots, PageServer],
) -> None:
    roots, pages = world
    folder = sites.downloads_path(roots, "demo")

    async def scenario() -> None:
        async for c in session(roots, pages):
            await c.call("snapshot", site="demo")
            first = await c.call("click", site="demo", text="/first", role="link")
            second = await c.call("click", site="demo", text="/second", role="link")
            names = [Path(e["path"]["text"]).name for e in first["downloads"]["new"]]
            names += [Path(e["path"]["text"]).name for e in second["downloads"]["new"]]
            assert names == ["same.txt", "same (2).txt"]
            third = await c.call("click", site="demo", text="/first", role="link")
            assert [Path(e["path"]["text"]).name for e in third["downloads"]["new"]] == [
                "same (3).txt"
            ]
            listing = await c.call("downloads", site="demo")
            assert names_in(listing) == ["same (2).txt", "same (3).txt", "same.txt"]
            assert not any(".incoming" in str(f) for f in listing["files"])

    run(scenario())
    bodies = _bodies(folder)
    assert bodies["same.txt"] == b"the first body\n"
    assert bodies["same (2).txt"] == b"the second body\n"
    assert bodies["same (3).txt"] == b"the first body\n"
    assert ".incoming" in _listing(folder)  # still there, and never listed as a download


@pytest.mark.integration
@needs_everything
def test_a_link_planted_in_the_incoming_folder_mid_session_is_not_followed(
    world: tuple[sites.Roots, PageServer],
) -> None:
    roots, pages = world
    folder = sites.downloads_path(roots, "demo")
    incoming = folder / ".incoming"
    secret = roots.state.parent / "secret.txt"
    secret.write_text("original", encoding="utf-8")

    async def scenario() -> None:
        async for c in session(roots, pages):
            (incoming / "evil.pdf").symlink_to(secret)
            (incoming / "evil-dir").symlink_to(roots.state.parent)
            await c.call("snapshot", site="demo")
            got = await c.call("click", site="demo", text="/invoice", role="link")
            assert [Path(e["path"]["text"]).name for e in got["downloads"]["new"]] == [
                "invoice.txt"
            ]
            listing = await c.call("downloads", site="demo")
            assert names_in(listing) == ["invoice.txt"]

    run(scenario())
    assert secret.read_text(encoding="utf-8") == "original"
    assert "evil.pdf" not in _listing(folder)
    assert "evil-dir" not in _listing(folder)


# -- naming and writing a file valetkey fetched ------------------------------------------------


@pytest.mark.parametrize(
    ("url", "mime", "name"),
    [
        ("https://x.test/img/photo.png", "image/png", "photo.png"),
        ("https://x.test/img/photo", "image/png", "photo.png"),
        ("https://x.test/img/photo.jpg", "image/avif", "photo.avif"),
        ("https://x.test/img/photo.jpg", "image/heic", "photo.heic"),
        ("https://x.test/img/photo", "image/heic", "photo.heic"),
        ("https://x.test/img/photo.heif", "image/heic", "photo.heif"),
        ("https://x.test/img/photo.jpeg", "image/jpeg", "photo.jpeg"),
        ("https://x.test/img/photo.jpg", "image/jpeg; charset=x", "photo.jpg"),
        ("https://x.test/a/my%20file.PDF", "application/pdf", "my file.PDF"),
        ("https://x.test/a/data.bin", "image/png", "data.bin"),
        ("https://x.test/a/readme.txt", "application/octet-stream", "readme.txt"),
        ("https://x.test/a/unknown", "application/octet-stream", "unknown"),
        ("https://x.test/a/v", "application/x-odd-type", "v"),
        ("https://x.test/a/doc.v2", "text/html", "doc.v2"),
        ("https://x.test/", "image/png", "download.png"),
        ("https://x.test", "", "download"),
        ("https://x.test/a/.hidden", "text/plain", "hidden.txt"),
        ("https://x.test/a/.png", "image/png", "png.png"),
        ("https://x.test/a/..%2F..%2Fetc%2Fpasswd", "text/plain", "passwd.txt"),
        ("https://x.test/a/x%5Cy%00z%0A.png", "image/png", "xyz.png"),
        ("https://x.test/a/%20%20.%20", "image/png", "download.png"),
        ("https://x.test/a/dir/", "image/png", "dir.png"),
        ("https://x.test/a/fit=contain,width=640/pic.jpg", "image/avif", "pic.avif"),
    ],
)
def test_a_fetched_file_is_named_from_its_address_and_type(url: str, mime: str, name: str) -> None:
    assert downloads.file_name(url, mime) == name


def test_a_very_long_name_is_cut_with_room_for_a_number() -> None:
    name = downloads.file_name("https://x.test/" + "é" * 500 + ".png", "image/png")
    assert len(name.encode()) <= downloads._NAME_BYTES + len(".png")  # noqa: SLF001
    assert name.endswith(".png")
    name.encode()  # whole characters only


def test_put_writes_a_file_and_leaves_no_claim_behind(tmp_path: Path) -> None:
    folder = tmp_path / "downloads"
    folder.mkdir()
    path = downloads.put(folder, "a.png", PDF)
    assert path == folder / "a.png"
    assert path.read_bytes() == PDF
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert [p.name for p in tmp_path.iterdir()] == ["downloads"]


def test_put_numbers_a_name_that_is_taken_and_never_replaces_a_file(tmp_path: Path) -> None:
    folder = tmp_path / "downloads"
    folder.mkdir()
    (folder / "a.png").write_bytes(b"first")
    second = downloads.put(folder, "a.png", b"second")
    third = downloads.put(folder, "a.png", b"third")
    assert [p.name for p in (second, third)] == ["a (2).png", "a (3).png"]
    assert (folder / "a.png").read_bytes() == b"first"
    assert second.read_bytes() == b"second"


def test_put_does_not_follow_a_link_the_browser_left_in_the_folder(tmp_path: Path) -> None:
    folder = tmp_path / "downloads"
    folder.mkdir()
    target = tmp_path / "secret"
    target.write_bytes(b"keep")
    (folder / "a.png").symlink_to(target)
    path = downloads.put(folder, "a.png", b"new")
    assert path.name == "a (2).png"
    assert target.read_bytes() == b"keep"


def test_put_cleans_up_when_the_name_cannot_be_taken(tmp_path: Path) -> None:
    with pytest.raises(OSError):  # noqa: PT011 - the folder does not exist
        downloads.put(tmp_path / "missing", "a.png", b"x")
    assert list(tmp_path.iterdir()) == []
