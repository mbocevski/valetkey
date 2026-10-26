# SPDX-License-Identifier: Apache-2.0
import hashlib
import io
import tarfile
import urllib.request
from typing import TYPE_CHECKING, Self

import conventional
import fetch_novnc
import pytest

if TYPE_CHECKING:
    from pathlib import Path
    from types import TracebackType

TOP = "noVNC-9.9.9"


def make_tarball(files: dict[str, bytes], *, extra: list[tarfile.TarInfo] | None = None) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(f"{TOP}/{name}")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        for info in extra or []:
            archive.addfile(info)
    return buffer.getvalue()


FILES = {
    "vnc.html": b"<html>",
    "LICENSE.txt": b"MPL",
    "AUTHORS": b"people",
    "defaults.json": b"{}",
    "mandatory.json": b"{}",
    "app/ui.js": b"ui",
    "core/rfb.js": b"rfb",
    "vendor/pako/LICENSE": b"MIT",
    "docs/LICENSE.MPL-2.0": b"text",
    "docs/LICENSE.BSD-3-Clause": b"text",
    "docs/README.md": b"not kept",
    "docs/sub/LICENSE.x": b"not kept",
    "tests/unit.js": b"not kept",
    "package.json": b"not kept",
    "README.md": b"not kept",
}
KEPT = {
    "vnc.html",
    "LICENSE.txt",
    "AUTHORS",
    "defaults.json",
    "mandatory.json",
    "app/ui.js",
    "core/rfb.js",
    "vendor/pako/LICENSE",
    "docs/LICENSE.MPL-2.0",
    "docs/LICENSE.BSD-3-Clause",
}


def pin_for(tarball: bytes) -> fetch_novnc.Pin:
    return fetch_novnc.Pin(
        "v9.9.9", hashlib.sha256(tarball).hexdigest(), "https://example.org/n.tgz"
    )


def listed(directory: Path) -> set[str]:
    return {str(p.relative_to(directory)) for p in directory.rglob("*") if p.is_file()}


def test_the_lock_of_this_repository_is_one_valid_line() -> None:
    pin = fetch_novnc.parse_lock(fetch_novnc.LOCK.read_text())
    assert pin.version.startswith("v")
    assert pin.url.startswith("https://")
    assert len(pin.sha256) == 64


def test_parse_lock_reads_version_digest_and_url() -> None:
    digest = "a" * 64
    pin = fetch_novnc.parse_lock(f"# a comment\n\nv1.2.3 {digest.upper()} https://x.test/a.tgz\n")
    assert pin == fetch_novnc.Pin("v1.2.3", digest, "https://x.test/a.tgz")


@pytest.mark.parametrize(
    "text",
    [
        "",
        "# only a comment\n",
        f"v1 {'a' * 64} https://x/a\nv2 {'b' * 64} https://x/b\n",
        "v1 abc https://x/a\n",
        f"v1 {'a' * 64} http://x/a\n",
        f"v1 {'a' * 64}\n",
        f"v1 {'g' * 64} https://x/a\n",
    ],
)
def test_parse_lock_refuses_anything_else(text: str) -> None:
    with pytest.raises(fetch_novnc.FetchError):
        fetch_novnc.parse_lock(text)


@pytest.mark.parametrize(
    ("parts", "kept"),
    [
        (("vnc.html",), True),
        (("README.md",), False),
        (("app", "ui.js"), True),
        (("core", "a", "b.js"), True),
        (("vendor", "pako", "x.js"), True),
        (("tests", "x.js"), False),
        (("docs", "LICENSE.MPL-2.0"), True),
        (("docs", "README.md"), False),
        (("docs", "sub", "LICENSE.x"), False),
        ((), False),
        (("app", "..", "x"), False),
        (("..", "app"), False),
        (("app", "", "x"), False),
    ],
)
def test_only_the_files_the_display_needs_are_kept(parts: tuple[str, ...], *, kept: bool) -> None:
    assert fetch_novnc.wanted(parts) is kept


def test_unpack_writes_only_the_kept_files(tmp_path: Path) -> None:
    count = fetch_novnc.unpack(make_tarball(FILES), tmp_path / "out")
    assert count == len(KEPT)
    assert listed(tmp_path / "out") == KEPT
    assert (tmp_path / "out" / "core" / "rfb.js").read_bytes() == b"rfb"


def test_unpack_skips_links_and_paths_that_leave_the_directory(tmp_path: Path) -> None:
    link = tarfile.TarInfo(f"{TOP}/app/link.js")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    escape = tarfile.TarInfo(f"{TOP}/app/../../escape.js")
    escape.size = 1
    tarball = make_tarball({"vnc.html": b"x"}, extra=[link])
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        archive.addfile(escape, io.BytesIO(b"x"))
        archive.addfile(tarfile.TarInfo("loose-file"), io.BytesIO(b""))
    assert fetch_novnc.unpack(tarball, tmp_path / "out") == 1
    assert fetch_novnc.unpack(buffer.getvalue(), tmp_path / "out2") == 0
    assert listed(tmp_path / "out") == {"vnc.html"}
    assert not (tmp_path / "escape.js").exists()


def test_fetch_checks_the_digest_before_it_unpacks_anything(tmp_path: Path) -> None:
    tarball = make_tarball(FILES)
    pin = fetch_novnc.Pin("v9.9.9", "0" * 64, "https://example.org/n.tgz")
    destination = tmp_path / "novnc"
    destination.mkdir()
    (destination / "old.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(fetch_novnc.FetchError, match=f"pins {'0' * 64}"):
        fetch_novnc.fetch(pin, destination, lambda _url: tarball)
    assert listed(destination) == {"old.txt"}
    assert not (tmp_path / "novnc.new").exists()


def test_fetch_replaces_the_destination_once_the_digest_matches(tmp_path: Path) -> None:
    tarball = make_tarball(FILES)
    destination = tmp_path / "novnc"
    destination.mkdir()
    (destination / "old.txt").write_text("gone", encoding="utf-8")
    asked: list[str] = []

    def fetcher(url: str) -> bytes:
        asked.append(url)
        return tarball

    assert fetch_novnc.fetch(pin_for(tarball), destination, fetcher) == len(KEPT)
    assert asked == ["https://example.org/n.tgz"]
    assert listed(destination) == KEPT
    assert not (tmp_path / "novnc.new").exists()


def test_fetch_refuses_a_release_without_the_viewer(tmp_path: Path) -> None:
    tarball = make_tarball({"AUTHORS": b"x"})
    destination = tmp_path / "novnc"
    with pytest.raises(fetch_novnc.FetchError, match=r"no vnc\.html"):
        fetch_novnc.fetch(pin_for(tarball), destination, lambda _url: tarball)
    assert not destination.exists()
    assert not (tmp_path / "novnc.new").exists()


def lock_file(tmp_path: Path, tarball: bytes) -> Path:
    pin = pin_for(tarball)
    path = tmp_path / "novnc.lock"
    path.write_text(f"{pin.version} {pin.sha256} {pin.url}\n", encoding="utf-8")
    return path


def test_main_fetches_into_the_destination_it_is_given(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    tarball = make_tarball(FILES)
    monkeypatch.setattr(conventional, "ROOT", tmp_path)
    status = fetch_novnc.main(["out"], lock_file(tmp_path, tarball), lambda _url: tarball)
    assert status == 0
    assert f"noVNC v9.9.9: {len(KEPT)} files in {tmp_path / 'out'}" in capsys.readouterr().out
    assert listed(tmp_path / "out") == KEPT


def test_main_defaults_to_the_directory_next_to_the_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tarball = make_tarball(FILES)
    monkeypatch.setattr(fetch_novnc, "DEFAULT_DESTINATION", tmp_path / "default")
    assert fetch_novnc.main([], lock_file(tmp_path, tarball), lambda _url: tarball) == 0
    assert listed(tmp_path / "default") == KEPT


def test_main_reports_a_bad_digest_a_bad_lock_and_a_bad_archive(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(conventional, "ROOT", tmp_path)
    tarball = make_tarball(FILES)
    lock = lock_file(tmp_path, tarball)
    assert fetch_novnc.main(["out"], lock, lambda _url: b"something else") == 1
    assert "fetch_novnc: " in capsys.readouterr().err
    lock.write_text("nonsense\n", encoding="utf-8")
    assert fetch_novnc.main(["out"], lock, lambda _url: tarball) == 1
    assert fetch_novnc.main(["out"], tmp_path / "missing.lock", lambda _url: tarball) == 1
    capsys.readouterr()
    junk = b"not a tarball"
    lock.write_text(f"v1 {hashlib.sha256(junk).hexdigest()} https://x.test/a\n", encoding="utf-8")
    assert fetch_novnc.main(["out"], lock, lambda _url: junk) == 1
    assert "fetch_novnc: " in capsys.readouterr().err


def test_main_usage(capsys: pytest.CaptureFixture[str]) -> None:
    assert fetch_novnc.main(["a", "b"]) == 2
    assert "fetch_novnc.py" in capsys.readouterr().err


def test_download_reads_the_url(monkeypatch: pytest.MonkeyPatch) -> None:
    class Response(io.BytesIO):
        def __enter__(self) -> Self:
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_val: BaseException | None,
            exc_tb: TracebackType | None,
        ) -> None:
            self.close()

    seen: list[tuple[str, float]] = []

    def fake_urlopen(url: str, timeout: float) -> Response:
        seen.append((url, timeout))
        return Response(b"body")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert fetch_novnc.download("https://x.test/a") == b"body"
    assert seen == [("https://x.test/a", fetch_novnc.TIMEOUT)]
