# SPDX-License-Identifier: Apache-2.0
import json
import os
import stat
from typing import TYPE_CHECKING

import pytest

from valetkey import profiles

if TYPE_CHECKING:
    from pathlib import Path


def preferences(profile: Path) -> dict[str, object]:
    return json.loads((profile / "Default" / "Preferences").read_text(encoding="utf-8"))


def test_a_new_profile_gets_the_setting_and_nothing_else(tmp_path: Path) -> None:
    profiles.keep_session_cookies(tmp_path / "p")
    assert preferences(tmp_path / "p") == {"session": {"restore_on_startup": 1}}
    mode = stat.S_IMODE((tmp_path / "p" / "Default" / "Preferences").stat().st_mode)
    assert mode == 0o600
    assert stat.S_IMODE((tmp_path / "p" / "Default").stat().st_mode) == 0o700


def test_every_other_preference_stays_as_it_was(tmp_path: Path) -> None:
    default = tmp_path / "Default"
    default.mkdir()
    (default / "Preferences").write_text(
        json.dumps(
            {
                "profile": {"name": "Person 1"},
                "session": {"restore_on_startup": 5, "startup_urls": ["https://a.test/"]},
            }
        ),
        encoding="utf-8",
    )
    profiles.keep_session_cookies(tmp_path)
    assert preferences(tmp_path) == {
        "profile": {"name": "Person 1"},
        "session": {"restore_on_startup": 1, "startup_urls": ["https://a.test/"]},
    }


def test_a_profile_that_already_has_the_setting_is_not_rewritten(tmp_path: Path) -> None:
    profiles.keep_session_cookies(tmp_path)
    path = tmp_path / "Default" / "Preferences"
    os.utime(path, (1_000_000, 1_000_000))
    profiles.keep_session_cookies(tmp_path)
    assert path.stat().st_mtime == 1_000_000


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"not json at all",
        b"[1, 2, 3]",
        b'"text"',
        b"null",
        b'{"session": 5}',
        b'{"session": [1]}',
        b"[" * 100_000,
        b"\xff\xfe\x00",
    ],
)
def test_a_file_that_is_not_the_object_chromium_writes_is_replaced(
    tmp_path: Path, content: bytes
) -> None:
    default = tmp_path / "Default"
    default.mkdir()
    (default / "Preferences").write_bytes(content)
    profiles.keep_session_cookies(tmp_path)
    assert preferences(tmp_path) == {"session": {"restore_on_startup": 1}}


def test_a_file_over_the_limit_is_replaced_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(profiles, "MAX_BYTES", 40)
    default = tmp_path / "Default"
    default.mkdir()
    (default / "Preferences").write_text(json.dumps({"keep": "x" * 100}), encoding="utf-8")
    profiles.keep_session_cookies(tmp_path)
    assert preferences(tmp_path) == {"session": {"restore_on_startup": 1}}


def test_a_link_in_place_of_the_file_is_replaced_and_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"secret": 1}), encoding="utf-8")
    profile = tmp_path / "p"
    (profile / "Default").mkdir(parents=True)
    (profile / "Default" / "Preferences").symlink_to(outside)
    profiles.keep_session_cookies(profile)
    assert json.loads(outside.read_text(encoding="utf-8")) == {"secret": 1}
    assert not (profile / "Default" / "Preferences").is_symlink()
    assert preferences(profile) == {"session": {"restore_on_startup": 1}}


def test_a_directory_in_place_of_the_file_is_an_error_and_leaves_no_temporary_file(
    tmp_path: Path,
) -> None:
    default = tmp_path / "Default"
    (default / "Preferences").mkdir(parents=True)
    with pytest.raises(OSError):  # noqa: PT011 - whichever the system says about replacing a directory
        profiles.keep_session_cookies(tmp_path)
    assert [p.name for p in default.iterdir()] == ["Preferences"]


def test_a_write_that_fails_leaves_the_old_file_and_no_temporary_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    default = tmp_path / "Default"
    default.mkdir()
    (default / "Preferences").write_text('{"a": 1}', encoding="utf-8")

    def broken(*_args: object, **_kwargs: object) -> None:
        raise ValueError("disk full")  # noqa: EM101, TRY003

    monkeypatch.setattr(profiles.json, "dump", broken)
    with pytest.raises(ValueError, match="disk full"):
        profiles.keep_session_cookies(tmp_path)
    assert (default / "Preferences").read_text(encoding="utf-8") == '{"a": 1}'
    assert [p.name for p in default.iterdir()] == ["Preferences"]


def test_prepare_forgets_the_saved_tabs_and_keeps_the_cookies(tmp_path: Path) -> None:
    default = tmp_path / "Default"
    (default / "Sessions").mkdir(parents=True)
    (default / "Sessions" / "Tabs_1").write_bytes(b"tabs")
    (default / "Sessions" / "Session_1").write_bytes(b"windows")
    (default / "Cookies").write_bytes(b"cookies")
    profiles.prepare(tmp_path)
    assert not (default / "Sessions").exists()
    assert (default / "Cookies").read_bytes() == b"cookies"
    assert preferences(tmp_path) == {"session": {"restore_on_startup": 1}}


def test_prepare_without_saved_tabs_is_fine(tmp_path: Path) -> None:
    profiles.prepare(tmp_path)
    profiles.prepare(tmp_path)
    assert preferences(tmp_path) == {"session": {"restore_on_startup": 1}}


def test_prepare_removes_a_link_or_a_file_in_place_of_the_tabs_without_following_it(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep", encoding="utf-8")
    default = tmp_path / "p" / "Default"
    default.mkdir(parents=True)
    (default / "Sessions").symlink_to(outside, target_is_directory=True)
    profiles.prepare(tmp_path / "p")
    assert not (default / "Sessions").exists(follow_symlinks=False)
    assert (outside / "keep.txt").read_text(encoding="utf-8") == "keep"
    (default / "Sessions").write_bytes(b"a file")
    profiles.prepare(tmp_path / "p")
    assert not (default / "Sessions").exists()
