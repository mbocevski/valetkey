# SPDX-License-Identifier: Apache-2.0

import shutil
import subprocess
from datetime import date
from typing import TYPE_CHECKING

import changelog_check
import pytest
import release

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

TODAY = date(2026, 11, 2)
INTRO = "# Changelog\n\nChanges that affect users.\n\n"
UNRELEASED = "## [Unreleased]\n\n### Added\n\n- The `status` command.\n"
HISTORY = "\n## [0.1.0] - 2026-10-26\n\n### Added\n\n- The `valetkey` command.\n"


def cut(body: str, version: str = "0.2.0") -> str:
    return release.cut(INTRO + body, version, TODAY)


def test_cut_releases_the_unreleased_entries() -> None:
    assert cut(UNRELEASED + HISTORY) == (
        INTRO
        + "## [Unreleased]\n\n## [0.2.0] - 2026-11-02\n\n### Added\n\n- The `status` command.\n"
        + HISTORY
    )


def test_cut_first_release_with_no_history() -> None:
    assert cut(UNRELEASED, "0.1.0").endswith(
        "## [Unreleased]\n\n## [0.1.0] - 2026-11-02\n\n### Added\n\n- The `status` command.\n"
    )


def test_cut_stops_at_the_next_release() -> None:
    # The entries of an older release do not count as unreleased ones.
    body = "## [Unreleased]\n" + HISTORY
    with pytest.raises(release.ReleaseError, match="no entries"):
        cut(body)


@pytest.mark.parametrize("body", [UNRELEASED, UNRELEASED + HISTORY])
def test_cut_output_passes_the_changelog_lint(body: str) -> None:
    assert changelog_check.lint(cut(body), "0.2.0") == []


def test_cut_keeps_link_definitions() -> None:
    link = "\n[0.1.0]: https://example.org/releases/0.1.0\n"
    assert cut(UNRELEASED + HISTORY + link).endswith(link)


@pytest.mark.parametrize("version", ["1", "1.2", "v1.2.3", "1.2.3-rc1", "01.2.x", ""])
def test_version_must_be_major_minor_patch(version: str) -> None:
    with pytest.raises(release.ReleaseError, match=r"not a MAJOR\.MINOR\.PATCH"):
        cut(UNRELEASED, version)


@pytest.mark.parametrize("version", ["0.1.0", "0.0.9"])
def test_version_must_be_newer(version: str) -> None:
    with pytest.raises(release.ReleaseError, match=r"not newer than the latest release, 0\.1\.0"):
        cut(UNRELEASED + HISTORY, version)


def test_version_compares_numbers_not_text() -> None:
    history = "\n## [0.9.0] - 2026-10-26\n\n### Added\n\n- A thing.\n"
    assert "## [0.10.0] - 2026-11-02" in cut(UNRELEASED + history, "0.10.0")


def test_unreleased_must_have_entries() -> None:
    with pytest.raises(release.ReleaseError, match="no entries"):
        cut("## [Unreleased]\n" + HISTORY)


def test_unreleased_heading_is_required() -> None:
    with pytest.raises(release.ReleaseError, match="no '## \\[Unreleased\\]' heading"):
        cut(HISTORY)


def test_released_versions_in_file_order() -> None:
    text = INTRO + UNRELEASED + "\n## [1.0.0] - 2027-01-01\n\n## [0.9.0] - 2026-12-01\n"
    assert release.released_versions(text) == [(1, 0, 0), (0, 9, 0)]


def test_release_section() -> None:
    link = "\n[0.2.0]: https://example.org/releases/0.2.0\n"
    text = cut(UNRELEASED + HISTORY + link)
    assert release.release_section(text, "0.2.0") == (
        "## [0.2.0] - 2026-11-02\n\n### Added\n\n- The `status` command."
    )
    assert release.release_section(text, "0.1.0").endswith("- The `valetkey` command.")


class Fake:
    """Records the commands and answers the two read-only git queries."""

    def __init__(self, *, status: str = "", tags: str = "", fail: str | None = None) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.status, self.tags, self.fail = status, tags, fail

    def __call__(self, args: Sequence[str]) -> str:
        self.calls.append(tuple(args))
        if args[:2] == ["git", "status"]:
            return self.status
        if args[:2] == ["git", "tag"] and "--list" in args:
            return self.tags
        if self.fail is not None and " ".join(args[:2]) == self.fail:
            message = f"{self.fail} failed"
            raise release.ReleaseError(message)
        return ""


@pytest.fixture
def root(tmp_path: Path) -> Path:
    (tmp_path / "CHANGELOG.md").write_text(INTRO + UNRELEASED + HISTORY)
    return tmp_path


def test_release_runs_git_and_uv_in_order(root: Path) -> None:
    fake = Fake()
    push = release.release("0.2.0", root, fake, TODAY)
    notes = "v0.2.0\n\n## [0.2.0] - 2026-11-02\n\n### Added\n\n- The `status` command.\n"
    assert fake.calls == [
        ("git", "status", "--porcelain"),
        ("git", "tag", "--list", "v0.2.0"),
        ("uv", "version", "0.2.0", "--no-sync"),
        ("git", "add", "CHANGELOG.md", "pyproject.toml", "uv.lock"),
        ("git", "commit", "-m", "chore(release): 0.2.0"),
        ("git", "tag", "-s", "--cleanup=verbatim", "-m", notes, "v0.2.0"),
    ]
    assert push == "git push origin HEAD v0.2.0"
    assert "## [0.2.0] - 2026-11-02" in (root / "CHANGELOG.md").read_text()


def test_release_can_make_an_unsigned_tag(root: Path) -> None:
    fake = Fake()
    release.release("0.2.0", root, fake, TODAY, sign=False)
    assert fake.calls[-1][:3] == ("git", "tag", "-a")


@pytest.mark.parametrize(
    ("fake", "version", "message"),
    [
        (Fake(), "2", "not a MAJOR.MINOR.PATCH"),
        (Fake(), "0.1.0", "not newer"),
        (Fake(status=" M README.md\n"), "0.2.0", "uncommitted changes"),
        (Fake(tags="v0.2.0\n"), "0.2.0", "tag v0.2.0 already exists"),
    ],
)
def test_release_refuses_without_changing_anything(
    root: Path, fake: Fake, version: str, message: str
) -> None:
    before = (root / "CHANGELOG.md").read_text()
    with pytest.raises(release.ReleaseError, match=message):
        release.release(version, root, fake, TODAY)
    assert (root / "CHANGELOG.md").read_text() == before
    assert all(call[0] == "git" and call[1] in {"status", "tag"} for call in fake.calls)


@pytest.mark.parametrize("failing", ["uv version", "git add", "git commit"])
def test_release_restores_the_files_when_a_step_fails(root: Path, failing: str) -> None:
    fake = Fake(fail=failing)
    with pytest.raises(release.ReleaseError, match=f"{failing} failed\\nThe release was undone"):
        release.release("0.2.0", root, fake, TODAY)
    assert fake.calls[-1] == ("git", "checkout", "HEAD", "--", *release.FILES)
    assert not any(call[:2] == ("git", "tag") and "-s" in call for call in fake.calls)


def test_release_says_how_to_undo_when_only_the_tag_fails(root: Path) -> None:
    fake = Fake(fail="git tag")
    with pytest.raises(release.ReleaseError) as caught:
        release.release("0.2.0", root, fake, TODAY)
    text = str(caught.value)
    assert "The release commit exists but the tag does not" in text
    assert "git reset --hard HEAD~1" in text
    assert "git tag -s v0.2.0" in text
    assert "## [0.2.0]" in (root / "CHANGELOG.md").read_text()


def test_main_reports_a_refusal(capsys: pytest.CaptureFixture[str]) -> None:
    assert release.main(["nonsense"]) == 1
    assert "release: 'nonsense' is not a MAJOR.MINOR.PATCH version" in capsys.readouterr().err


def test_main_usage(capsys: pytest.CaptureFixture[str]) -> None:
    assert release.main([]) == 2
    assert "release.py X.Y.Z" in capsys.readouterr().err


def test_main_prints_the_push_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(release, "release", lambda *_a, **_k: "git push origin HEAD v9.9.9")
    assert release.main(["9.9.9"]) == 0
    out = capsys.readouterr().out
    assert "Nothing was pushed" in out
    assert "    git push origin HEAD v9.9.9" in out


def git(root: Path, *args: str) -> str:
    result = subprocess.run(  # noqa: S603 - git in a throwaway repository
        ["git", *args],  # noqa: S607 - git from PATH
        capture_output=True,
        text=True,
        check=True,
        cwd=root,
    )
    return result.stdout


@pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("uv") is None, reason="needs git and uv"
)
def test_release_end_to_end_in_a_throwaway_repository(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1.0"\nrequires-python = ">=3.14"\n'
        '[build-system]\nrequires = ["uv_build>=0.13.5,<0.14.0"]\nbuild-backend = "uv_build"\n'
    )
    (tmp_path / "src" / "demo").mkdir(parents=True)
    (tmp_path / "src" / "demo" / "__init__.py").write_text("")
    (tmp_path / "CHANGELOG.md").write_text(INTRO + UNRELEASED)
    subprocess.run(["uv", "lock", "--offline"], cwd=tmp_path, check=True, capture_output=True)  # noqa: S607
    git(tmp_path, "init", "-q", "-b", "main")
    for key, value in [
        ("user.name", "Test"),
        ("user.email", "test@example.org"),
        ("commit.gpgsign", "false"),
        ("tag.gpgsign", "false"),
    ]:
        git(tmp_path, "config", "--local", key, value)
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-q", "-m", "chore: start")

    push = release.release("0.2.0", tmp_path, release.make_runner(tmp_path), TODAY, sign=False)

    assert push == "git push origin HEAD v0.2.0"
    assert git(tmp_path, "log", "-1", "--format=%s").strip() == "chore(release): 0.2.0"
    assert git(tmp_path, "status", "--porcelain") == ""
    assert 'version = "0.2.0"' in (tmp_path / "pyproject.toml").read_text()
    assert 'version = "0.2.0"' in (tmp_path / "uv.lock").read_text()
    assert git(tmp_path, "tag", "--list", "v0.2.0").strip() == "v0.2.0"
    assert git(tmp_path, "tag", "-n99", "--list", "v0.2.0").startswith("v0.2.0")
    assert "## [0.2.0] - 2026-11-02\n\n### Added\n\n- The `status` command." in git(
        tmp_path, "cat-file", "-p", "v0.2.0"
    )
    text = (tmp_path / "CHANGELOG.md").read_text()
    assert changelog_check.lint(text, "0.2.0") == []

    with pytest.raises(release.ReleaseError, match="failed"):
        release.make_runner(tmp_path)(["git", "no-such-command"])
    with pytest.raises(release.ReleaseError, match="not newer"):
        release.release("0.2.0", tmp_path, release.make_runner(tmp_path), TODAY, sign=False)
