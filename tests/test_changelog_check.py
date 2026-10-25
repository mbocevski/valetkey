# SPDX-License-Identifier: Apache-2.0

from typing import TYPE_CHECKING

import changelog_check
import conventional
import pytest

if TYPE_CHECKING:
    from pathlib import Path

INTRO = "# Changelog\n\nChanges that affect users.\n\n"


def lint(body: str) -> list[str]:
    return [p.message for p in changelog_check.lint(INTRO + body)]


def test_valid_changelog() -> None:
    body = (
        "## [Unreleased]\n\n### Added\n\n- The `status` command.\n- A second line that\n"
        "  wraps onto the next.\n\n### Fixed\n\n- Exit with status 2 on usage errors.\n\n"
        "## [0.2.0] - 2026-11-02\n\n### Security\n\n- Refuse DNS from the browser.\n\n"
        "## [0.1.0] - 2026-10-26\n\n### Added\n\n- The `valetkey` command.\n\n"
        "[0.1.0]: https://example.org/releases/0.1.0\n"
    )
    assert lint(body) == []


def test_this_repository_changelog_is_valid() -> None:
    assert changelog_check.main(["lint"]) == 0


def test_title_is_required() -> None:
    assert changelog_check.lint("# Changes\n\n## [Unreleased]\n")[0].message == (
        "line 1: the file must start with '# Changelog'"
    )


def test_unreleased_is_required() -> None:
    assert lint("## [0.1.0] - 2026-10-26\n\n### Added\n\n- A thing.\n") == [
        "line 10: there must be an '## [Unreleased]' section"
    ]


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("## [Unreleased] - 2026-10-26\n", "line 5: '## [Unreleased]' takes no date"),
        (
            "## [Unreleased]\n\n## [Unreleased]\n",
            "line 7: '## [Unreleased]' must come first, once",
        ),
        ("## [Unreleased]\n\n## [1.0]\n", "line 7: '1.0' is not a MAJOR.MINOR.PATCH version"),
        (
            "## [Unreleased]\n\n## [0.1.0]\n\n### Added\n\n- A thing.\n",
            "line 7: '0.1.0' needs a date: '## [0.1.0] - YYYY-MM-DD'",
        ),
        (
            (
                "## [Unreleased]\n\n## [0.1.0] - 2026-10-26\n\n### Added\n\n- A.\n\n"
                "## [0.2.0] - 2026-11-02\n\n### Added\n\n- B.\n"
            ),
            "line 13: versions must go from newest to oldest",
        ),
    ],
)
def test_version_headings(body: str, expected: str) -> None:
    assert expected in lint(body)


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("## [Unreleased]\n\n### New\n\n- A thing.\n", "line 7: 'New' is not one of: "),
        (
            "## [Unreleased]\n\n### Fixed\n\n- A.\n\n### Added\n\n- B.\n",
            "line 11: 'Added' is out of order or repeated",
        ),
        ("## [Unreleased]\n\n### Added\n\n### Fixed\n\n- A.\n", "line 9: empty '### Added'"),
        ("## [Unreleased]\n\n### Added\n", "line 8: empty '### Added' section"),
        ("### Added\n\n- A.\n\n## [Unreleased]\n", "line 5: a section must sit under a version"),
    ],
)
def test_sections(body: str, expected: str) -> None:
    assert any(message.startswith(expected) for message in lint(body)), lint(body)


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ("- lowercase start.", "start each entry with a capital letter"),
        ("- No full stop", "end each entry with a full stop"),
        ("- Refactor the proxy.", "'Refactor' is an internal change; users never see it"),
        ("- Add tests for the daemon.", "'tests' is an internal change"),
        ("- Bump ruff.", "'Bump' is an internal change"),
        ("- Various fixes.", "'Various' is vague; say what changed"),
        ("- " + "word " * 41 + "end.", "42 words; keep an entry under 40"),
    ],
)
def test_entry_wording(entry: str, expected: str) -> None:
    messages = lint(f"## [Unreleased]\n\n### Fixed\n\n{entry}\n")
    assert any(expected in message for message in messages), messages


def test_entries_need_a_section_and_no_nesting() -> None:
    messages = lint("## [Unreleased]\n\n- Loose entry.\n\n### Added\n\n- A.\n  - nested.\n")
    assert "line 7: an entry must sit under a '### Added'-style section" in messages
    assert "line 12: entries take no nested lists" in messages


def test_stray_text_in_a_release() -> None:
    assert lint("## [Unreleased]\n\nSome prose.\n") == [
        "line 7: only versions, sections and '- ' entries belong here"
    ]


def commit(message: str) -> conventional.Commit:
    return conventional.parse(message)


@pytest.mark.parametrize(
    ("message", "touches", "fails"),
    [
        ("feat: add status", True, False),
        ("feat: add status", False, True),
        ("fix: handle EOF\n\nChangelog: skip", False, False),
        ("refactor!: rename the socket", False, True),
        ("chore: tidy", False, False),
        ("chore: tidy", True, True),
        ("docs(changelog): reword", True, False),
        ("chore(release): 0.1.0", True, False),
    ],
)
def test_check_commit(*, message: str, touches: bool, fails: bool) -> None:
    reason = changelog_check.check_commit(commit(message), touches_changelog=touches)
    assert (reason is not None) is fails


def test_check_range_and_the_skip_label() -> None:
    changelog = frozenset({"CHANGELOG.md"})
    commits = [
        conventional.RangeCommit("a" * 40, commit("feat: add status"), frozenset()),
        conventional.RangeCommit("b" * 40, commit("chore: tidy"), changelog),
        conventional.RangeCommit("c" * 40, commit("fix: handle EOF"), changelog),
    ]
    problems = [p.message for p in changelog_check.check_range(commits, skip=False)]
    assert len(problems) == 2
    assert problems[0].startswith("aaaaaaaaaaaa 'feat: add status' changes what users see")
    assert problems[1].startswith("bbbbbbbbbbbb 'chore: tidy' is not user-facing")
    skipped = [p.message for p in changelog_check.check_range(commits, skip=True)]
    assert skipped == [problems[1]]


def test_range_reads_git(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    outputs = {
        ("rev-list", "--reverse", "--no-merges", "base..head"): "s1\ns2\n",
        ("log", "-1", "--format=%B", "s1"): "feat: add status\n",
        ("diff-tree", "--no-commit-id", "--name-only", "-r", "s1"): "src/x.py\n",
        ("log", "-1", "--format=%B", "s2"): "docs: reword\n",
        ("diff-tree", "--no-commit-id", "--name-only", "-r", "s2"): "README.md\n",
    }
    monkeypatch.setattr(conventional, "git", lambda *args: outputs[args])
    assert changelog_check.main(["range", "base", "head"]) == 1
    assert "s1 'feat: add status' changes what users see" in capsys.readouterr().err
    assert changelog_check.main(["range", "base", "head", "--skip"]) == 0


def test_commit_msg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    message = tmp_path / "COMMIT_EDITMSG"
    message.write_text("feat: add status\n")
    monkeypatch.setattr(conventional, "git", lambda *_: "src/x.py\n")
    assert changelog_check.main(["commit-msg", str(message)]) == 1
    assert "This commit changes what users see" in capsys.readouterr().err
    monkeypatch.setattr(conventional, "git", lambda *_: "CHANGELOG.md\n")
    assert changelog_check.main(["commit-msg", str(message)]) == 0


def test_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert changelog_check.main(["range", "a", "b", "--bogus"]) == 2
    assert "changelog_check.py lint" in capsys.readouterr().err


def test_newest_release_must_match_the_package_version() -> None:
    body = (
        "## [Unreleased]\n\n## [0.2.0] - 2026-11-02\n\n### Added\n\n- A thing.\n\n"
        "## [0.1.0] - 2026-10-26\n\n### Added\n\n- Another.\n"
    )
    assert changelog_check.lint(INTRO + body, "0.2.0") == []
    problems = [p.message for p in changelog_check.lint(INTRO + body, "0.1.0")]
    assert problems == ["line 7: the newest release is 0.2.0 but pyproject.toml has version 0.1.0"]


def test_unreleased_only_changelog_matches_any_version() -> None:
    body = "## [Unreleased]\n\n### Added\n\n- A thing.\n"
    assert changelog_check.lint(INTRO + body, "0.1.0") == []


def test_project_version_is_read_from_pyproject() -> None:
    assert changelog_check.SEMVER.match(changelog_check.project_version())
