# SPDX-License-Identifier: Apache-2.0

import conventional
import pytest


@pytest.mark.parametrize(
    ("message", "type_", "scope", "breaking", "user_facing"),
    [
        ("feat: add status", "feat", None, False, True),
        ("fix(cli): exit 2 on errors", "fix", "cli", False, True),
        ("perf: cache the policy", "perf", None, False, True),
        ("revert: undo the cache", "revert", None, False, True),
        ("refactor!: rename the socket", "refactor", None, True, True),
        ("chore: tidy\n\nBREAKING CHANGE: config moved", "chore", None, True, True),
        ("docs(changelog): reword an entry", "docs", "changelog", False, False),
        ("ci: pin actions", "ci", None, False, False),
        ("Merge branch 'main'", None, None, False, False),
    ],
)
def test_parse(
    *, message: str, type_: str | None, scope: str | None, breaking: bool, user_facing: bool
) -> None:
    commit = conventional.parse(message)
    assert (commit.type, commit.scope, commit.breaking) == (type_, scope, breaking)
    assert commit.user_facing is user_facing


def test_trailers() -> None:
    commit = conventional.parse("feat: x\n\nBody.\n\nChangelog: skip\nDocs:  None \n")
    assert commit.has_trailer("Changelog", "skip")
    assert commit.has_trailer("docs", "none")
    assert not commit.has_trailer("Changelog", "none")


def test_range_commits_reads_git(monkeypatch: pytest.MonkeyPatch) -> None:
    outputs = {
        ("rev-list", "--reverse", "--no-merges", "base..head"): "s1\n",
        ("log", "-1", "--format=%B", "s1"): "feat: add status\n\nBody.\n",
        ("diff-tree", "--no-commit-id", "--name-only", "-r", "s1"): "src/x.py\nREADME.md\n",
    }
    monkeypatch.setattr(conventional, "git", lambda *args: outputs[args])
    [item] = conventional.range_commits("base", "head")
    assert (item.sha, item.header, item.files) == (
        "s1",
        "feat: add status",
        frozenset({"src/x.py", "README.md"}),
    )


def test_empty_message_has_an_empty_header() -> None:
    assert conventional.RangeCommit("s", conventional.parse(""), frozenset()).header == ""


def test_git_runs_in_the_repository() -> None:
    assert conventional.git("rev-parse", "--is-inside-work-tree").strip() == "true"
    assert isinstance(conventional.staged_files(), list)
