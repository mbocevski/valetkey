# SPDX-License-Identifier: Apache-2.0
"""Read Conventional Commits messages, and the commits in a range, the same way in every check."""

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

HEADER = re.compile(r"\A(?P<type>[a-z]+)(?:\((?P<scope>[a-z0-9-]+)\))?(?P<bang>!)?: ")
BREAKING_FOOTER = re.compile(r"^BREAKING[ -]CHANGE: ", re.MULTILINE)

# The types whose changes a user can notice.
USER_FACING_TYPES = frozenset({"feat", "fix", "perf", "revert"})


@dataclass(frozen=True)
class Commit:
    """The parts of a commit message the checks care about."""

    message: str
    type: str | None
    scope: str | None
    breaking: bool

    @property
    def user_facing(self) -> bool:
        """Whether users can notice this change."""
        return self.breaking or self.type in USER_FACING_TYPES

    def has_trailer(self, key: str, value: str) -> bool:
        """Whether the message carries the trailer ``KEY: VALUE`` (case-insensitive)."""
        pattern = rf"^{re.escape(key)}:[ \t]*{re.escape(value)}[ \t]*$"
        return re.search(pattern, self.message, re.MULTILINE | re.IGNORECASE) is not None


def parse(message: str) -> Commit:
    """Parse a commit message; a header that is not conventional leaves the type empty."""
    header = HEADER.match(message)
    if header is None:
        return Commit(message=message, type=None, scope=None, breaking=False)
    breaking = bool(header["bang"]) or BREAKING_FOOTER.search(message) is not None
    return Commit(message=message, type=header["type"], scope=header["scope"], breaking=breaking)


@dataclass(frozen=True)
class RangeCommit:
    """One commit of a range: its id, its parsed message and the paths it changed."""

    sha: str
    commit: Commit
    files: frozenset[str]

    @property
    def header(self) -> str:
        """The first line of the message."""
        return self.commit.message.splitlines()[0] if self.commit.message else ""


def git(*args: str) -> str:
    """Return the output of a read-only git command run in the repository."""
    result = subprocess.run(  # noqa: S603 - git with fixed subcommands
        ["git", *args],  # noqa: S607 - git from PATH, as hooks do
        capture_output=True,
        text=True,
        check=True,
        cwd=ROOT,
    )
    return result.stdout


def staged_files() -> list[str]:
    """Return the paths staged for the commit in progress."""
    return git("diff", "--cached", "--name-only").split()


def range_commits(base: str, head: str) -> list[RangeCommit]:
    """Return every non-merge commit in ``BASE..HEAD``, oldest first."""
    commits = []
    for sha in git("rev-list", "--reverse", "--no-merges", f"{base}..{head}").split():
        message = git("log", "-1", "--format=%B", sha)
        files = git("diff-tree", "--no-commit-id", "--name-only", "-r", sha).split()
        commits.append(RangeCommit(sha=sha, commit=parse(message), files=frozenset(files)))
    return commits
