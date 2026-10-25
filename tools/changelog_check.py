# SPDX-License-Identifier: Apache-2.0
"""Keep CHANGELOG.md a record of what changed for users, and nothing else.

    python tools/changelog_check.py lint
    python tools/changelog_check.py commit-msg MESSAGE_FILE
    python tools/changelog_check.py range BASE HEAD [--skip]

``lint`` checks the file: the Keep a Changelog layout, entries written as short
sentences, no internal or vague wording, and that the newest released version is the
version in pyproject.toml.

``commit-msg`` checks one commit while it is being made, ``range`` checks every commit
in ``BASE..HEAD`` (a pull request). Both apply the same rules:

* A user-facing commit (``feat``, ``fix``, ``perf``, ``revert`` or a breaking change)
  must update CHANGELOG.md, or carry a ``Changelog: skip`` trailer. In ``range``,
  ``--skip`` (a ``skip-changelog`` label) waives this.
* Any other commit must leave CHANGELOG.md alone, unless its scope is ``changelog``
  or ``release``.
"""

import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

import conventional

CHANGELOG = conventional.ROOT / "CHANGELOG.md"
NAME = "CHANGELOG.md"

SECTIONS = ("Added", "Changed", "Deprecated", "Removed", "Fixed", "Security")
CHANGELOG_SCOPES = frozenset({"changelog", "release"})
MAX_ENTRY_WORDS = 40

VERSION = re.compile(r"^## \[(?P<version>[^\]]+)\](?: - (?P<date>.+))?$")
SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SECTION = re.compile(r"^### (?P<name>.+)$")
LINK = re.compile(r"^\[[^\]]+\]: \S+$")
WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9'\u2019-]*")
# Changes users never see.
INTERNAL = re.compile(
    r"\b(?:refactor\w*|tests?|testing|CI|lint\w*|coverage|pytest|ruff|prek|pre-commit|"
    r"Dependabot|bumps?|bumped|typos?|internals?|codebase|clean[- ]?up|workflows?)\b",
    re.IGNORECASE,
)
VAGUE = re.compile(r"\b(?:various|misc|miscellaneous|minor|assorted|several)\b", re.IGNORECASE)


@dataclass(frozen=True)
class Problem:
    """Something in CHANGELOG.md, or in a commit, that breaks the rules."""

    message: str


class Linter:
    """Walks CHANGELOG.md line by line and collects what breaks its rules."""

    def __init__(self) -> None:
        """Start before the first line."""
        self.problems: list[Problem] = []
        self.versions: list[tuple[int, int, int]] = []
        self.newest_line = 0
        self.seen_unreleased = False
        self.section: str | None = None
        self.sections_here: list[str] = []
        self.entries_here = 0
        self.entry_start: int | None = None
        self.entry_last = ""

    def fail(self, number: int, message: str) -> None:
        """Record a problem on line ``number``."""
        self.problems.append(Problem(f"line {number}: {message}"))

    @property
    def in_release(self) -> bool:
        """Whether a version heading has been seen."""
        return self.seen_unreleased or bool(self.versions)

    def end_entry(self) -> None:
        """Check that the entry just finished ends with a full stop."""
        if self.entry_start is not None and not self.entry_last.rstrip().endswith("."):
            self.fail(self.entry_start, "end each entry with a full stop")
        self.entry_start = None

    def end_section(self, number: int) -> None:
        """Check that the section just finished has entries."""
        self.end_entry()
        if self.section is not None and self.entries_here == 0:
            self.fail(number, f"empty '### {self.section}' section")
        self.section, self.entries_here = None, 0

    def on_version(self, number: int, name: str, date: str | None) -> None:
        """Handle a ``## [VERSION] - DATE`` heading."""
        self.end_section(number)
        self.sections_here = []
        if name == "Unreleased":
            if self.in_release:
                self.fail(number, "'## [Unreleased]' must come first, once")
            if date is not None:
                self.fail(number, "'## [Unreleased]' takes no date")
            self.seen_unreleased = True
            return
        semver = SEMVER.match(name)
        if semver is None:
            self.fail(number, f"'{name}' is not a MAJOR.MINOR.PATCH version")
            return
        if date is None or not DATE.match(date):
            self.fail(number, f"'{name}' needs a date: '## [{name}] - YYYY-MM-DD'")
        key = (int(semver[1]), int(semver[2]), int(semver[3]))
        if not self.versions:
            self.newest_line = number
        if self.versions and key >= self.versions[-1]:
            self.fail(number, "versions must go from newest to oldest")
        self.versions.append(key)

    def on_section(self, number: int, name: str) -> None:
        """Handle a ``### Added``-style heading."""
        self.end_section(number)
        order = ", ".join(SECTIONS)
        if not self.in_release:
            self.fail(number, "a section must sit under a version heading")
        if name not in SECTIONS:
            self.fail(number, f"'{name}' is not one of: {order}")
        elif self.sections_here and SECTIONS.index(name) <= SECTIONS.index(self.sections_here[-1]):
            self.fail(number, f"'{name}' is out of order or repeated; use: {order}")
        self.section = name
        self.sections_here.append(name)

    def on_entry(self, number: int, text: str) -> None:
        """Handle a ``- `` entry."""
        self.end_entry()
        if self.section is None:
            self.fail(number, "an entry must sit under a '### Added'-style section")
        self.entries_here += 1
        self.entry_start, self.entry_last = number, text
        for message in entry_problems(text):
            self.fail(number, message)

    def on_line(self, number: int, line: str) -> None:
        """Dispatch one line."""
        if version := VERSION.match(line):
            self.on_version(number, version["version"], version["date"])
        elif heading := SECTION.match(line):
            self.on_section(number, heading["name"])
        elif line.startswith("- "):
            self.on_entry(number, line[2:])
        elif self.entry_start is not None and line.startswith("  ") and line.strip():
            if line.lstrip().startswith(("- ", "* ")):
                self.fail(number, "entries take no nested lists")
            self.entry_last = line
        elif not line.strip():
            self.end_entry()
        elif self.in_release and not LINK.match(line):
            self.fail(number, "only versions, sections and '- ' entries belong here")


def lint(text: str, version: str | None = None) -> list[Problem]:
    """Return everything in ``text`` that breaks the changelog's layout or wording rules.

    When ``version`` (the package version) is given and a version is released, the newest
    release must be that version.
    """
    lines = text.splitlines()
    linter = Linter()
    if not lines or lines[0] != "# Changelog":
        linter.fail(1, "the file must start with '# Changelog'")
    for number, line in enumerate(lines[1:], start=2):
        linter.on_line(number, line)
    linter.end_section(len(lines) + 1)
    if not linter.seen_unreleased:
        linter.fail(len(lines) + 1, "there must be an '## [Unreleased]' section")
    if version is not None and linter.versions:
        newest = ".".join(map(str, linter.versions[0]))
        if newest != version:
            linter.fail(
                linter.newest_line,
                f"the newest release is {newest} but pyproject.toml has version {version}",
            )
    return linter.problems


def project_version() -> str:
    """Return ``project.version`` from pyproject.toml."""
    with (conventional.ROOT / "pyproject.toml").open("rb") as file:
        return str(tomllib.load(file)["project"]["version"])


def entry_problems(entry: str) -> list[str]:
    """Return what is wrong with the first line of one entry."""
    problems: list[str] = []
    if not (entry[:1].isupper() or entry[:1] == "`"):
        problems.append("start each entry with a capital letter")
    words = len(WORD.findall(entry))
    if words > MAX_ENTRY_WORDS:
        problems.append(f"{words} words; keep an entry under {MAX_ENTRY_WORDS}")
    if internal := INTERNAL.search(entry):
        problems.append(f"'{internal[0]}' is an internal change; users never see it")
    if vague := VAGUE.search(entry):
        problems.append(f"'{vague[0]}' is vague; say what changed")
    return problems


def check_commit(commit: conventional.Commit, *, touches_changelog: bool) -> str | None:
    """Return why ``commit`` breaks the changelog rules, or None."""
    if commit.user_facing:
        if touches_changelog or commit.has_trailer("Changelog", "skip"):
            return None
        return (
            "changes what users see but does not update CHANGELOG.md; add an entry, "
            "or a 'Changelog: skip' trailer if users would not notice"
        )
    if touches_changelog and commit.scope not in CHANGELOG_SCOPES:
        return (
            "is not user-facing but edits CHANGELOG.md; use feat/fix/perf/revert if users "
            "see this change, or the 'changelog' or 'release' scope to edit the file itself"
        )
    return None


def check_range(commits: list[conventional.RangeCommit], *, skip: bool) -> list[Problem]:
    """Check each commit of a range; ``skip`` waives missing entries."""
    problems: list[Problem] = []
    for item in commits:
        reason = check_commit(item.commit, touches_changelog=NAME in item.files)
        if reason is None or (skip and item.commit.user_facing):
            continue
        problems.append(Problem(f"{item.sha[:12]} '{item.header}' {reason}"))
    return problems


def report(problems: list[Problem], prefix: str) -> int:
    """Print ``problems`` and return the exit status."""
    for problem in problems:
        print(f"{prefix}{problem.message}", file=sys.stderr)
    return 1 if problems else 0


def main(argv: list[str]) -> int:
    """Dispatch to ``lint``, ``commit-msg`` or ``range``."""
    match argv:
        case ["lint"]:
            text = CHANGELOG.read_text()
            return report(lint(text, project_version()), f"{NAME}: ")
        case ["commit-msg", path]:
            commit = conventional.parse(Path(path).read_text())
            staged = conventional.staged_files()
            reason = check_commit(commit, touches_changelog=NAME in staged)
            return report([Problem(f"This commit {reason}.")] if reason else [], "")
        case ["range", base, head, *flags] if flags in ([], ["--skip"]):
            commits = conventional.range_commits(base, head)
            problems = check_range(commits, skip=flags == ["--skip"])
            return report(problems, "")
        case _:
            print(__doc__, file=sys.stderr)
            return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
