# SPDX-License-Identifier: Apache-2.0
"""Cut a release from the changelog, so the changelog, the version and the tag agree.

    python tools/release.py X.Y.Z

The command refuses unless X.Y.Z is a ``MAJOR.MINOR.PATCH`` version newer than the
newest released one, ``## [Unreleased]`` has entries, the worktree is clean and the tag
``vX.Y.Z`` does not exist. Then it:

* turns ``## [Unreleased]`` into ``## [X.Y.Z] - DATE`` and adds a new empty
  ``## [Unreleased]`` above it,
* sets the package version with ``uv version``, which also updates ``uv.lock``,
* commits the three files as ``chore(release): X.Y.Z``, and
* creates a signed, annotated tag ``vX.Y.Z`` that carries the changelog section.

It never pushes. It prints the command to run when you are ready.
"""

import subprocess
import sys
from collections.abc import Callable, Sequence
from datetime import date
from typing import TYPE_CHECKING

import changelog_check
import conventional

if TYPE_CHECKING:
    from pathlib import Path

FILES = ("CHANGELOG.md", "pyproject.toml", "uv.lock")
UNRELEASED = "## [Unreleased]"

type Version = tuple[int, int, int]
type Runner = Callable[[Sequence[str]], str]


class ReleaseError(Exception):
    """A release cannot go ahead; the message says why."""


def parse_version(text: str) -> Version:
    """Return ``text`` as a ``(major, minor, patch)`` tuple, or refuse."""
    match = changelog_check.SEMVER.match(text)
    if match is None:
        message = f"'{text}' is not a MAJOR.MINOR.PATCH version"
        raise ReleaseError(message)
    return int(match[1]), int(match[2]), int(match[3])


def released_versions(text: str) -> list[Version]:
    """Return the released versions in ``text``, in the order the file lists them."""
    found: list[Version] = []
    for line in text.splitlines():
        heading = changelog_check.VERSION.match(line)
        if heading and (semver := changelog_check.SEMVER.match(heading["version"])):
            found.append((int(semver[1]), int(semver[2]), int(semver[3])))
    return found


def cut(text: str, version: str, today: date) -> str:
    """Return ``text`` with ``## [Unreleased]`` released as ``version`` on ``today``."""
    number = parse_version(version)
    released = released_versions(text)
    if released and number <= max(released):
        newest = ".".join(map(str, max(released)))
        message = f"{version} is not newer than the latest release, {newest}"
        raise ReleaseError(message)
    lines = text.splitlines()
    if UNRELEASED not in lines:
        message = f"CHANGELOG.md has no '{UNRELEASED}' heading"
        raise ReleaseError(message)
    start = lines.index(UNRELEASED)
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## [")), len(lines))
    if not any(line.startswith("- ") for line in lines[start + 1 : end]):
        message = f"'{UNRELEASED}' has no entries to release"
        raise ReleaseError(message)
    heading = f"## [{version}] - {today.isoformat()}"
    return "\n".join([*lines[: start + 1], "", heading, *lines[start + 1 :]]) + "\n"


def release_section(text: str, version: str) -> str:
    """Return the heading and entries of ``version`` in ``text``."""
    lines = text.splitlines()
    prefix = f"## [{version}]"
    start = next(i for i, line in enumerate(lines) if line.startswith(prefix))
    section = []
    for line in lines[start:]:
        if section and (line.startswith("## [") or changelog_check.LINK.match(line)):
            break
        section.append(line)
    return "\n".join(section).strip()


def make_runner(root: Path) -> Runner:
    """Return a function that runs a command in ``root`` and returns its standard output."""

    def run(args: Sequence[str]) -> str:
        try:
            result = subprocess.run(  # noqa: S603 - fixed git and uv commands, no shell
                list(args), capture_output=True, text=True, check=True, cwd=root
            )
        except subprocess.CalledProcessError as error:
            message = f"{' '.join(args)} failed:\n{error.stdout}{error.stderr}".rstrip()
            raise ReleaseError(message) from error
        return result.stdout

    return run


def release(version: str, root: Path, run: Runner, today: date, *, sign: bool = True) -> str:
    """Cut ``version`` in ``root`` through ``run``; return the command that pushes it.

    ``sign`` is turned off only by tests, in a throwaway repository with no signing key.
    """
    tag = f"v{version}"
    changelog = root / "CHANGELOG.md"
    text = cut(changelog.read_text(), version, today)
    if run(["git", "status", "--porcelain"]).strip():
        message = "the worktree has uncommitted changes; commit or stash them first"
        raise ReleaseError(message)
    if run(["git", "tag", "--list", tag]).strip():
        message = f"the tag {tag} already exists"
        raise ReleaseError(message)
    changelog.write_text(text)
    try:
        run(["uv", "version", version, "--no-sync"])
        run(["git", "add", *FILES])
        run(["git", "commit", "-m", f"chore(release): {version}"])
    except ReleaseError as error:
        run(["git", "checkout", "HEAD", "--", *FILES])
        message = f"{error}\nThe release was undone: {', '.join(FILES)} are as they were."
        raise ReleaseError(message) from error
    notes = f"{tag}\n\n{release_section(text, version)}\n"
    try:
        # Verbatim, because git would strip the changelog's '#' headings from the message.
        run(["git", "tag", "-s" if sign else "-a", "--cleanup=verbatim", "-m", notes, tag])
    except ReleaseError as error:
        message = (
            f"{error}\nThe release commit exists but the tag does not. To try again, undo the "
            f"commit with:\n\n    git reset --hard HEAD~1\n\nor create the tag yourself: "
            f"git tag -s {tag}"
        )
        raise ReleaseError(message) from error
    return f"git push origin HEAD {tag}"


def main(argv: list[str]) -> int:
    """Run the release for the version given on the command line."""
    match argv:
        case [version]:
            root = conventional.ROOT
            today = date.today()  # noqa: DTZ011 - the release date is the local date
            try:
                push = release(version, root, make_runner(root), today)
            except ReleaseError as error:
                print(f"release: {error}", file=sys.stderr)
                return 1
            print(f"Released {version}: CHANGELOG.md, pyproject.toml and uv.lock are committed")
            print(f"and tagged v{version}. Nothing was pushed. To publish, run:\n\n    {push}")
            return 0
        case _:
            print(__doc__, file=sys.stderr)
            return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
