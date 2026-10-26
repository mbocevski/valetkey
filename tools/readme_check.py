# SPDX-License-Identifier: Apache-2.0
"""Keep README.md in step with the code.

    python tools/readme_check.py facts [--fix]
    python tools/readme_check.py style
    python tools/readme_check.py commit-msg MESSAGE_FILE
    python tools/readme_check.py range BASE HEAD [--skip]

``facts`` checks what the README states about the code. A block between
``<!-- begin: valetkey ARGS -->`` and ``<!-- end: valetkey ARGS -->`` must hold the
output of ``valetkey ARGS`` in a ``text`` code fence; ``--fix`` rewrites stale blocks.
The README must also state the Python version that ``requires-python`` sets.

``style`` keeps the README short and plain. It caps the prose at a word budget and
the number of sections, and rejects the habits that pad a README: boilerplate
sections, list items that open with a bold label, deeply nested lists, horizontal
rules and walls of badges. Vale checks the wording; this checks the shape.

``commit-msg`` checks whether a commit should have changed the README. A ``feat``
commit or a breaking change alters what users can do, so it must stage README.md,
or carry a ``Docs: none`` trailer that records the README is still accurate.
``range`` applies the same rule to every commit in ``BASE..HEAD`` (a pull request);
``--skip`` (a ``skip-readme`` label) waives it.
"""

import os
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import conventional

from valetkey import sessions

if TYPE_CHECKING:
    from collections.abc import Callable

README = conventional.ROOT / "README.md"
PYPROJECT = conventional.ROOT / "pyproject.toml"

BLOCK = re.compile(
    r"(?P<begin><!-- begin: valetkey(?P<args>[^>]*?) -->\n)"
    r"(?P<body>.*?)"
    r"(?P<end><!-- end: valetkey(?P=args) -->)",
    re.DOTALL,
)
HELP_WIDTH = "80"

MAX_WORDS = 700
MAX_SECTIONS = 8
MAX_BADGES = 3
FENCE = re.compile(r"^```.*?^```[^\n]*$", re.MULTILINE | re.DOTALL)
COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9'\u2019-]*")
SECTION = re.compile(r"^## ", re.MULTILINE)
BOILERPLATE = re.compile(
    r"^#{1,6}\s+(?:(?:key\s+)?features|overview|introduction|why\s+valetkey\b.*|conclusion"
    r"|summary|table\s+of\s+contents)\s*\??$",
    re.MULTILINE | re.IGNORECASE,
)
BOLD_LABEL_ITEM = re.compile(
    r"^[ \t]*(?:[-*+]|\d+[.)])\s+(?:\*\*|__)[^*_\n]+(?:\*\*|__)", re.MULTILINE
)
DEEP_ITEM = re.compile(r"^(?: {4,}|\t+)(?:[-*+]|\d+[.)])\s", re.MULTILINE)
RULE = re.compile(r"^ {0,3}(?:-{3,}|\*{3,}|_{3,})\s*$", re.MULTILINE)
BADGE = re.compile(r"!\[[^\]]*\]\(https?://[^)]*(?:shields\.io|badge)[^)]*\)")


@dataclass(frozen=True)
class Problem:
    """Something in the README that needs fixing."""

    message: str


def run_valetkey(args: list[str]) -> str:
    """Return what ``valetkey ARGS`` prints, at a fixed width, without colour or trailing spaces."""
    env = os.environ | {"COLUMNS": HELP_WIDTH, "NO_COLOR": "1", "TERM": "dumb"}
    result = subprocess.run(  # noqa: S603 - runs this interpreter on fixed arguments
        [sys.executable, "-m", "valetkey", *args],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    # The help formatter pads some lines with spaces; the file hygiene hook would strip them.
    return "\n".join(line.rstrip() for line in result.stdout.rstrip().splitlines()) + "\n"


def render_block(output: str) -> str:
    """Return the body of a generated block for ``output``."""
    return f"```text\n{output}```\n"


def check_blocks(
    readme: str, run: Callable[[list[str]], str] = run_valetkey
) -> tuple[str, list[Problem]]:
    """Return the README with every generated block refreshed, and the stale ones."""
    problems: list[Problem] = []

    def refresh(match: re.Match[str]) -> str:
        args = match["args"].split()
        body = render_block(run(args))
        if match["body"] != body:
            problems.append(Problem(f"the output of `valetkey{match['args']}` has changed"))
        return match["begin"] + body + match["end"]

    return BLOCK.sub(refresh, readme), problems


def required_python(pyproject: str) -> str:
    """Return the minimum Python version in ``requires-python``, e.g. ``3.14``."""
    spec = tomllib.loads(pyproject)["project"]["requires-python"]
    match = re.fullmatch(r">=\s*(\d+\.\d+)", spec.strip())
    if match is None:
        msg = f"requires-python must be a plain '>=X.Y', not {spec!r}"
        raise ValueError(msg)
    return match[1]


def check_python(readme: str, pyproject: str) -> list[Problem]:
    """Return a problem unless the README states the Python version the project requires."""
    version = required_python(pyproject)
    if f"Python {version} or newer" in readme:
        return []
    return [Problem(f"the requirements must say 'Python {version} or newer'")]


def check_agent_browser(readme: str) -> list[Problem]:
    """Return a problem unless the requirements give agent-browser's minimum and tested versions."""
    wanted = (
        f"{sessions.short_version_text(sessions.MIN_VERSION)} or newer, "
        f"tested with {sessions.version_text(sessions.TESTED_VERSION)}"
    )
    lines = [line for line in readme.splitlines() if line.startswith("- [agent-browser]")]
    if lines and wanted in lines[0]:
        return []
    return [Problem(f"the requirements must say that agent-browser is '{wanted}'")]


def facts(*, fix: bool) -> int:
    """Check the README's statements about the code, rewriting stale blocks if ``fix``."""
    readme = README.read_text()
    refreshed, problems = check_blocks(readme)
    problems += check_python(refreshed, PYPROJECT.read_text())
    problems += check_agent_browser(refreshed)
    if fix and refreshed != readme:
        README.write_text(refreshed)
    for problem in problems:
        print(f"README.md: {problem.message}", file=sys.stderr)
    if problems:
        hint = (
            "rewrote the generated blocks; review and stage README.md"
            if fix
            else ("run `uv run python tools/readme_check.py facts --fix` for generated blocks")
        )
        print(hint, file=sys.stderr)
    return 1 if problems else 0


def line_of(text: str, index: int) -> int:
    """Return the 1-based line number of ``index`` in ``text``."""
    return text.count("\n", 0, index) + 1


def check_style(readme: str) -> list[Problem]:
    """Return what makes the README longer or noisier than it needs to be."""
    prose = COMMENT.sub("", FENCE.sub("", BLOCK.sub("", readme)))
    problems: list[Problem] = []

    words = len(WORD.findall(prose))
    if words > MAX_WORDS:
        problems.append(Problem(f"{words} words of prose; the budget is {MAX_WORDS}"))
    sections = len(SECTION.findall(prose))
    if sections > MAX_SECTIONS:
        problems.append(Problem(f"{sections} sections; the budget is {MAX_SECTIONS}"))
    badges = len(BADGE.findall(prose))
    if badges > MAX_BADGES:
        problems.append(Problem(f"{badges} badges; at most {MAX_BADGES}"))

    rules = (
        (BOILERPLATE, "boilerplate section; put the content where a reader looks for it"),
        (BOLD_LABEL_ITEM, "list item opens with a bold label; write the sentence plainly"),
        (DEEP_ITEM, "list nested more than one level; flatten it or use prose"),
        (RULE, "horizontal rule; headings already separate sections"),
    )
    # Line numbers refer to the README as written, so match against it, skipping code.
    hidden = [
        (m.start(), m.end())
        for pattern in (BLOCK, FENCE, COMMENT)
        for m in pattern.finditer(readme)
    ]
    problems.extend(
        Problem(f"line {line_of(readme, match.start())}: {message}")
        for pattern, message in rules
        for match in pattern.finditer(readme)
        if not any(start <= match.start() < end for start, end in hidden)
    )
    return problems


def style() -> int:
    """Check that the README stays short and plain."""
    problems = check_style(README.read_text())
    for problem in problems:
        print(f"README.md: {problem.message}", file=sys.stderr)
    return 1 if problems else 0


def needs_readme(message: str) -> bool:
    """Return whether a commit with ``message`` changes what users can do."""
    commit = conventional.parse(message)
    return commit.type == "feat" or commit.breaking


def missing_readme(message: str, files: list[str] | frozenset[str]) -> bool:
    """Return whether a commit with ``message`` changing ``files`` leaves the README behind."""
    no_docs = conventional.parse(message).has_trailer("Docs", "none")
    return needs_readme(message) and "README.md" not in files and not no_docs


def commit_msg(message: str, staged: list[str]) -> int:
    """Fail a user-visible commit that leaves the README untouched without saying so."""
    if not missing_readme(message, staged):
        return 0
    print(
        "This commit changes what users can do, but README.md is not staged.\n"
        "Update the README, or add a 'Docs: none' trailer if it is still accurate.",
        file=sys.stderr,
    )
    return 1


def check_range(commits: list[conventional.RangeCommit]) -> list[Problem]:
    """Return a problem for each user-visible commit in a range that left the README behind."""
    return [
        Problem(
            f"{item.sha[:12]} '{item.header}' changes what users can do but does not update "
            "README.md; update it, or add a 'Docs: none' trailer if it is still accurate"
        )
        for item in commits
        if missing_readme(item.commit.message, item.files)
    ]


def readme_range(base: str, head: str, *, skip: bool) -> int:
    """Check every commit in ``BASE..HEAD``; ``skip`` (a label) waives the check."""
    if skip:
        return 0
    problems = check_range(conventional.range_commits(base, head))
    for problem in problems:
        print(problem.message, file=sys.stderr)
    return 1 if problems else 0


def main(argv: list[str]) -> int:
    """Dispatch to ``facts``, ``style``, ``commit-msg`` or ``range``."""
    match argv:
        case ["facts"]:
            return facts(fix=False)
        case ["facts", "--fix"]:
            return facts(fix=True)
        case ["style"]:
            return style()
        case ["commit-msg", path]:
            return commit_msg(Path(path).read_text(), conventional.staged_files())
        case ["range", base, head, *flags] if flags in ([], ["--skip"]):
            return readme_range(base, head, skip=flags == ["--skip"])
        case _:
            print(__doc__, file=sys.stderr)
            return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
