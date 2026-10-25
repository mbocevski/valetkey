# SPDX-License-Identifier: Apache-2.0
"""Keep README.md in step with the code.

    python tools/readme_check.py facts [--fix]
    python tools/readme_check.py commit-msg MESSAGE_FILE

``facts`` checks what the README states about the code. A block between
``<!-- begin: valetkey ARGS -->`` and ``<!-- end: valetkey ARGS -->`` must hold the
output of ``valetkey ARGS`` in a ``text`` code fence; ``--fix`` rewrites stale blocks.
The README must also state the Python version that ``requires-python`` sets.

``commit-msg`` checks whether a commit should have changed the README. A ``feat``
commit or a breaking change alters what users can do, so it must stage README.md,
or carry a ``Docs: none`` trailer that records the README is still accurate.
"""

import os
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
PYPROJECT = ROOT / "pyproject.toml"

BLOCK = re.compile(
    r"(?P<begin><!-- begin: valetkey(?P<args>[^>]*?) -->\n)"
    r"(?P<body>.*?)"
    r"(?P<end><!-- end: valetkey(?P=args) -->)",
    re.DOTALL,
)
HEADER = re.compile(
    r"\A(?P<type>[a-z]+)(?:\([a-z0-9-]+\))?(?P<bang>!)?: ",
)
BREAKING_FOOTER = re.compile(r"^BREAKING[ -]CHANGE: ", re.MULTILINE)
NO_DOCS_TRAILER = re.compile(r"^Docs: none$", re.MULTILINE | re.IGNORECASE)
HELP_WIDTH = "80"


@dataclass(frozen=True)
class Problem:
    """Something in the README that no longer matches the code."""

    message: str


def run_valetkey(args: list[str]) -> str:
    """Return what ``valetkey ARGS`` prints, at a fixed width and without colour."""
    env = os.environ | {"COLUMNS": HELP_WIDTH, "NO_COLOR": "1", "TERM": "dumb"}
    result = subprocess.run(  # noqa: S603 - runs this interpreter on fixed arguments
        [sys.executable, "-m", "valetkey", *args],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    return result.stdout.rstrip() + "\n"


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


def facts(*, fix: bool) -> int:
    """Check the README's statements about the code, rewriting stale blocks if ``fix``."""
    readme = README.read_text()
    refreshed, problems = check_blocks(readme)
    problems += check_python(refreshed, PYPROJECT.read_text())
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


def needs_readme(message: str) -> bool:
    """Return whether a commit with ``message`` changes what users can do."""
    header = HEADER.match(message)
    if header is None:
        return False
    return header["type"] == "feat" or bool(header["bang"]) or bool(BREAKING_FOOTER.search(message))


def commit_msg(message: str, staged: list[str]) -> int:
    """Fail a user-visible commit that leaves the README untouched without saying so."""
    if not needs_readme(message) or "README.md" in staged or NO_DOCS_TRAILER.search(message):
        return 0
    print(
        "This commit changes what users can do, but README.md is not staged.\n"
        "Update the README, or add a 'Docs: none' trailer if it is still accurate.",
        file=sys.stderr,
    )
    return 1


def staged_files() -> list[str]:
    """Return the paths staged for the commit in progress."""
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],  # noqa: S607 - git from PATH, as hooks do
        capture_output=True,
        text=True,
        check=True,
        cwd=ROOT,
    )
    return result.stdout.split()


def main(argv: list[str]) -> int:
    """Dispatch to ``facts`` or ``commit-msg``."""
    match argv:
        case ["facts"]:
            return facts(fix=False)
        case ["facts", "--fix"]:
            return facts(fix=True)
        case ["commit-msg", path]:
            return commit_msg(Path(path).read_text(), staged_files())
        case _:
            print(__doc__, file=sys.stderr)
            return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
