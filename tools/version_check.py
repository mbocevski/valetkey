# SPDX-License-Identifier: Apache-2.0
"""Keep the agent-browser versions in step.

    python tools/version_check.py

``valetkey.sessions`` holds two versions: the oldest agent-browser valetkey drives
(``MIN_VERSION``) and the one it was tested with (``TESTED_VERSION``). Two files outside the
code repeat them and must agree:

* the CI workflow installs the tested version, in ``AGENT_BROWSER_VERSION``;
* the Arch PKGBUILD depends on ``agent-browser>=`` the minimum.

The README's requirements say the same, and ``tools/readme_check.py facts`` checks that.
"""

import re
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

import conventional

from valetkey import sessions

if TYPE_CHECKING:
    from pathlib import Path

WORKFLOW = conventional.ROOT / ".github" / "workflows" / "ci.yml"
PKGBUILD = conventional.ROOT / "packaging" / "arch" / "PKGBUILD"

TESTED_LINE = re.compile(r"^\s*AGENT_BROWSER_VERSION:\s*(\S+)\s*$", re.MULTILINE)
DEPENDS_LINE = re.compile(r"'agent-browser>=([^']+)'")


@dataclass(frozen=True)
class Problem:
    """Two places that name a version and disagree."""

    message: str


def check_workflow(text: str) -> list[Problem]:
    """Return a problem unless the workflow installs the version valetkey was tested with."""
    tested = sessions.version_text(sessions.TESTED_VERSION)
    found = TESTED_LINE.findall(text)
    if found == [tested]:
        return []
    shown = ", ".join(found) or "nothing"
    return [
        Problem(
            f"{WORKFLOW.name} installs agent-browser {shown}, but TESTED_VERSION in "
            f"valetkey/sessions.py is {tested}"
        )
    ]


def check_pkgbuild(text: str) -> list[Problem]:
    """Return a problem unless the PKGBUILD depends on the minimum agent-browser."""
    minimum = sessions.short_version_text(sessions.MIN_VERSION)
    found = DEPENDS_LINE.findall(text)
    if found == [minimum]:
        return []
    shown = ", ".join(found) or "no agent-browser dependency"
    return [
        Problem(
            f"PKGBUILD depends on agent-browser>={shown}, but MIN_VERSION in "
            f"valetkey/sessions.py is {minimum}"
        )
    ]


def main(argv: list[str], workflow: Path = WORKFLOW, pkgbuild: Path = PKGBUILD) -> int:
    """Check both files and report what disagrees."""
    if argv:
        print(__doc__, file=sys.stderr)
        return 2
    problems = check_workflow(workflow.read_text()) + check_pkgbuild(pkgbuild.read_text())
    for problem in problems:
        print(problem.message, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
