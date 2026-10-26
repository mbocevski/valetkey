# SPDX-License-Identifier: Apache-2.0
from typing import TYPE_CHECKING

import pytest
import version_check

from valetkey import sessions

if TYPE_CHECKING:
    from pathlib import Path

TESTED = sessions.version_text(sessions.TESTED_VERSION)
MINIMUM = sessions.short_version_text(sessions.MIN_VERSION)
WORKFLOW = f"env:\n  # the tested release\n  AGENT_BROWSER_VERSION: {TESTED}\n  OTHER: 1\n"
PKGBUILD = f"depends=(\n  'agent-browser>={MINIMUM}'\n  'bubblewrap'\n)\n"


def test_the_repository_agrees() -> None:
    assert version_check.main([]) == 0


def test_a_matching_workflow_passes() -> None:
    assert version_check.check_workflow(WORKFLOW) == []


@pytest.mark.parametrize(
    "text",
    ["env:\n  AGENT_BROWSER_VERSION: 0.1.0\n", "env:\n  NOTHING: 1\n", WORKFLOW + WORKFLOW],
)
def test_a_workflow_with_another_version_fails(text: str) -> None:
    (problem,) = version_check.check_workflow(text)
    assert f"TESTED_VERSION in valetkey/sessions.py is {TESTED}" in problem.message


def test_the_message_names_what_the_workflow_installs() -> None:
    (problem,) = version_check.check_workflow("  AGENT_BROWSER_VERSION: 0.1.0\n")
    assert "installs agent-browser 0.1.0" in problem.message
    (problem,) = version_check.check_workflow("")
    assert "installs agent-browser nothing" in problem.message


def test_a_matching_pkgbuild_passes() -> None:
    assert version_check.check_pkgbuild(PKGBUILD) == []


@pytest.mark.parametrize("text", ["'agent-browser>=0.1'", "depends=('bubblewrap')", PKGBUILD * 2])
def test_a_pkgbuild_with_another_minimum_fails(text: str) -> None:
    (problem,) = version_check.check_pkgbuild(text)
    assert f"MIN_VERSION in valetkey/sessions.py is {MINIMUM}" in problem.message


def test_the_message_names_what_the_pkgbuild_depends_on() -> None:
    (problem,) = version_check.check_pkgbuild("'agent-browser>=0.1'")
    assert "depends on agent-browser>=0.1" in problem.message
    (problem,) = version_check.check_pkgbuild("")
    assert "no agent-browser dependency" in problem.message


def test_main_reports_what_disagrees(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    workflow = tmp_path / "ci.yml"
    pkgbuild = tmp_path / "PKGBUILD"
    workflow.write_text("AGENT_BROWSER_VERSION: 0.1.0\n")
    pkgbuild.write_text("'agent-browser>=0.2'\n")
    assert version_check.main([], workflow, pkgbuild) == 1
    err = capsys.readouterr().err
    assert "0.1.0" in err
    assert "0.2" in err
    workflow.write_text(WORKFLOW)
    pkgbuild.write_text(PKGBUILD)
    assert version_check.main([], workflow, pkgbuild) == 0
    assert capsys.readouterr().err == ""


def test_main_usage(capsys: pytest.CaptureFixture[str]) -> None:
    assert version_check.main(["extra"]) == 2
    assert "version_check.py" in capsys.readouterr().err
