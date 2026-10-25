# SPDX-License-Identifier: Apache-2.0

import re
from typing import TYPE_CHECKING

import pytest
import readme_check

if TYPE_CHECKING:
    from pathlib import Path

PYPROJECT = '[project]\nname = "x"\nrequires-python = ">=3.14"\n'


def fake_run(args: list[str]) -> str:
    return f"output of {' '.join(args)}\n"


def block(args: str, body: str) -> str:
    return f"<!-- begin: valetkey {args} -->\n{body}<!-- end: valetkey {args} -->"


def test_current_block_passes() -> None:
    readme = "# x\n\n" + block("--help", "```text\noutput of --help\n```\n") + "\n"
    refreshed, problems = readme_check.check_blocks(readme, fake_run)
    assert problems == []
    assert refreshed == readme


def test_stale_block_is_reported_and_refreshed() -> None:
    readme = block("--help", "```text\nold\n```\n")
    refreshed, problems = readme_check.check_blocks(readme, fake_run)
    assert [p.message for p in problems] == ["the output of `valetkey --help` has changed"]
    assert "output of --help" in refreshed
    assert "old" not in refreshed


def test_each_block_runs_its_own_command() -> None:
    readme = block("--help", "") + "\n" + block("status --help", "")
    refreshed, problems = readme_check.check_blocks(readme, fake_run)
    assert len(problems) == 2
    assert "output of --help" in refreshed
    assert "output of status --help" in refreshed


def test_python_requirement_matches() -> None:
    assert readme_check.check_python("Python 3.14 or newer", PYPROJECT) == []


def test_python_requirement_is_stale() -> None:
    problems = readme_check.check_python("Python 3.12 or newer", PYPROJECT)
    assert [p.message for p in problems] == ["the requirements must say 'Python 3.14 or newer'"]


def test_unsupported_requires_python_is_an_error() -> None:
    with pytest.raises(ValueError, match=re.escape("plain '>=X.Y'")):
        readme_check.required_python('[project]\nrequires-python = "~=3.14"\n')


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("feat: add the status command", True),
        ("feat(cli): add the status command", True),
        ("fix!: rename the socket", True),
        ("refactor: move code\n\nBREAKING CHANGE: the socket moved", True),
        ("fix: handle a closed socket", False),
        ("docs: reword the README", False),
        ("not a conventional header", False),
    ],
)
def test_needs_readme(*, message: str, expected: bool) -> None:
    assert readme_check.needs_readme(message) is expected


def test_feature_without_readme_fails(capsys: pytest.CaptureFixture[str]) -> None:
    assert readme_check.commit_msg("feat: add status", ["src/valetkey/cli.py"]) == 1
    assert "README.md is not staged" in capsys.readouterr().err


def test_feature_with_readme_passes() -> None:
    assert readme_check.commit_msg("feat: add status", ["src/x.py", "README.md"]) == 0


def test_feature_with_no_docs_trailer_passes() -> None:
    message = "feat: add status\n\nThe README already covers it.\n\nDocs: none\n"
    assert readme_check.commit_msg(message, ["src/x.py"]) == 0


def test_fix_never_needs_readme() -> None:
    assert readme_check.commit_msg("fix: handle a closed socket", ["src/x.py"]) == 0


def test_runs_valetkey_at_a_fixed_width() -> None:
    assert readme_check.run_valetkey(["--version"]).startswith("valetkey ")


def test_facts_on_this_repository() -> None:
    assert readme_check.facts(fix=False) == 0


def test_facts_fix_rewrites_a_stale_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    readme = tmp_path / "README.md"
    readme.write_text("Python 3.14 or newer\n" + block("--version", "```text\nold\n```\n"))
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(PYPROJECT)
    monkeypatch.setattr(readme_check, "README", readme)
    monkeypatch.setattr(readme_check, "PYPROJECT", pyproject)
    assert readme_check.facts(fix=True) == 1
    assert "rewrote the generated blocks" in capsys.readouterr().err
    assert "valetkey " in readme.read_text()
    assert readme_check.facts(fix=False) == 0


def test_commit_msg_reads_the_message_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    message = tmp_path / "COMMIT_EDITMSG"
    message.write_text("feat: add status\n")
    monkeypatch.setattr(readme_check, "staged_files", lambda: ["README.md"])
    assert readme_check.main(["commit-msg", str(message)]) == 0


def test_staged_files_lists_the_index() -> None:
    assert isinstance(readme_check.staged_files(), list)


def test_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert readme_check.main([]) == 2
    assert "readme_check.py facts" in capsys.readouterr().err


def test_main_runs_facts() -> None:
    assert readme_check.main(["facts"]) == 0


def test_main_runs_facts_fix_on_a_current_readme() -> None:
    assert readme_check.main(["facts", "--fix"]) == 0
