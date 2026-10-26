# SPDX-License-Identifier: Apache-2.0

import re
import subprocess
from typing import TYPE_CHECKING, Any

import conventional
import pytest
import readme_check

from valetkey import sessions

if TYPE_CHECKING:
    from pathlib import Path

REQUIREMENT = (
    f"{sessions.short_version_text(sessions.MIN_VERSION)} or newer, "
    f"tested with {sessions.version_text(sessions.TESTED_VERSION)}"
)

_VALETKEY_RUNS: dict[tuple[str, ...], subprocess.CompletedProcess[str]] = {}
_REAL_RUN = subprocess.run


def _run_once(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:  # noqa: ANN401
    """Run ``python -m valetkey ...`` for real the first time and remember the answer.

    Starting the command is most of what these tests cost, and the same few help screens are
    asked for again and again. The answer to one question about the installed program does not
    change during a test run. Anything else runs as asked.
    """
    if command[1:3] != ["-m", "valetkey"]:
        return _REAL_RUN(command, **kwargs)
    key = (*command, kwargs["env"]["COLUMNS"])
    if key not in _VALETKEY_RUNS:
        _VALETKEY_RUNS[key] = _REAL_RUN(command, **kwargs)
    return _VALETKEY_RUNS[key]


@pytest.fixture(autouse=True)
def _remember_valetkey_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(readme_check.subprocess, "run", _run_once)


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
    help_text = readme_check.run_valetkey(["sites", "--help"])
    assert all(line == line.rstrip() for line in help_text.splitlines())


def test_facts_on_this_repository() -> None:
    assert readme_check.facts(fix=False) == 0


def test_facts_fix_rewrites_a_stale_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    readme = tmp_path / "README.md"
    readme.write_text(
        "Python 3.14 or newer\n"
        f"- [agent-browser](https://example.org) {REQUIREMENT}\n"
        + block("--version", "```text\nold\n```\n")
    )
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
    monkeypatch.setattr(conventional, "staged_files", lambda: ["README.md"])
    assert readme_check.main(["commit-msg", str(message)]) == 0


def range_commit(sha: str, message: str, *files: str) -> conventional.RangeCommit:
    return conventional.RangeCommit(sha * 40, conventional.parse(message), frozenset(files))


def test_range_flags_user_visible_commits_without_the_readme() -> None:
    commits = [
        range_commit("a", "feat: add status", "src/x.py"),
        range_commit("b", "feat: add sites", "src/x.py", "README.md"),
        range_commit("c", "feat: add watch\n\nDocs: none", "src/x.py"),
        range_commit("d", "fix!: rename the socket", "src/x.py"),
        range_commit("e", "chore: tidy", "src/x.py"),
    ]
    problems = [p.message for p in readme_check.check_range(commits)]
    assert [m[:12] for m in problems] == ["a" * 12, "d" * 12]
    assert "'feat: add status' changes what users can do" in problems[0]


def test_range_command(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    commits = [range_commit("a", "feat: add status", "src/x.py")]
    monkeypatch.setattr(conventional, "range_commits", lambda *_: commits)
    assert readme_check.main(["range", "base", "head"]) == 1
    assert "does not update README.md" in capsys.readouterr().err
    assert readme_check.main(["range", "base", "head", "--skip"]) == 0
    monkeypatch.setattr(conventional, "range_commits", lambda *_: [])
    assert readme_check.main(["range", "base", "head"]) == 0


def test_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert readme_check.main([]) == 2
    assert "readme_check.py facts" in capsys.readouterr().err


def test_main_runs_facts() -> None:
    assert readme_check.main(["facts"]) == 0


def test_main_runs_facts_fix_on_a_current_readme() -> None:
    assert readme_check.main(["facts", "--fix"]) == 0


def messages(readme: str) -> list[str]:
    return [p.message for p in readme_check.check_style(readme)]


def test_plain_readme_passes_style() -> None:
    readme = "# x\n\nOne plain paragraph.\n\n## Usage\n\n- a short item\n  - one level down\n"
    assert messages(readme) == []


def test_word_budget() -> None:
    readme = "word " * (readme_check.MAX_WORDS + 1)
    assert messages(readme) == [f"701 words of prose; the budget is {readme_check.MAX_WORDS}"]


def test_code_and_generated_blocks_do_not_count() -> None:
    filler = "word " * (readme_check.MAX_WORDS + 1)
    readme = f"```text\n{filler}\n```\n" + block("--help", f"```text\n{filler}```\n") + "\n"
    assert messages(readme) == []


def test_section_budget() -> None:
    readme = "".join(f"## s{i}\n\ntext\n\n" for i in range(readme_check.MAX_SECTIONS + 1))
    assert messages(readme) == [f"9 sections; the budget is {readme_check.MAX_SECTIONS}"]


def test_badge_budget() -> None:
    badge = "![ci](https://img.shields.io/badge/ci-passing-green)"
    assert messages(badge * 4) == [f"4 badges; at most {readme_check.MAX_BADGES}"]


@pytest.mark.parametrize(
    "heading", ["## Features", "## Key features", "## Overview", "### Why valetkey?", "## Summary"]
)
def test_boilerplate_sections(heading: str) -> None:
    assert messages(f"# x\n\n{heading}\n\ntext\n") == [
        "line 3: boilerplate section; put the content where a reader looks for it"
    ]


@pytest.mark.parametrize(
    "item", ["- **Fast:** it is fast", "1. **Step one.** do it", "* __Bold__ x"]
)
def test_bold_label_items(item: str) -> None:
    assert messages(f"# x\n\n{item}\n") == [
        "line 3: list item opens with a bold label; write the sentence plainly"
    ]


def test_deeply_nested_list() -> None:
    readme = "- a\n  - b\n    - c\n"
    assert messages(readme) == ["line 3: list nested more than one level; flatten it or use prose"]


def test_horizontal_rule() -> None:
    assert messages("# x\n\ntext\n\n---\n\nmore\n") == [
        "line 5: horizontal rule; headings already separate sections"
    ]


def test_rules_inside_code_are_ignored() -> None:
    readme = "```md\n## Features\n- **Bold:** x\n---\n```\n"
    assert messages(readme) == []


def test_style_on_this_repository() -> None:
    assert readme_check.main(["style"]) == 0


def test_style_reports_problems(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    readme = tmp_path / "README.md"
    readme.write_text("## Overview\n")
    monkeypatch.setattr(readme_check, "README", readme)
    assert readme_check.style() == 1
    assert "README.md: line 1: boilerplate section" in capsys.readouterr().err


def test_agent_browser_requirement_states_the_minimum_and_the_tested_version() -> None:
    wanted = REQUIREMENT
    good = f"- [agent-browser](https://example.org) {wanted}\n"
    assert readme_check.check_agent_browser(good) == []
    for bad in (
        "- [agent-browser](https://example.org) 0.1 or newer\n",
        "- [agent-browser](https://example.org) 0.1 or newer, tested with 0.1.0\n",
        "no such line\n",
    ):
        (problem,) = readme_check.check_agent_browser(bad)
        assert wanted in problem.message
