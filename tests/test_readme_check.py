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
    err = capsys.readouterr().err
    assert "neither README.md nor a page under docs/ is staged" in err


def test_feature_with_readme_passes() -> None:
    assert readme_check.commit_msg("feat: add status", ["src/x.py", "README.md"]) == 0


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        (["README.md"], True),
        (["docs/commands.md"], True),
        (["docs/deep/er/page.md"], True),
        (["src/x.py", "docs/security.md"], True),
        ([], False),
        (["src/x.py"], False),
        (["docs/image.png"], False),
        (["docs/notes.txt"], False),
        (["docs"], False),
        (["docs.md"], False),
        (["mydocs/page.md"], False),
        (["src/docs/page.md"], False),
        (["docs-old/page.md"], False),
        (["docs/page.md.bak"], False),
        (["README.md.orig"], False),
        (["sub/README.md"], False),
    ],
)
def test_touches_docs(files: list[str], *, expected: bool) -> None:
    assert readme_check.touches_docs(files) is expected


def test_feature_with_a_docs_page_passes() -> None:
    assert readme_check.commit_msg("feat: add status", ["src/x.py", "docs/commands.md"]) == 0
    assert readme_check.commit_msg("fix!: rename it", ["docs/mcp.md"]) == 0


def test_feature_with_only_an_unrelated_markdown_file_fails() -> None:
    assert readme_check.commit_msg("feat: add status", ["CHANGELOG.md", "AGENTS.md"]) == 1


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
    monkeypatch.setattr(readme_check, "DOCS", tmp_path / "docs")
    monkeypatch.setattr(readme_check, "COMMANDS_PAGE", tmp_path / "docs" / "commands.md")
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
        range_commit("f", "feat: add add", "src/x.py", "docs/commands.md"),
        range_commit("g", "feat: add more", "src/x.py", "CHANGELOG.md"),
    ]
    problems = [p.message for p in readme_check.check_range(commits)]
    assert [m[:12] for m in problems] == ["a" * 12, "d" * 12, "g" * 12]
    assert "'feat: add status' changes what users can do" in problems[0]


def test_range_command(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    commits = [range_commit("a", "feat: add status", "src/x.py")]
    monkeypatch.setattr(conventional, "range_commits", lambda *_: commits)
    assert readme_check.main(["range", "base", "head"]) == 1
    assert "does not update README.md or a page under docs/" in capsys.readouterr().err
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
    monkeypatch.setattr(readme_check, "DOCS", tmp_path / "docs")
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


# -- the pages in docs/ ------------------------------------------------------------------------

HELP = """Usage: valetkey COMMAND

Commands:
  allow: Allow a host.
  sites: List the sites.
  --help, -h: Display this message and exit.
  --version: Display application version.
"""


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A README, a docs folder and a project file the checks read instead of the real ones."""
    (tmp_path / "docs").mkdir()
    (tmp_path / "pyproject.toml").write_text(PYPROJECT)
    (tmp_path / "README.md").write_text(
        f"Python 3.14 or newer\n- [agent-browser](https://example.org) {REQUIREMENT}\n"
    )
    monkeypatch.setattr(readme_check, "README", tmp_path / "README.md")
    monkeypatch.setattr(readme_check, "DOCS", tmp_path / "docs")
    monkeypatch.setattr(readme_check, "COMMANDS_PAGE", tmp_path / "docs" / "commands.md")
    monkeypatch.setattr(readme_check, "PYPROJECT", tmp_path / "pyproject.toml")
    monkeypatch.setattr(readme_check, "run_valetkey", fake_run)
    return tmp_path


def test_documents_are_the_readme_and_every_page(workspace: Path) -> None:
    (workspace / "docs" / "b.md").write_text("b\n")
    (workspace / "docs" / "a.md").write_text("a\n")
    (workspace / "docs" / "notes.txt").write_text("not a page\n")
    assert [p.name for p in readme_check.documents()] == ["README.md", "a.md", "b.md"]


def test_the_commands_come_from_the_help() -> None:
    assert readme_check.listed_commands(HELP) == ["allow", "sites"]


def test_every_command_needs_a_block_in_the_commands_page() -> None:
    page = block("allow --help", "x\n") + block("sites --help", "y\n") + block("--help", "z\n")
    assert readme_check.check_commands(page, ["allow", "sites"]) == []
    (problem,) = readme_check.check_commands(block("allow --help", "x\n"), ["allow", "sites"])
    assert "`valetkey sites` has no help block" in problem.message
    assert "begin: valetkey sites --help" in problem.message
    assert len(readme_check.check_commands("", ["allow", "sites"])) == 2


def test_facts_checks_the_blocks_of_every_page(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    page = workspace / "docs" / "install.md"
    page.write_text(block("--version", "```text\nold\n```\n") + "\n")
    assert readme_check.facts(fix=False) == 1
    assert "install.md: the output of `valetkey --version` has changed" in capsys.readouterr().err
    assert readme_check.facts(fix=True) == 1
    assert "valetkey " in page.read_text()
    assert "old" not in page.read_text()
    assert readme_check.facts(fix=False) == 0


def test_facts_wants_every_command_in_the_commands_page(
    workspace: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(readme_check, "run_valetkey", lambda _args: HELP)
    page = workspace / "docs" / "commands.md"
    page.write_text(block("allow --help", "```text\nold\n```\n") + "\n")
    assert readme_check.facts(fix=True) == 1
    err = capsys.readouterr().err
    assert "commands.md: `valetkey sites` has no help block" in err
    page.write_text(page.read_text() + block("sites --help", "```text\nold\n```\n") + "\n")
    readme_check.facts(fix=True)  # settles the block just added
    assert readme_check.facts(fix=False) == 0


@pytest.mark.usefixtures("workspace")
def test_facts_without_a_commands_page_does_not_ask_for_one() -> None:
    assert readme_check.facts(fix=False) == 0


def test_a_relative_link_must_point_at_a_file(tmp_path: Path) -> None:
    (tmp_path / "other.md").write_text("x\n")
    text = (
        "[ok](other.md) [fragment](other.md#part) [site](https://example.org/x) "
        "[mail](mailto:a@b.c) [here](#top) [gone](missing.md) [gone too](missing.md#part)\n"
    )
    problems = [p.message for p in readme_check.check_links(text, tmp_path)]
    assert problems == ["line 1: no file at missing.md", "line 1: no file at missing.md#part"]


def test_links_in_code_and_generated_blocks_are_not_checked(tmp_path: Path) -> None:
    text = "```md\n[x](missing.md)\n```\n" + block("--help", "```text\n[y](gone.md)\n```\n")
    assert readme_check.check_links(text, tmp_path) == []


def test_facts_reports_a_broken_link_in_a_page(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (workspace / "docs" / "a.md").write_text("see [b](b.md)\n")
    assert readme_check.facts(fix=False) == 1
    assert "a.md: line 1: no file at b.md" in capsys.readouterr().err
    (workspace / "docs" / "b.md").write_text("b\n")
    assert readme_check.facts(fix=False) == 0


def docs_messages(page: str) -> list[str]:
    return [p.message for p in readme_check.check_docs_style(page)]


def test_a_page_with_short_sections_passes() -> None:
    assert docs_messages("# Page\n\nSome words.\n\n## Part\n\nMore words.\n") == []


def test_a_long_section_is_reported_by_name() -> None:
    long = " ".join(["word"] * (readme_check.MAX_SECTION_WORDS + 1))
    page = f"# Page\n\nShort.\n\n## The long one\n\n{long}\n\n## After\n\nShort.\n"
    limit = readme_check.MAX_SECTION_WORDS
    assert docs_messages(page) == [
        f"section 'The long one' has {limit + 1} words; the limit is {limit}"
    ]


def test_a_section_at_the_limit_passes_and_the_last_section_counts() -> None:
    at_limit = " ".join(["word"] * readme_check.MAX_SECTION_WORDS)
    assert docs_messages(f"## One\n\n{at_limit}\n") == []
    assert len(docs_messages(f"## One\n\n{at_limit} more\n")) == 1


def test_generated_blocks_and_code_do_not_count_toward_a_section() -> None:
    filler = "\n".join(["output line"] * 500)
    page = f"## One\n\n```text\n{filler}\n```\n\n" + block("--help", f"```text\n{filler}\n```\n")
    assert docs_messages(page) == []


def test_pages_have_no_word_budget_or_section_count() -> None:
    sections = "".join(
        f"## Part {n}\n\nWords here.\n\n" for n in range(readme_check.MAX_SECTIONS + 4)
    )
    assert docs_messages(sections) == []


def test_pages_get_the_shape_rules() -> None:
    page = "## Overview\n\n- **Bold:** x\n\n---\n"
    found = docs_messages(page)
    assert any("boilerplate section" in m for m in found)
    assert any("bold label" in m for m in found)
    assert any("horizontal rule" in m for m in found)


def test_style_checks_the_pages_too(workspace: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert readme_check.style() == 0
    (workspace / "docs" / "a.md").write_text("## Summary\n")
    assert readme_check.style() == 1
    assert "a.md: line 1: boilerplate section" in capsys.readouterr().err


def test_a_path_outside_the_repository_is_shown_whole(tmp_path: Path) -> None:
    assert readme_check.shown(tmp_path / "x.md") == str(tmp_path / "x.md")
    assert readme_check.shown(conventional.ROOT / "docs" / "x.md") == "docs/x.md"


def test_the_commands_page_exists_and_documents_every_command() -> None:
    assert readme_check.COMMANDS_PAGE.is_file()
    page = readme_check.COMMANDS_PAGE.read_text()
    help_text = readme_check.run_valetkey(["--help"])
    assert readme_check.check_commands(page, readme_check.listed_commands(help_text)) == []
