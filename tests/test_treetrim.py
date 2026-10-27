# SPDX-License-Identifier: Apache-2.0

import re
from pathlib import Path

import pytest

from valetkey.treetrim import trim_tree

RECORDED = Path(__file__).parent / "data" / "shop_tree.txt"
"""The top of a long listing page as agent-browser wrote it (``snapshot``, whole tree), with every
name and text replaced by a placeholder. Roles, nesting, references and attributes are as
recorded."""


def lines(*rows: str) -> str:
    return "\n".join(rows)


@pytest.mark.parametrize(
    "role", ["generic", "group", "LayoutTable", "LayoutTableRow", "LayoutTableCell"]
)
def test_a_wrapper_with_no_name_ref_or_attribute_is_removed_and_its_children_move_up(
    role: str,
) -> None:
    tree = lines("- main", f"  - {role}", '    - link "A" [ref=e1]', '    - link "B" [ref=e2]')
    assert trim_tree(tree) == lines("- main", ' - link "A" [ref=e1]', ' - link "B" [ref=e2]')


@pytest.mark.parametrize(
    "wrapper",
    ['- generic "Menu"', "- generic [ref=e1]", "- group [expanded=true]", '- LayoutTableCell "x"'],
)
def test_a_wrapper_with_a_name_a_ref_or_an_attribute_is_kept(wrapper: str) -> None:
    tree = lines("- main", f"  {wrapper}", '    - link "A" [ref=e9]')
    assert trim_tree(tree) == lines("- main", f" {wrapper}", '  - link "A" [ref=e9]')


def test_nested_wrappers_collapse_over_more_than_one_level() -> None:
    tree = lines(
        "- main",
        "  - generic",
        "    - group",
        "      - generic",
        '        - heading "T" [level=1, ref=e1]',
        '          - link "T" [ref=e2]',
        "      - paragraph",
        '        - StaticText "Body"',
    )
    assert trim_tree(tree) == lines(
        "- main",
        ' - heading "T" [level=1, ref=e1]',
        '  - link "T" [ref=e2]',
        " - paragraph",
        '  - StaticText "Body"',
    )


def test_a_repeat_of_the_parents_name_is_removed() -> None:
    tree = lines(
        '- link "Logo Home" [ref=e6]',
        '  - image "Logo"',
        '  - StaticText "Home"',
        '- button "Menu" [ref=e7]',
        '  - StaticText "Menu"',
    )
    assert trim_tree(tree) == lines('- link "Logo Home" [ref=e6]', '- button "Menu" [ref=e7]')


def test_a_repeat_is_judged_against_the_nearest_node_that_is_kept() -> None:
    tree = lines(
        '- link "Read more" [ref=e1]',
        "  - generic",
        '    - StaticText "Read more"',
        '- region "Intro" [ref=e2]',
        "  - generic",
        '    - StaticText "Read more"',
    )
    assert trim_tree(tree) == lines(
        '- link "Read more" [ref=e1]',
        '- region "Intro" [ref=e2]',
        ' - StaticText "Read more"',
    )


@pytest.mark.parametrize(
    "child",
    ['StaticText "Home" [ref=e9]', 'image "Logo" [ref=e9]', 'StaticText "Other"', "StaticText"],
)
def test_a_text_node_that_is_not_a_plain_repeat_is_kept(child: str) -> None:
    tree = lines('- link "Logo Home" [ref=e6]', f"  - {child}")
    assert trim_tree(tree) == lines('- link "Logo Home" [ref=e6]', f" - {child}")


def test_text_under_a_node_with_no_name_is_kept() -> None:
    tree = lines("- paragraph", '  - StaticText "Hello"', '  - image "Hello"')
    assert trim_tree(tree) == lines("- paragraph", ' - StaticText "Hello"', ' - image "Hello"')


def test_names_are_compared_as_text_not_as_quoted_source() -> None:
    tree = lines('- link "Say \\"hi\\" now" [ref=e1]', '  - StaticText "Say \\"hi\\""')
    assert trim_tree(tree) == '- link "Say \\"hi\\" now" [ref=e1]'


def test_a_name_that_is_not_a_json_string_is_kept_as_written() -> None:
    tree = lines('- link "a\\qb" [ref=e1]', '  - StaticText "a\\qb"')
    assert trim_tree(tree) == '- link "a\\qb" [ref=e1]'


def test_text_after_a_colon_counts_as_an_attribute_and_keeps_its_node() -> None:
    tree = lines("- main", "  - generic: text", '    - link "A" [ref=e1]')
    assert trim_tree(tree) == lines("- main", " - generic: text", '  - link "A" [ref=e1]')


def test_a_line_that_is_not_a_node_is_kept_whole() -> None:
    tree = lines("- main", "  note without a dash", "  - generic", "")
    assert trim_tree(tree) == lines("- main", "  note without a dash", "")


def test_an_empty_tree_stays_empty() -> None:
    assert trim_tree("") == ""


def _quoted(tree: str) -> list[str]:
    return re.findall(r'"(?:[^"\\]|\\.)*"', tree)


def test_a_recorded_page_keeps_every_reference_attribute_and_text() -> None:
    raw = RECORDED.read_text(encoding="utf-8").rstrip("\n")
    trimmed = trim_tree(raw)
    assert re.findall(r"ref=e\d+", trimmed) == re.findall(r"ref=e\d+", raw)
    assert re.findall(r"\[[^\]]*\]", trimmed) == re.findall(r"\[[^\]]*\]", raw)
    kept = _quoted(trimmed)
    for text in set(_quoted(raw)):
        assert any(text[1:-1] in other for other in kept), text
    # Every node left is one the page had, in the same order.
    wanted = [re.sub(r"^ *", "", line) for line in raw.split("\n")]
    rest = iter(wanted)
    assert all(
        any(line == candidate for candidate in rest)
        for line in (re.sub(r"^ *", "", row) for row in trimmed.split("\n"))
    )


def test_a_recorded_page_shrinks_by_a_third_and_nests_by_one_space() -> None:
    raw = RECORDED.read_text(encoding="utf-8").rstrip("\n")
    trimmed = trim_tree(raw)
    # Measured on this 150-line tree: 6,188 characters become 3,855, 37.7% fewer.
    assert len(trimmed) <= len(raw) * 0.7
    depths = {len(row) - len(row.lstrip(" ")) for row in trimmed.split("\n")}
    assert depths == set(range(max(depths) + 1))
