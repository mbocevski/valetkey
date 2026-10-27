# SPDX-License-Identifier: Apache-2.0
import copy
from typing import Any

import delta_answers as recorded
import pytest

from valetkey import deltas, sessions


def parsed(data: dict[str, Any]) -> sessions.SnapshotDelta:
    return sessions.parse_snapshot_delta(copy.deepcopy(data))


def view_at_start() -> tuple[deltas.View, dict[str, tuple[str, str]]]:
    first = parsed(recorded.FULL)
    assert first.snapshot is not None
    refs = {name: (ref.role, ref.name) for name, ref in first.snapshot.refs.items()}
    return deltas.start(7, True, first), refs  # noqa: FBT003


# -- reading agent-browser's answers -------------------------------------------------------


def test_a_full_answer_holds_the_tree_as_written_and_its_references() -> None:
    answer = parsed(recorded.FULL)
    assert (answer.kind, answer.url, answer.revision, answer.base_revision) == (
        "full",
        recorded.ORIGIN,
        1,
        None,
    )
    assert answer.tree.startswith('- heading "Account" [level=1, ref=e1]\n- button "Go"')
    assert answer.snapshot is not None
    assert answer.snapshot.tree == answer.tree
    assert answer.snapshot.refs["e2"] == sessions.Ref("button", "Go")


def test_an_unchanged_answer_names_the_revision_it_follows() -> None:
    answer = parsed(recorded.UNCHANGED)
    assert (answer.kind, answer.revision, answer.base_revision) == ("unchanged", 2, 1)


def test_a_delta_answer_holds_its_changes_and_one_splice() -> None:
    answer = parsed(recorded.REPLACED)
    assert (answer.kind, answer.revision, answer.base_revision) == ("delta", 5, 4)
    assert answer.changes == (
        sessions.RefChange("remove", "e63"),
        sessions.RefChange("add", "e64", "link", "New link"),
        sessions.RefChange("add", "e65", "button", "Another"),
    )
    assert (answer.start_line, answer.delete_count) == (3, 1)
    assert answer.lines == ('- link "New link" [ref=e64]', '- button "Another" [ref=e65]')
    renamed = parsed(recorded.RENAMED).changes
    assert renamed == (sessions.RefChange("replace", "e4", field="name", value="Renamed"),)


@pytest.mark.parametrize(
    "data",
    [
        {"origin": "x", "snapshot": "- a plain string"},
        {"origin": "x", "snapshot": {"kind": "something else", "revision": 1}},
        {"origin": "x"},
    ],
)
def test_an_answer_that_is_not_one_of_the_three_forms_is_refused(data: dict[str, Any]) -> None:
    with pytest.raises(sessions.AgentBrowserError, match="does not document"):
        sessions.parse_snapshot_delta(data)


def test_odd_values_in_a_delta_are_read_as_empty_not_trusted() -> None:
    answer = sessions.parse_snapshot_delta(
        {
            "snapshot": {
                "kind": "delta",
                "revision": True,
                "baseRevision": "1",
                "changes": ["not an object", {"op": "add", "ref": "@e9", "node": None}],
                "treeChange": {"startLine": "0", "deleteCount": None, "lines": "no"},
            }
        }
    )
    assert (answer.revision, answer.base_revision) == (0, 0)
    assert answer.changes == (sessions.RefChange("add", "e9"),)
    assert (answer.start_line, answer.delete_count, answer.lines) == (0, 0, ())
    bare = sessions.parse_snapshot_delta({"snapshot": {"kind": "delta", "treeChange": "x"}})
    assert bare.changes == ()


# -- following them ------------------------------------------------------------------------


def test_nothing_changed_moves_the_revision_on() -> None:
    view, refs = view_at_start()
    assert deltas.follow(view, parsed(recorded.UNCHANGED), refs, 4000) == {"kind": "unchanged"}
    assert view.revision == 2


def test_a_delta_gives_the_lines_it_took_out_and_put_in_and_changes_the_references() -> None:
    view, refs = view_at_start()
    added = deltas.follow(view, parsed(recorded.ADDED), refs, 4000)
    assert added == {"kind": "delta", "removed": [], "added": ['- link "New link" [ref=e63]']}
    assert refs["e63"] == ("link", "New link")
    removed = deltas.follow(view, parsed(recorded.REMOVED), refs, 4000)
    assert removed == {"kind": "delta", "removed": ['- link "Item 0" [ref=e3]'], "added": []}
    assert "e3" not in refs
    renamed = deltas.follow(view, parsed(recorded.RENAMED), refs, 4000)
    assert renamed["removed"] == ['- link "Item 1" [ref=e4]']
    assert renamed["added"] == ['- link "Renamed" [ref=e4]']
    assert refs["e4"] == ("link", "Renamed")
    replaced = deltas.follow(view, parsed(recorded.REPLACED), refs, 4000)
    assert replaced["removed"] == ['- link "New link" [ref=e63]']
    assert len(replaced["added"]) == 2
    assert "e63" not in refs
    assert refs["e65"] == ("button", "Another")
    assert view.revision == 5
    assert view.lines == [
        '- heading "Account" [level=1, ref=e1]',
        '- button "Go" [ref=e2]',
        '- link "Renamed" [ref=e4]',
        '- link "New link" [ref=e64]',
        '- button "Another" [ref=e65]',
    ]


def test_a_replace_of_a_role_or_of_a_reference_nobody_has_is_applied_or_left() -> None:
    view, refs = view_at_start()
    answer = parsed(recorded.ADDED)
    answer = sessions.SnapshotDelta(
        "delta",
        answer.url,
        2,
        1,
        changes=(
            sessions.RefChange("replace", "e2", field="role", value="link"),
            sessions.RefChange("replace", "e2", field="colour", value="red"),
            sessions.RefChange("replace", "e99", field="name", value="nobody"),
            sessions.RefChange("remove", "e98"),
        ),
        start_line=0,
        delete_count=0,
        lines=("- a line",),
    )
    deltas.follow(view, answer, refs, 4000)
    assert refs["e2"] == ("link", "Go")
    assert "e99" not in refs


def test_changes_over_the_limit_are_not_listed_but_are_followed() -> None:
    view, refs = view_at_start()
    assert deltas.follow(view, parsed(recorded.ADDED), refs, 10) == {"kind": "large"}
    assert refs["e63"] == ("link", "New link")  # the next delta still applies
    assert view.lines is not None
    assert len(view.lines) == 5
    fits = deltas.follow(view, parsed(recorded.REMOVED), refs, 25)  # one line and its newline
    assert fits["kind"] == "delta"


def test_a_full_answer_starts_the_view_again_and_leaves_the_references() -> None:
    view, refs = view_at_start()
    again = parsed(recorded.FULL)
    again = sessions.SnapshotDelta(
        "full", again.url, 9, snapshot=again.snapshot, tree='- heading "Elsewhere"'
    )
    assert deltas.follow(view, again, refs, 4000) == {"kind": "full"}
    assert (view.revision, view.lines) == (9, ['- heading "Elsewhere"'])
    assert "e2" in refs


@pytest.mark.parametrize("base", [1, 3])
def test_a_delta_that_does_not_follow_what_the_client_read_says_the_page_changed(
    base: int,
) -> None:
    view, refs = view_at_start()
    view.revision = 2  # another client's snapshot moved the baseline
    answer = parsed(recorded.ADDED)
    answer = sessions.SnapshotDelta(
        "delta", answer.url, 3, base, changes=answer.changes, lines=answer.lines
    )
    assert deltas.follow(view, answer, refs, 4000) == {"kind": "changed"}
    assert "e63" not in refs
    assert view.lines is None
    # From then on it stays out of step, whatever the revisions say, until a snapshot starts it.
    later = sessions.SnapshotDelta("delta", answer.url, 4, 3, lines=("- x",))
    assert deltas.follow(view, later, refs, 4000) == {"kind": "changed"}


def test_a_splice_past_the_end_of_the_tree_says_the_page_changed() -> None:
    view, refs = view_at_start()
    answer = sessions.SnapshotDelta("delta", recorded.ORIGIN, 2, 1, start_line=3, delete_count=5)
    assert deltas.follow(view, answer, refs, 4000) == {"kind": "changed"}
    assert view.lines is None


# -- a splice that carries unchanged lines along -------------------------------------------------


def long_page() -> list[str]:
    """A tree of 160 lines: a header with a button, rows, and a button in the foot."""
    rows = [f'- link "Item {n} of the list of items" [ref=e{n + 10}]' for n in range(158)]
    return ['- button "Account" [ref=e2]', *rows, '- button "Cookies" [ref=e3, expanded=false]']


def two_distant_changes() -> tuple[deltas.View, dict[str, tuple[str, str]], sessions.SnapshotDelta]:
    """A view of the long page, and agent-browser's splice for a click that opens a menu at the top
    and toggles the button in the foot: one splice from the first changed line to the last."""
    old = long_page()
    new = [
        old[0],
        "- list",
        "  - listitem",
        '    - link "Orders" [ref=e900]',
        "  - listitem",
        '    - link "Settings" [ref=e901]',
        *old[1:-1],
        '- button "Cookies" [ref=e3, expanded=true]',
    ]
    view = deltas.View(7, interactive=False, revision=1, lines=list(old), url=recorded.ORIGIN)
    refs = {"e2": ("button", "Account"), "e3": ("button", "Cookies")}
    answer = sessions.SnapshotDelta(
        "delta",
        recorded.ORIGIN,
        2,
        1,
        changes=(
            sessions.RefChange("add", "e900", "link", "Orders"),
            sessions.RefChange("add", "e901", "link", "Settings"),
            sessions.RefChange("replace", "e3", field="name", value="Cookies"),
        ),
        start_line=1,
        delete_count=len(old) - 1,
        lines=tuple(new[1:]),
    )
    return view, refs, answer


def test_two_distant_changes_report_only_the_lines_that_changed() -> None:
    view, refs, answer = two_distant_changes()
    splice = sum(len(line) + 1 for line in (*answer.lines, *long_page()[1:]))
    assert splice > 4000  # the splice, as agent-browser sends it, is over the limit
    change = deltas.follow(view, answer, refs, 4000)
    assert change == {
        "kind": "delta",
        "removed": ['- button "Cookies" [ref=e3, expanded=false]'],
        "added": [
            "- list",
            " - listitem",
            '  - link "Orders" [ref=e900]',
            " - listitem",
            '  - link "Settings" [ref=e901]',
            '- button "Cookies" [ref=e3, expanded=true]',
        ],
    }
    assert refs["e900"] == ("link", "Orders")  # every reference of the delta is kept
    assert view.lines is not None
    assert len(view.lines) == 165
    assert view.lines[3] == '    - link "Orders" [ref=e900]'  # the view keeps agent-browser's lines


def test_over_the_limit_the_added_lines_with_a_reference_come_first_and_the_rest_is_counted() -> (
    None
):
    view, refs, answer = two_distant_changes()
    change = deltas.follow(view, answer, refs, 110)
    assert change == {
        "kind": "delta",
        "removed": [],
        "added": [
            '  - link "Orders" [ref=e900]',
            '  - link "Settings" [ref=e901]',
            '- button "Cookies" [ref=e3, expanded=true]',
        ],
        "more": 4,  # the list and two items, and the button's old line
    }
    assert "e901" in refs


def test_over_the_limit_with_no_reference_in_the_added_lines_is_a_lot() -> None:
    view, refs, _ = two_distant_changes()
    answer = sessions.SnapshotDelta(
        "delta",
        recorded.ORIGIN,
        2,
        1,
        start_line=1,
        delete_count=3,
        lines=tuple(f"- paragraph {n} of text that is long enough" for n in range(10)),
    )
    assert deltas.follow(view, answer, refs, 100) == {"kind": "large"}


def test_a_splice_that_changes_nothing_in_its_lines_is_no_change() -> None:
    view, refs, _ = two_distant_changes()
    assert view.lines is not None
    same = tuple(view.lines[1:4])
    answer = sessions.SnapshotDelta(
        "delta", recorded.ORIGIN, 2, 1, start_line=1, delete_count=3, lines=same
    )
    assert deltas.follow(view, answer, refs, 4000) == {"kind": "unchanged"}


def test_the_lines_shown_are_trimmed_like_a_snapshot() -> None:
    view, refs, _ = two_distant_changes()
    answer = sessions.SnapshotDelta(
        "delta",
        recorded.ORIGIN,
        2,
        1,
        start_line=1,
        delete_count=0,
        lines=(
            "- generic",
            '  - heading "Menu"',
            "    - generic",
            '      - link "Orders" [ref=e950]',
        ),
    )
    change = deltas.follow(view, answer, refs, 4000)
    assert change["added"] == ['- heading "Menu"', ' - link "Orders" [ref=e950]']


def test_a_splice_too_long_to_compare_is_taken_to_have_changed_throughout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deltas, "MAX_COMPARED", 10)
    view, refs, answer = two_distant_changes()
    change = deltas.follow(view, answer, refs, 100_000)
    assert change["kind"] == "delta"
    assert len(change["removed"]) == 159  # nothing was left out as unchanged


def test_the_lines_a_splice_begins_and_ends_with_unchanged_are_set_aside() -> None:
    old = ["- a", "- b", "- c", "- d", "- e"]
    new = ["- a", "- b", "- X", "- Y", "- d", "- e"]
    assert deltas._difference(old, new) == (["- c"], ["- X", "- Y"])  # noqa: SLF001
    assert deltas._difference(old, old) == ([], [])  # noqa: SLF001
    assert deltas._difference([], ["- new"]) == ([], ["- new"])  # noqa: SLF001
