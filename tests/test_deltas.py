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
