# SPDX-License-Identifier: Apache-2.0
"""Follow a page as it changes, from agent-browser's ``snapshot --delta`` answers.

After a click or a typed field, the agent should learn what happened without reading the page
again. agent-browser keeps one baseline for the tab and answers ``snapshot --delta`` with the
whole tree, with ``unchanged``, or with a delta: changes to the references and one splice of the
tree's lines. A :class:`View` is what one client last saw of one site's tree: the lines, as
agent-browser wrote them (the splice counts lines in them, so they are never trimmed), and the
revision they belong to. :func:`follow` applies an answer to it and to the client's table of
references, and says what changed.

A client can only be followed while it is the one that moved the baseline. If another client's
snapshot moved it, a delta does not apply to what this client saw, and the answer is that the page
changed, without saying how.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from valetkey import sessions


@dataclass(eq=False)
class View:
    """What a client last saw of a site's tree, and where agent-browser's baseline stood."""

    generation: int
    """The session the tree belongs to."""
    interactive: bool
    """Whether it is the interactive tree or the whole one: the options of the last snapshot."""
    revision: int
    lines: list[str] | None
    """The tree's lines, or ``None`` once the client is out of step with the baseline."""


def start(generation: int, interactive: bool, answer: sessions.SnapshotDelta) -> View:  # noqa: FBT001
    """Begin a view at a whole tree: the answer of a snapshot asked for in full."""
    return View(generation, interactive, answer.revision, answer.tree.split("\n"))


def _apply_refs(refs: dict[str, tuple[str, str]], changes: tuple[sessions.RefChange, ...]) -> None:
    """Apply the reference changes of a delta to a client's table of ``{ref: (role, name)}``."""
    for change in changes:
        if change.op == "add":
            refs[change.ref] = (change.role, change.name)
        elif change.op == "remove":
            refs.pop(change.ref, None)
        elif change.op == "replace" and change.ref in refs:
            role, name = refs[change.ref]
            if change.field == "name":
                refs[change.ref] = (role, change.value)
            elif change.field == "role":
                refs[change.ref] = (change.value, name)


def follow(
    view: View,
    answer: sessions.SnapshotDelta,
    refs: dict[str, tuple[str, str]],
    limit: int,
) -> dict[str, Any]:
    """Apply ``answer`` to ``view`` and ``refs``, and say what it means for the client.

    The result has a ``kind``: ``unchanged``; ``delta`` with the ``removed`` and ``added`` lines,
    when they come to ``limit`` characters or fewer; ``large`` when they come to more;
    ``full`` when agent-browser sent the whole tree again (the address changed, or too much
    did); and ``changed`` when the delta does not apply to what the client saw. ``refs`` is only
    changed by a delta that applies, and the view is moved on in every case.
    """
    previous, view.revision = view.revision, answer.revision
    if answer.kind == "unchanged":
        return {"kind": "unchanged"}
    if answer.kind == "full":
        view.lines = answer.tree.split("\n")
        return {"kind": "full"}
    start = answer.start_line
    if (
        view.lines is None
        or answer.base_revision != previous
        or start + answer.delete_count > len(view.lines)
    ):
        view.lines = None
        return {"kind": "changed"}
    removed = view.lines[start : start + answer.delete_count]
    view.lines[start : start + answer.delete_count] = answer.lines
    _apply_refs(refs, answer.changes)
    size = sum(len(line) + 1 for line in (*removed, *answer.lines))
    if size > limit:
        return {"kind": "large"}
    return {"kind": "delta", "removed": removed, "added": list(answer.lines)}
