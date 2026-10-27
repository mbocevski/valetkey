# SPDX-License-Identifier: Apache-2.0
"""Follow a page as it changes, from agent-browser's ``snapshot --delta`` answers.

After a click or a typed field, the agent should learn what happened without reading the page
again. agent-browser keeps one baseline for the tab and answers ``snapshot --delta`` with the
whole tree, with ``unchanged``, or with a delta: changes to the references and one splice of the
tree's lines. A :class:`View` is what one client last saw of one site's tree: the lines, as
agent-browser wrote them (the splice counts lines in them, so they are never trimmed), and the
revision they belong to. :func:`follow` applies an answer to it and to the client's table of
references, and says what changed.

agent-browser's splice runs from the first changed line to the last. A click that changes two
places far apart (a menu opens, and something in the page's foot toggles) gives a splice that
holds every unchanged line between them. So what is reported is the difference between the lines the
splice takes out and the lines it puts in (:func:`_difference`), trimmed as a snapshot is, and
the limit applies to that.

A client can only be followed while it is the one that moved the baseline. If another client's
snapshot moved it, a delta does not apply to what this client saw, and the answer is that the page
changed, without saying how.
"""

import difflib
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from valetkey import treetrim

if TYPE_CHECKING:
    from valetkey import sessions

MAX_COMPARED = 20_000
"""The most lines, taken out and put in together, that are compared line by line. Past it every
line of the splice is taken to have changed, which costs the comparison nothing."""
_REF = re.compile(r"\bref=e\d+")


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
    url: str = ""
    """The address of the page the tree is of, as agent-browser last reported it."""


def start(generation: int, interactive: bool, answer: sessions.SnapshotDelta) -> View:  # noqa: FBT001
    """Begin a view at a whole tree: the answer of a snapshot asked for in full."""
    return View(generation, interactive, answer.revision, answer.tree.split("\n"), answer.url)


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


def _difference(old: list[str], new: list[str]) -> tuple[list[str], list[str]]:
    """Return the lines of ``old`` that are gone and the lines of ``new`` that are there now.

    The lines both have in the same order are the unchanged ones a splice carried along, and are
    left out. The lines the two begin and end with are set aside first, which is cheap and is most
    of a splice. A splice whose middle is too long to compare is taken to have changed throughout.
    """
    head = 0
    while head < min(len(old), len(new)) and old[head] == new[head]:
        head += 1
    tail = 0
    while tail < min(len(old), len(new)) - head and old[-1 - tail] == new[-1 - tail]:
        tail += 1
    old, new = old[head : len(old) - tail], new[head : len(new) - tail]
    if len(old) + len(new) > MAX_COMPARED:
        return old, new
    gone: list[str] = []
    came: list[str] = []
    matcher = difflib.SequenceMatcher(None, old, new, autojunk=False)
    for tag, old_from, old_to, new_from, new_to in matcher.get_opcodes():
        if tag != "equal":
            gone += old[old_from:old_to]
            came += new[new_from:new_to]
    return gone, came


def _shown(lines: list[str]) -> list[str]:
    """Return ``lines`` as an agent reads a snapshot: without empty wrappers, one space a level."""
    return treetrim.trim_tree("\n".join(lines)).split("\n") if lines else []


def _size(lines: list[str]) -> int:
    return sum(len(line) + 1 for line in lines)


def follow(
    view: View,
    answer: sessions.SnapshotDelta,
    refs: dict[str, tuple[str, str]],
    limit: int,
) -> dict[str, Any]:
    """Apply ``answer`` to ``view`` and ``refs``, and say what it means for the client.

    The result has a ``kind``: ``unchanged``; ``delta`` with the ``removed`` and ``added`` lines
    that really changed, when they come to ``limit`` characters or fewer; when they come to more,
    a ``delta`` with the ``added`` lines that carry a reference, as many as fit, and ``more``, the
    number of changed lines not shown, or ``large`` when none of them carries one;
    ``full`` when agent-browser sent the whole tree again (the address changed, or too much
    did); and ``changed`` when the delta does not apply to what the client saw. ``refs`` is only
    changed by a delta that applies, and the view is moved on in every case.
    """
    previous, view.revision = view.revision, answer.revision
    if answer.kind == "unchanged":
        return {"kind": "unchanged"}
    if answer.kind == "full":
        view.lines, view.url = answer.tree.split("\n"), answer.url
        return {"kind": "full"}
    start = answer.start_line
    if (
        view.lines is None
        or answer.base_revision != previous
        or start + answer.delete_count > len(view.lines)
    ):
        view.lines = None
        return {"kind": "changed"}
    taken_out = view.lines[start : start + answer.delete_count]
    view.lines[start : start + answer.delete_count] = answer.lines
    _apply_refs(refs, answer.changes)
    return _report(taken_out, list(answer.lines), limit)


def _report(taken_out: list[str], put_in: list[str], limit: int) -> dict[str, Any]:
    """Say what a splice that took out ``taken_out`` and put in ``put_in`` changed."""
    gone, came = (_shown(lines) for lines in _difference(taken_out, put_in))
    if not (gone or came):
        return {"kind": "unchanged"}  # the lines are the same: only what a splice carried along
    if _size(gone) + _size(came) <= limit:
        return {"kind": "delta", "removed": gone, "added": came}
    shown: list[str] = []
    for line in (line for line in came if _REF.search(line)):
        if _size(shown) + len(line) + 1 > limit:
            break
        shown.append(line)
    if not shown:
        return {"kind": "large"}
    more = len(gone) + len(came) - len(shown)
    return {"kind": "delta", "removed": [], "added": shown, "more": more}
