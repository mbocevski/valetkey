# SPDX-License-Identifier: Apache-2.0
"""Trim an accessibility tree to what an agent reads, keeping every reference and every text.

agent-browser writes a tree one node to a line: ``- role "name" [attributes]``, indented two
spaces per level. On a real page a fifth to two fifths of that text carries nothing. This module
removes the nodes that carry nothing and writes one space per level:

* A ``generic``, ``group`` or layout table node with no name and no attributes (a reference is an
  attribute) is dropped, and its children move up a level.
* A ``StaticText`` or ``image`` node with no reference or other attribute whose name is part of
  the name of the nearest node that is kept above it is dropped: the text is already there.

Anything else stays as it was, including every line this module cannot read.
"""

import json
import re

EMPTY_ROLES = frozenset({"generic", "group", "LayoutTable", "LayoutTableRow", "LayoutTableCell"})
"""The roles of nodes that only group others, so that they carry nothing when they have no name."""
REPEATING_ROLES = frozenset({"StaticText", "image"})
"""The roles of nodes that repeat the name of the node they sit in, when they have no reference."""
_INDENT = 2
_NODE = re.compile(r'( *)- ([^\s":]+)(?: ("(?:[^"\\]|\\.)*"))?(?: (\[.*\]))?(:.*)?')


def trim_tree(tree: str) -> str:
    """Return ``tree`` without its empty wrappers and repeated text, one space to a level."""
    kept_names: list[tuple[int, str]] = []  # (input depth, name) of the kept nodes above
    lines: list[str] = []
    for line in tree.split("\n"):
        match = _NODE.fullmatch(line)
        if match is None:
            lines.append(line)
            continue
        spaces, role, quoted, attributes, tail = match.groups()
        depth = len(spaces) // _INDENT
        while kept_names and kept_names[-1][0] >= depth:
            kept_names.pop()
        name = _decode(quoted)
        if _drops(role, name, attributes or tail, kept_names[-1][1] if kept_names else ""):
            continue
        lines.append(" " * len(kept_names) + line.lstrip(" "))
        kept_names.append((depth, name))
    return "\n".join(lines)


def _decode(quoted: str | None) -> str:
    """Return the text of a quoted name, or an empty string when there is none."""
    if quoted is None:
        return ""
    try:
        decoded = json.loads(quoted)
    except ValueError:
        return quoted[1:-1]
    return decoded if isinstance(decoded, str) else quoted[1:-1]


def _drops(role: str, name: str, attributes: str | None, above: str) -> bool:
    """Tell whether a node carries nothing the nodes around it do not."""
    if role in EMPTY_ROLES:
        return not name and attributes is None
    return role in REPEATING_ROLES and attributes is None and bool(name) and name in above
