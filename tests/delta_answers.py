# SPDX-License-Identifier: Apache-2.0
"""Answers of ``agent-browser snapshot -i --delta`` in the form agent-browser 0.40.0 writes them.

The keys, the ``@`` before a reference in a change, and the splice are as recorded from a local
page whose button adds a link, removes one, renames one and replaces one with two. The tree is
cut down to four nodes so that the line numbers can be read. The integration test of
``browser_click`` checks the same forms against the real thing.
"""

from typing import Any

ORIGIN = "http://site.test/"

FULL: dict[str, Any] = {
    "origin": ORIGIN,
    "snapshot": {
        "kind": "full",
        "refs": {
            "e1": {"name": "Account", "role": "heading"},
            "e2": {"name": "Go", "role": "button"},
            "e3": {"name": "Item 0", "role": "link"},
            "e4": {"name": "Item 1", "role": "link"},
        },
        "revision": 1,
        "tree": (
            '- heading "Account" [level=1, ref=e1]\n- button "Go" [ref=e2]\n'
            '- link "Item 0" [ref=e3]\n- link "Item 1" [ref=e4]'
        ),
    },
}

UNCHANGED: dict[str, Any] = {
    "origin": ORIGIN,
    "snapshot": {"baseRevision": 1, "kind": "unchanged", "revision": 2},
}

ADDED: dict[str, Any] = {
    "origin": ORIGIN,
    "snapshot": {
        "baseRevision": 1,
        "changes": [{"node": {"name": "New link", "role": "link"}, "op": "add", "ref": "@e63"}],
        "kind": "delta",
        "revision": 2,
        "treeChange": {
            "deleteCount": 0,
            "lines": ['- link "New link" [ref=e63]'],
            "startLine": 4,
        },
    },
}

REMOVED: dict[str, Any] = {
    "origin": ORIGIN,
    "snapshot": {
        "baseRevision": 2,
        "changes": [{"op": "remove", "ref": "@e3"}],
        "kind": "delta",
        "revision": 3,
        "treeChange": {"deleteCount": 1, "lines": [], "startLine": 2},
    },
}

RENAMED: dict[str, Any] = {
    "origin": ORIGIN,
    "snapshot": {
        "baseRevision": 3,
        "changes": [{"field": "name", "op": "replace", "ref": "@e4", "value": "Renamed"}],
        "kind": "delta",
        "revision": 4,
        "treeChange": {
            "deleteCount": 1,
            "lines": ['- link "Renamed" [ref=e4]'],
            "startLine": 2,
        },
    },
}

REPLACED: dict[str, Any] = {
    "origin": ORIGIN,
    "snapshot": {
        "baseRevision": 4,
        "changes": [
            {"op": "remove", "ref": "@e63"},
            {"node": {"name": "New link", "role": "link"}, "op": "add", "ref": "@e64"},
            {"node": {"name": "Another", "role": "button"}, "op": "add", "ref": "@e65"},
        ],
        "kind": "delta",
        "revision": 5,
        "treeChange": {
            "deleteCount": 1,
            "lines": ['- link "New link" [ref=e64]', '- button "Another" [ref=e65]'],
            "startLine": 3,
        },
    },
}
