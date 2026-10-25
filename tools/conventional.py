# SPDX-License-Identifier: Apache-2.0
"""Read Conventional Commits messages the same way in every check."""

import re
from dataclasses import dataclass

HEADER = re.compile(r"\A(?P<type>[a-z]+)(?:\((?P<scope>[a-z0-9-]+)\))?(?P<bang>!)?: ")
BREAKING_FOOTER = re.compile(r"^BREAKING[ -]CHANGE: ", re.MULTILINE)

# The types whose changes a user can notice.
USER_FACING_TYPES = frozenset({"feat", "fix", "perf", "revert"})


@dataclass(frozen=True)
class Commit:
    """The parts of a commit message the checks care about."""

    message: str
    type: str | None
    scope: str | None
    breaking: bool

    @property
    def user_facing(self) -> bool:
        """Whether users can notice this change."""
        return self.breaking or self.type in USER_FACING_TYPES

    def has_trailer(self, key: str, value: str) -> bool:
        """Whether the message carries the trailer ``KEY: VALUE`` (case-insensitive)."""
        pattern = rf"^{re.escape(key)}:[ \t]*{re.escape(value)}[ \t]*$"
        return re.search(pattern, self.message, re.MULTILINE | re.IGNORECASE) is not None


def parse(message: str) -> Commit:
    """Parse a commit message; a header that is not conventional leaves the type empty."""
    header = HEADER.match(message)
    if header is None:
        return Commit(message=message, type=None, scope=None, breaking=False)
    breaking = bool(header["bang"]) or BREAKING_FOOTER.search(message) is not None
    return Commit(message=message, type=header["type"], scope=header["scope"], breaking=breaking)
