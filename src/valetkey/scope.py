# SPDX-License-Identifier: Apache-2.0
"""Which sites a client of the daemon may act on.

``valetkey mcp --site sitex`` gives an MCP server that acts on named sites only. The server tells
the daemon its scope when it connects, and the daemon keeps it with that connection: it refuses
every request for another site, and filters what it lists. The scope is set once. Nothing the
client sends can change or widen it, and a connection that never declares one is not limited.
"""

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from valetkey import sites
from valetkey.client import DaemonError

if TYPE_CHECKING:
    from collections.abc import Iterable

OUT_OF_SCOPE = "out_of_scope"
"""The error code of a request for a site, or an operation, that the scope does not cover."""
_MAX_SHOWN = 60


@dataclass(frozen=True, slots=True)
class Scope:
    """A list of sites, each a whole site (every account) or one account of a site.

    ``entries`` holds ``(site, account)``. An account of ``None`` covers every account of the
    site, including ones made later; ``"main"`` is the account-less name ``sitex``, written
    ``sitex:main`` once a site has other accounts; any other account covers just that one.
    """

    entries: tuple[tuple[str, str | None], ...]

    @classmethod
    def parse(cls, values: Iterable[object]) -> Scope:
        """Read ``site`` and ``site:account`` entries.

        Raises:
            ValueError: when an entry is not a valid site name, or there are none.

        """
        entries: list[tuple[str, str | None]] = []
        for value in values:
            if not isinstance(value, str):
                message = "a scope is a list of site names"
                raise ValueError(message)  # noqa: TRY004 - the callers catch ValueError
            site, _, account = value.partition(sites.ACCOUNT_SEPARATOR)
            if account == sites.FIRST_ACCOUNT:
                entry = (sites.validate_site_name(site), account)
            else:
                site, account_or_none = sites.split_site_name(sites.validate_site_name(value))
                entry = (site, account_or_none)
            if entry not in entries:
                entries.append(entry)
        if not entries:
            message = "give at least one site"
            raise ValueError(message)
        return cls(tuple(entries))

    def covers(self, name: str) -> bool:
        """Tell whether the account ``name`` (``sitex`` or ``sitex:work``) is in scope."""
        site, account = sites.split_site_name(name)
        for entry_site, entry_account in self.entries:
            if entry_site != site:
                continue
            if entry_account is None:
                return True
            wanted = None if entry_account == sites.FIRST_ACCOUNT else entry_account
            if account == wanted:
                return True
        return False

    def allowed(self) -> str:
        """Return the entries as the person wrote them, for an error message."""
        return ", ".join(
            site if account is None else f"{site}{sites.ACCOUNT_SEPARATOR}{account}"
            for site, account in self.entries
        )

    def refusal(self, requested: str) -> DaemonError:
        """Return the error for a request for the site ``requested``, which is not in scope."""
        shown = json.dumps(requested[:_MAX_SHOWN])
        message = f"site {shown} is outside this server's scope (allowed: {self.allowed()})"
        return DaemonError(OUT_OF_SCOPE, message)

    def refuse_operation(self, op: str) -> DaemonError:
        """Return the error for an operation that a scoped connection may not use."""
        shown = json.dumps(op[:_MAX_SHOWN])
        message = f"{shown} is not available to a server limited to: {self.allowed()}"
        return DaemonError(OUT_OF_SCOPE, message)

    def filter_activity(self, activity: dict[str, Any]) -> dict[str, Any]:
        """Return ``activity`` (what ``status`` shows) without other sites, and without bridges."""
        return activity | {
            "sessions": [e for e in activity["sessions"] if self.covers(e["site"])],
            "logins": [e for e in activity["logins"] if self.covers(e["site"])],
            "bridges": [],
        }

    def allows_event(self, event: dict[str, Any]) -> bool:
        """Tell whether a ``watch`` event is about a site in scope (never about a bridge)."""
        site = event.get("site")
        return isinstance(site, str) and self.covers(site)
