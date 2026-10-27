# SPDX-License-Identifier: Apache-2.0
"""Download collection: what each client is told about the files a site's browser saves.

The files arrive in the site's downloads directory (see :mod:`valetkey.downloads`). Each client
connection remembers which of them it has been told about, per site, so a ``click``, a
``navigate`` or a ``downloads`` answer lists only what is new to that client.
"""

import asyncio
import contextlib
from typing import TYPE_CHECKING, Any

from valetkey import downloads, sessions, sites
from valetkey.protocol import untrusted

if TYPE_CHECKING:
    from valetkey.client import DaemonError
    from valetkey.registry import Connection, Registry, Site


MAX_STARTED = 10
"""The most unsaved downloads a result names; the count is always complete."""


def _download_entry(item: downloads.Download) -> dict[str, Any]:
    """Describe a download for a client. The page chose the name in the path, so it is untrusted."""
    return {"path": untrusted(str(item.path)), "size": item.size, "mime": item.mime}


class Downloads:
    """Report the downloads of a site's browser to the clients that ask.

    ``settle`` is how long to look for a download that a click has only just started, and
    ``wait`` is the longest to wait for downloads that are running.
    """

    def __init__(self, registry: Registry, *, settle: float, wait: float) -> None:
        """Create the collector for the sites of ``registry``."""
        self.registry = registry
        self.roots = registry.roots
        self._settle = settle
        self._wait = wait

    async def seen_downloads(
        self, connection: Connection, site: str
    ) -> dict[str, downloads.Signature]:
        """Return the downloads this client already knows of, starting from what is there now."""
        directory = sites.downloads_path(self.roots, site)
        if site not in connection.seen_downloads:
            connection.seen_downloads[site] = await asyncio.to_thread(downloads.snapshot, directory)
        return connection.seen_downloads[site]

    async def new_downloads(
        self,
        connection: Connection,
        state: Site,
        seen: dict[str, downloads.Signature],
        settle: float | None = None,
        *,
        unprompted: bool = False,
    ) -> dict[str, Any]:
        """Report the files that arrived since ``seen``, waiting a little for running ones.

        Responses logged since the call began that said ``attachment`` are the downloads the
        browser started. Any beyond the files that arrived and the ones still running are
        counted as ``unsaved``: the browser started a download and nothing was written, as it
        does when the file name is too long. Then ``started`` lists them (at most
        :data:`MAX_STARTED`, untrusted), and ``by_page`` says the call was one that clicks nothing,
        so the page started them itself.
        """
        site = state.name
        paths = sessions.session_paths(self.roots, site)
        found = await asyncio.to_thread(
            downloads.collect,
            paths.downloads_dir,
            seen,
            incoming=paths.incoming_dir,
            settle=self._settle if settle is None else settle,
            finish=self._wait,
        )
        connection.seen_downloads[site] = found.seen
        started = await self.started(state)
        report: dict[str, Any] = {
            "new": [_download_entry(item) for item in found.new],
            "in_progress": [_download_entry(item) for item in found.in_progress],
            "unsaved": max(0, len(started) - len(found.new) - len(found.in_progress)),
        }
        if report["unsaved"]:
            report["started"] = [
                {"url": untrusted(item.url), "name": untrusted(item.name)}
                for item in started[:MAX_STARTED]
            ]
            report["by_page"] = unprompted
        return report

    async def started(self, state: Site) -> list[sessions.Attachment]:
        """List the responses logged since the call began that the browser turns into downloads."""
        session = state.session
        if session is None:
            return []
        with contextlib.suppress(sessions.AgentBrowserError, sessions.SessionError):
            return await asyncio.to_thread(session.started_downloads)
        return []

    async def navigation_that_downloaded(
        self,
        connection: Connection,
        state: Site,
        seen: dict[str, downloads.Signature],
        error: DaemonError,
    ) -> dict[str, Any]:
        """Turn the failure of a navigation that became a download into an answer.

        A URL that answers with an attachment is not a page: the browser aborts the navigation
        and starts a download. If a download did start, say so instead of reporting a failure;
        otherwise the failure stands.
        """
        if error.code != "browser_error" or "ERR_ABORTED" not in error.message:
            raise error
        found = await self.new_downloads(connection, state, seen, self._settle * 4)
        if not (found["new"] or found["in_progress"] or found["unsaved"]):
            raise error
        envelope = {k: error.details[k] for k in ("site", "contained", "url", "refused")}
        return envelope | {
            "page": {"title": untrusted("")},
            "downloads": found,
            "download_only": True,
        }

    async def op_downloads(self, connection: Connection, args: dict[str, Any]) -> dict[str, Any]:
        """Answer ``downloads``: the files in the site's directory, and those still arriving."""
        site = self.registry.site_of(args)
        seen = await self.seen_downloads(connection, site)
        paths = sessions.session_paths(self.roots, site)
        found = await asyncio.to_thread(
            downloads.collect,
            paths.downloads_dir,
            seen,
            incoming=paths.incoming_dir,
            finish=self._wait,
        )
        connection.seen_downloads[site] = found.seen
        fresh = {item.name for item in found.new}
        files = [_download_entry(item) | {"new": item.name in fresh} for item in found.everything]
        return {
            "site": site,
            "files": files,
            "in_progress": [_download_entry(item) for item in found.in_progress],
        }
