# SPDX-License-Identifier: Apache-2.0
"""A browser that sits idle asks the proxy for nothing it did not need: no Google update host."""

import tempfile
import time
from pathlib import Path

import pytest
from environment import unusable_reason
from proxy_stub import PageServer, ProxyStub

from valetkey import sandbox, sessions, sites

_SKIP_REASON = unusable_reason("bwrap", "chromium", "agent-browser")
needs_everything = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")

WAIT_SECONDS = 30
"""Long enough for the component updater, which asks within a second of the browser's start."""


@pytest.mark.integration
@needs_everything
def test_an_idle_session_makes_no_request_to_a_google_update_host() -> None:
    with tempfile.TemporaryDirectory(prefix="vk-") as directory:
        base = Path(directory)
        runtime = base / "rt"
        runtime.mkdir(mode=0o700)
        roots = sites.Roots(base / "cfg", base / "state", runtime)
        paths = sessions.session_paths(roots, "demo")
        paths.proxy_socket.parent.mkdir(parents=True)
        with (
            PageServer({"/": "<title>Idle</title><h1>Nothing to do</h1>"}) as pages,
            ProxyStub(paths.proxy_socket, pages.address) as proxy,
            sessions.Session.start(roots, "demo", "http://site.test/", timeout=60),
        ):
            time.sleep(WAIT_SECONDS)
            asked = [head.splitlines()[0] for head in proxy.requests]
    background = [line for line in asked if any(host in line for host in sandbox.BACKGROUND_HOSTS)]
    assert background == []
    assert any("site.test" in line for line in asked)  # the proxy was in use, only not for those
