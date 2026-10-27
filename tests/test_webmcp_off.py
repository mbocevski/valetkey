# SPDX-License-Identifier: Apache-2.0
"""A page in a session sees no WebMCP API: the browser is started with page tools turned off."""

import tempfile
from pathlib import Path

import pytest
from environment import unusable_reason
from proxy_stub import PageServer, ProxyStub

from valetkey import sessions, sites

_SKIP_REASON = unusable_reason("bwrap", "chromium", "agent-browser")
needs_everything = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")

PAGE = "<title>A page that would register tools</title><h1>Tools</h1>"


@pytest.mark.integration
@needs_everything
def test_a_page_on_localhost_sees_no_model_context() -> None:
    """``http://localhost`` is a secure context, where Chromium offers the API when it is on."""
    with tempfile.TemporaryDirectory(prefix="vk-") as directory:
        base = Path(directory)
        runtime = base / "rt"
        runtime.mkdir(mode=0o700)
        roots = sites.Roots(base / "cfg", base / "state", runtime)
        paths = sessions.session_paths(roots, "demo")
        paths.proxy_socket.parent.mkdir(parents=True)
        with (
            PageServer({"/": PAGE}) as pages,
            ProxyStub(paths.proxy_socket, pages.address),
            sessions.Session.start(roots, "demo", "http://localhost/", timeout=60) as session,
        ):
            assert session.open("http://localhost/").title == "A page that would register tools"
            secure = session._call("eval", "window.isSecureContext")["result"]  # noqa: SLF001
            document = session._call("eval", "typeof document.modelContext")["result"]  # noqa: SLF001
            window = session._call("eval", "'ModelContext' in window")["result"]  # noqa: SLF001
            navigator = session._call("eval", "typeof navigator.modelContext")["result"]  # noqa: SLF001
    assert secure is True
    assert document == "undefined"
    assert navigator == "undefined"
    assert window is False
