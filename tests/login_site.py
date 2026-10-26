# SPDX-License-Identifier: Apache-2.0
"""A small site with a login, for tests: it sets a session cookie and redirects without one."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Self
from urllib.parse import urlsplit

LOGIN_FORM = (
    "<!doctype html><title>Sign in</title><h1>Sign in</h1>"
    '<form id="f" method="post" action="/login">'
    '<input name="user" value="ada"><input type="password" name="pw" value="secret">'
    '<button type="submit">Sign in</button></form>'
    "{script}"
)
# The page stays open for a moment first: a page that submits itself at once is not a page a person
# used, and learn does not take it for a sign-in page.
AUTO_SUBMIT = '<script>setTimeout(() => document.getElementById("f").submit(), 400)</script>'
PAGES = {
    "/": "<title>Home</title><h1>Home, signed in</h1>",
    "/app": "<title>Dashboard</title><h1>Dashboard</h1>",
    "/welcome": "<title>Welcome</title><h1>Welcome page</h1>",
    "/public": (
        "<title>Public</title><h1>A public page</h1>"
        '<form><input type="password" aria-label="Quick login"><button>Go</button></form>'
    ),
}
PRIVATE = {"/", "/app"}
COOKIE = "session=ok"


class LoginSite:
    """A local web site: ``/`` and ``/app`` need a ``session`` cookie, which ``POST /login`` sets.

    Without the cookie, ``/`` and ``/app`` redirect to ``/login?next=...``. While ``auto_login``
    is true the login page submits itself, so a test can log in without typing. ``/public`` is
    open and has a login box. ``/promo`` redirects to ``/welcome``, a normal page. ``hits`` lists
    every request line.
    """

    def __init__(self) -> None:
        self.auto_login = True
        self.hits: list[str] = []
        site = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                site.hits.append(f"GET {self.path}")
                status, headers, body = site.answer(self.path, self.headers.get("Cookie") or "")
                data = body.encode()
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self) -> None:
                site.hits.append(f"POST {self.path}")
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                self.send_response(302)
                self.send_header("Location", "/app")
                self.send_header("Set-Cookie", f"{COOKIE}; Path=/; Max-Age=3600; HttpOnly")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002  # signature of the base class
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def answer(self, target: str, cookie: str) -> tuple[int, dict[str, str], str]:
        """Return the status, headers and body for a GET of ``target`` with this ``cookie``."""
        path = urlsplit(target).path
        html = {"Content-Type": "text/html"}
        if path == "/login":
            return 200, html, LOGIN_FORM.format(script=AUTO_SUBMIT if self.auto_login else "")
        if path == "/promo":
            return 302, {"Location": "/welcome"}, ""
        if path in PRIVATE and COOKIE not in cookie:
            return 302, {"Location": f"/login?next={path}"}, ""
        if path in PAGES:
            return 200, html, PAGES[path]
        return 404, {"Content-Type": "text/plain"}, "not found"

    @property
    def address(self) -> tuple[str, int]:
        """Host and port the site listens on."""
        host, port = self._server.server_address[:2]
        return str(host), port

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(10)
