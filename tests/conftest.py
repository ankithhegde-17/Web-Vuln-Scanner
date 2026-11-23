"""A tiny, deliberately insecure website that runs on localhost during tests.

It lets us test the scanner end-to-end without touching any real site:
- several linked pages, one off-domain link, one robots-disallowed page
- a login form
- cookies with missing flags
- a Server header with a version, and X-Powered-By
- an exposed /.git/HEAD
- an SPA-style catch-all: unknown paths return the index page with 200
"""

from __future__ import annotations

import html
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

INDEX = b"""<html><head><title>Test shop</title></head><body>
<a href="/about">About</a>
<a href="/login#top">Login</a>
<a href="https://example.org/elsewhere">Off-domain link</a>
<a href="/private/secret">Private</a>
<a href="mailto:me@example.com">Mail</a>
</body></html>"""

ABOUT = b"""<html><body><a href="/">Home</a><a href="/about/team">Team</a></body></html>"""
TEAM = b"""<html><body>Team page</body></html>"""
LOGIN = b"""<html><body>
<form action="/session" method="post">
  <input type="email" name="email">
  <input type="password" name="password">
  <input type="hidden" name="csrf" value="abc123">
  <input type="submit" value="Log in">
</form>
<form><input name="q"></form>
</body></html>"""

ROBOTS = b"User-agent: *\nDisallow: /private/\n"


class Handler(BaseHTTPRequestHandler):
    # Record every request so tests can assert what the scanner did.
    requests_seen: list[tuple[str, str]] = []

    def log_message(self, *args):  # keep test output quiet
        pass

    def version_string(self):  # controls the Server header
        return "Apache/2.4.29 (Ubuntu)"

    def _send(self, status, body, content_type="text/html; charset=utf-8", extra_headers=()):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "Express")
        for k, v in extra_headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        Handler.requests_seen.append(("GET", self.path))
        path = self.path.split("?")[0]
        if path == "/robots.txt":
            return self._send(200, ROBOTS, "text/plain")
        if path == "/":
            return self._send(200, INDEX, extra_headers=[
                ("Set-Cookie", "sessionid=s3cr3t; Path=/"),
                ("Set-Cookie", "theme=dark; Path=/; HttpOnly; SameSite=Lax"),
            ])
        if path == "/about":
            return self._send(200, ABOUT, extra_headers=[("X-Frame-Options", "SAMEORIGIN")])
        if path == "/about/team":
            return self._send(200, TEAM)
        if path == "/login":
            return self._send(200, LOGIN)
        if path == "/old":
            self.send_response(302)
            self.send_header("Location", "https://example.org/")
            self.end_headers()
            return
        if path == "/.git/HEAD":
            return self._send(200, b"ref: refs/heads/main\n", "text/plain")

        # ---- Deliberately vulnerable endpoints, for the active-check tests ---
        query = parse_qs(urlsplit(self.path).query)

        if path == "/search":
            # Reflects 'q' into HTML WITHOUT encoding -> reflected XSS.
            q = query.get("q", [""])[0]
            return self._send(200, f"<html><body>Results for {q}</body></html>".encode())

        if path == "/safe-search":
            # Reflects 'q' but HTML-escaped -> must NOT be flagged.
            q = query.get("q", [""])[0]
            return self._send(200, f"<html><body>Results for {html.escape(q)}</body></html>".encode())

        if path == "/product":
            # Error-based SQLi: an unbalanced quote yields a SQLite error.
            pid = query.get("id", [""])[0]
            if "'" in pid or '"' in pid:
                return self._send(500, b"<html><body>SQLITE_ERROR: unrecognized token: near syntax</body></html>")
            return self._send(200, f"<html><body>Product {html.escape(pid)}</body></html>".encode())

        if path == "/go":
            # Open redirect: blindly redirects to whatever 'to' says.
            to = query.get("to", [""])[0]
            self.send_response(302)
            self.send_header("Location", to)
            self.end_headers()
            return

        # SPA-style catch-all: everything else returns the index page.
        return self._send(200, INDEX)

    def do_POST(self):
        Handler.requests_seen.append(("POST", self.path))
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode() if length else ""

        # A JSON login API that leaks only a driver stack trace (no clean
        # "SQLITE_ERROR" string) when a quote breaks the query -- mimics Juice
        # Shop's /rest/user/login, to test JSON-body injection + the ORM
        # stack-trace signature.
        if self.path == "/rest/user/login":
            try:
                email = json.loads(raw).get("email", "") if raw else ""
            except json.JSONDecodeError:
                email = ""
            if "'" in email or '"' in email:
                return self._send(500, b"<html><body>Error at "
                                        b"sequelize/lib/dialects/sqlite/query.js:185:27</body></html>")
            return self._send(401, b"Invalid email or password.", "text/plain")

        # Reflects the 'comment' field unencoded -> reflected XSS via POST form.
        comment = parse_qs(raw).get("comment", [""])[0]
        self._send(200, f"<html><body>You said: {comment}</body></html>".encode())


@pytest.fixture()
def test_site():
    Handler.requests_seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)  # port 0 = pick a free port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", Handler.requests_seen
    server.shutdown()
