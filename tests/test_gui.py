"""Local web interface: access control and report reading. No scan is started here."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from winsentinel import gui
from winsentinel.config import Config


@pytest.fixture
def server(tmp_path):
    rep = tmp_path / "reports" / "20260101-000000"
    rep.mkdir(parents=True)
    (rep / "findings.json").write_text(json.dumps({
        "meta": {"started": "2026-01-01T00:00:00", "mode": "quick", "admin": False},
        "modules": [{"name": "files", "status": "ok", "notes": [], "coverage": {}, "duration_s": 1.0, "findings": 1}],
        "findings": [{"module": "files", "severity": "high", "title": "<img src=x onerror=alert(1)>", "evidence": "/tmp/x"}],
    }), "utf-8")
    (tmp_path / "secret.txt").write_text("outside the reports folder", "utf-8")
    app = gui.App(Config(data_dir=tmp_path, code_dirs=[]), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = gui._handler(app, port)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}", app
    httpd.shutdown()
    httpd.server_close()


def _get(url, headers=None, data=None):
    req = urllib.request.Request(url, headers=headers or {}, data=data)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8"), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8"), e.headers


def test_page_and_api_need_the_token(server):
    base, app = server
    assert _get(base + "/")[0] == 403
    assert _get(base + "/?t=wrong")[0] == 403
    assert _get(base + "/api/state")[0] == 403
    assert _get(base + "/api/state", {"X-WS-Token": "wrong"})[0] == 403
    code, page, headers = _get(f"{base}/?t={app.token}")
    assert code == 200 and "winsentinel" in page and "__TOKEN__" not in page and "__NONCE__" not in page
    csp = headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "unsafe-inline" not in csp
    assert "style=" not in page          # inline style attributes would be blocked by that policy


def test_foreign_host_header_is_refused(server):
    base, app = server
    assert _get(base + "/api/state", {"X-WS-Token": app.token, "Host": "attacker.example"})[0] == 403


def test_state_and_report_are_served_as_data(server):
    base, app = server
    tok = {"X-WS-Token": app.token}
    code, body, _ = _get(base + "/api/state", tok)
    st = json.loads(body)
    assert code == 200 and st["reports"][0]["counts"]["high"] == 1 and st["job"] is None
    code, body, headers = _get(base + "/api/report?id=20260101-000000", tok)
    assert code == 200 and headers["Content-Type"].startswith("application/json")
    assert json.loads(body)["findings"][0]["title"].startswith("<img")   # passed through as JSON; the page renders text only


@pytest.mark.parametrize("rid", ["../secret.txt", "..", "..%2F", "20260101-000000/../..", "", "a/b"])
def test_report_ids_cannot_leave_the_reports_folder(server, rid):
    base, app = server
    code, body, _ = _get(f"{base}/api/report?id={rid}", {"X-WS-Token": app.token})
    assert code == 404 and "outside the reports folder" not in body


def test_post_is_validated_before_anything_starts(server):
    base, app = server
    tok = {"X-WS-Token": app.token}
    js = {**tok, "Content-Type": "application/json"}
    assert _get(base + "/api/scan", tok, b"{}")[0] == 403                                   # not JSON: refused
    assert _get(base + "/api/scan", {"Content-Type": "application/json"}, b"{}")[0] == 403  # no token
    assert _get(base + "/api/scan", js, b'{"modules": ["files; rm -rf /"]}')[0] == 400
    assert _get(base + "/api/analyze", js, b'{"path": "/no/such/file"}')[0] == 400
    assert app.job is None
