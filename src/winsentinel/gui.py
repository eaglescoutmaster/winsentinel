"""Local web interface: browse reports, start scans, analyse a file. Read-only like the CLI.

Served on 127.0.0.1 only, on a random port, behind a per-run token. Nothing is exposed to the
network and there are still no remediation code paths: the page can start the same `scan` and
`analyze` commands the CLI has, and read the reports they write.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import threading
import webbrowser
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__
from .config import Config
from .osinfo import OS, is_admin

_PAGE = Path(__file__).with_name("gui_page.html")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,80}$")
_SEVS = ("critical", "high", "medium", "low", "info")
_CLI = "import sys; from winsentinel.cli import main; sys.exit(main())"


class Job:
    """One CLI run (scan or analyze) as a child process, with its output kept for the page."""

    def __init__(self, kind: str, args: list[str], cwd: Path):
        self.kind, self.args = kind, args
        self.lines: deque[str] = deque(maxlen=400)
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
        self.proc = subprocess.Popen([sys.executable, "-c", _CLI, *args], cwd=str(cwd), env=env, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                     errors="replace")
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        for line in self.proc.stdout:
            self.lines.append(line.rstrip("\n"))
        self.proc.wait()

    def to_dict(self) -> dict:
        rc = self.proc.poll()
        return {"kind": self.kind, "command": "winsentinel " + " ".join(self.args), "running": rc is None, "rc": rc,
                "log": list(self.lines)}


class App:
    def __init__(self, cfg: Config, config_path: Path | None):
        self.cfg, self.config_path = cfg, config_path
        self.token = secrets.token_urlsafe(24)
        self.job: Job | None = None
        self.lock = threading.Lock()

    # ---- reading what the CLI wrote ----------------------------------------
    def _dirs(self, analyses: bool) -> list[Path]:
        try:
            ds = [d for d in self.cfg.reports_dir.iterdir() if d.is_dir() and d.name.startswith("analyze-") == analyses]
        except OSError:
            return []
        return sorted(ds, key=lambda d: d.name, reverse=True)[:40]

    def _load(self, rid: str, name: str):
        if not _ID.match(rid or ""):
            return None
        try:
            return (self.cfg.reports_dir / rid / name).read_text("utf-8", "replace")
        except OSError:
            return None

    def state(self) -> dict:
        reports, analyses = [], []
        for d in self._dirs(False):
            try:
                doc = json.loads((d / "findings.json").read_text("utf-8"))
            except (OSError, ValueError):
                continue
            counts = dict.fromkeys(_SEVS, 0)
            for f in doc.get("findings", []):
                if f.get("severity") in counts:
                    counts[f["severity"]] += 1
            meta = doc.get("meta", {})
            reports.append({"id": d.name, "started": meta.get("started", ""), "mode": meta.get("mode", ""),
                            "admin": meta.get("admin", False), "counts": counts})
        for d in self._dirs(True):
            try:
                f = json.loads((d / "dossier.json").read_text("utf-8")).get("file", {})
            except (OSError, ValueError):
                continue
            verdict = None
            try:
                v = json.loads((d / "verdict.json").read_text("utf-8"))
                verdict = {"verdict": v.get("verdict"), "confidence": v.get("confidence")} if isinstance(v, dict) and v.get("verdict") else None
            except (OSError, ValueError):
                pass
            analyses.append({"id": d.name, "name": f.get("name", ""), "path": f.get("path", ""), "kind": f.get("kind", ""),
                             "sha256": f.get("sha256", ""), "verdict": verdict})
        from .modules import REGISTRY

        return {"version": __version__, "os": OS, "admin": is_admin(), "reports": reports, "analyses": analyses,
                "modules": [{"name": n, "description": m.DESCRIPTION} for n, m in REGISTRY.items()],
                "reports_dir": str(self.cfg.reports_dir), "job": self.job.to_dict() if self.job else None}

    def setup(self) -> dict:
        out = {}
        for key, args in (("tools", ["tools", "status"]), ("keys", ["keys", "status"])):
            try:
                r = subprocess.run([sys.executable, "-c", _CLI, *args, *self._cfg_args(args[0])], capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=90, stdin=subprocess.DEVNULL,
                                   env=dict(os.environ, PYTHONIOENCODING="utf-8"))
                out[key] = (r.stdout + r.stderr).strip()
            except (OSError, subprocess.SubprocessError) as e:
                out[key] = f"could not run: {e}"
        return out

    def _cfg_args(self, cmd: str) -> list[str]:
        return ["--config", str(self.config_path)] if self.config_path and cmd in ("scan", "tools", "analyze") else []

    # ---- starting the CLI ---------------------------------------------------
    def start(self, kind: str, body: dict) -> tuple[int, dict]:
        from .modules import REGISTRY

        if kind == "scan":
            args = ["scan", "--full" if body.get("mode") == "full" else "--quick"]
            mods = body.get("modules") or []
            if not isinstance(mods, list) or any(m not in REGISTRY for m in mods):
                return 400, {"error": "unknown module"}
            if len(mods) != len(REGISTRY):
                for m in mods:
                    args += ["--module", m]
        else:
            path = str(body.get("path", "")).strip().strip('"')
            if not path or not os.path.isfile(path):
                return 400, {"error": "That path is not a file on this machine."}
            args = ["analyze", path]
            if body.get("llm"):
                args.append("--llm")
        args += self._cfg_args(args[0])
        with self.lock:
            if self.job and self.job.proc.poll() is None:
                return 409, {"error": f"A {self.job.kind} is already running."}
            try:
                self.job = Job(kind, args, Path.cwd())
            except OSError as e:
                return 500, {"error": str(e)}
        return 200, self.job.to_dict()

    def stop(self) -> dict:
        if self.job and self.job.proc.poll() is None:
            self.job.proc.terminate()
        return self.job.to_dict() if self.job else {}


def _handler(app: App, port: int):
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class H(BaseHTTPRequestHandler):
        server_version = "winsentinel"

        def log_message(self, *a):  # keep the terminal quiet
            pass

        def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj) -> None:
            self._send(code, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

        def _allowed(self, api: bool) -> bool:
            # Host check defeats DNS rebinding; the token stops other local pages and programs driving the scanner.
            if self.headers.get("Host", "") not in hosts:
                return False
            return not api or secrets.compare_digest(self.headers.get("X-WS-Token", ""), app.token)

        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if u.path == "/":
                if not self._allowed(False) or not secrets.compare_digest(q.get("t", [""])[0], app.token):
                    return self._send(403, b"Open the link printed by 'winsentinel gui'.", "text/plain; charset=utf-8")
                nonce = secrets.token_urlsafe(16)
                page = _PAGE.read_text("utf-8").replace("__NONCE__", nonce).replace("__TOKEN__", app.token)
                csp = (f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; "
                       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
                return self._send(200, page.encode("utf-8"), "text/html; charset=utf-8", {"Content-Security-Policy": csp})
            if not u.path.startswith("/api/") or not self._allowed(True):
                return self._json(403, {"error": "forbidden"})
            rid = q.get("id", [""])[0]
            if u.path == "/api/state":
                return self._json(200, app.state())
            if u.path == "/api/job":
                return self._json(200, app.job.to_dict() if app.job else None)
            if u.path == "/api/setup":
                return self._json(200, app.setup())
            if u.path == "/api/report":
                text = app._load(rid, "findings.json")
                return self._send(200, text.encode("utf-8"), "application/json; charset=utf-8") if text else self._json(404, {"error": "no such report"})
            if u.path == "/api/analysis":
                md = app._load(rid, "analysis.md")
                if md is None:
                    return self._json(404, {"error": "no such analysis"})
                try:
                    verdict = json.loads(app._load(rid, "verdict.json") or "null")
                except ValueError:
                    verdict = None
                return self._json(200, {"id": rid, "markdown": md, "verdict": verdict})
            return self._json(404, {"error": "not found"})

        def do_POST(self):
            u = urlparse(self.path)
            if not self._allowed(True) or "application/json" not in self.headers.get("Content-Type", ""):
                return self._json(403, {"error": "forbidden"})
            try:
                n = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(min(n, 65536)) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self._json(400, {"error": "bad request"})
            if u.path == "/api/scan":
                return self._json(*app.start("scan", body))
            if u.path == "/api/analyze":
                return self._json(*app.start("analyze", body))
            if u.path == "/api/stop":
                return self._json(200, app.stop())
            return self._json(404, {"error": "not found"})

    return H


def serve(cfg: Config, config_path: Path | None = None, port: int = 0, open_browser: bool = True) -> int:
    app = App(cfg, config_path)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), BaseHTTPRequestHandler)
    httpd.daemon_threads = True
    httpd.RequestHandlerClass = _handler(app, httpd.server_address[1])
    url = f"http://127.0.0.1:{httpd.server_address[1]}/?t={app.token}"
    print(f"winsentinel gui: {url}", flush=True)
    print("local only (127.0.0.1); this link is the key. Ctrl+C to stop.", flush=True)
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.stop()
        httpd.server_close()
    return 0
