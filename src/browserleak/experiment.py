"""Controlled test website (ground-truth log) and safe acquisition from a closed Chrome profile."""
from __future__ import annotations

import csv
import json
import shutil
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .forensics import sha256

FIELDNAMES = ["phase", "url", "visited_at_utc", "page_number"]


SEARCH_TERMS = [
    "browser forensics", "sqlite deleted records", "chrome history recovery",
    "digital evidence", "write ahead log", "freelist pages", "secure delete",
    "forensic timeline", "evidence integrity", "ground truth validation",
]


class ExperimentServer:
    """Local test website that writes the independent ground-truth log.

    Every page request is logged with the server's own clock, separately from
    Chrome. Pages can advance automatically (auto=True) so that hundreds of
    visits need no clicking. Post-deletion pages are refused until
    `enable_post()` is called, so they cannot be visited before the deletion.
    """

    def __init__(self, port: int, log_path: Path, pages: int, searches: int = 0,
                 post_count: int = 0, auto: bool = True, delay_ms: int = 300,
                 post_enabled: bool = False):
        if pages < 1 or pages > 10000:
            raise ValueError("pages must be between 1 and 10000")
        if not 0 <= searches <= len(SEARCH_TERMS):
            raise ValueError(f"searches must be between 0 and {len(SEARCH_TERMS)}")
        if not 0 <= post_count <= 10000:
            raise ValueError("post_count must be between 0 and 10000")
        self.port, self.log_path, self.auto, self.delay_ms = port, Path(log_path), auto, delay_ms
        base = f"http://127.0.0.1:{port}"
        baseline = [f"/visit/baseline/{i:04d}" for i in range(1, pages + 1)]
        baseline += ["/search?q=" + term.replace(" ", "+") for term in SEARCH_TERMS[:searches]]
        self.sequence = {"baseline": baseline,
                         "post": [f"/visit/post/{i:04d}" for i in range(1, post_count + 1)]}
        self.base = base
        self.post_enabled = post_enabled
        self.served = {"baseline": set(), "post": set()}
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._httpd = None

    def start_url(self, phase: str) -> str:
        return self.base + self.sequence[phase][0]

    def total(self, phase: str) -> int:
        return len(self.sequence[phase])

    def done(self, phase: str) -> bool:
        return len(self.served[phase]) >= self.total(phase)

    def enable_post(self) -> None:
        self.post_enabled = True

    def _log(self, phase: str, path: str, number: int) -> None:
        with self._lock:
            new = not self.log_path.exists() or self.log_path.stat().st_size == 0
            with self.log_path.open("a", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=FIELDNAMES)
                if new:
                    writer.writeheader()
                writer.writerow({"phase": phase, "url": self.base + path,
                                 "visited_at_utc": datetime.now(timezone.utc).isoformat(),
                                 "page_number": number})
            self.served[phase].add(path)

    def _page(self, path: str) -> tuple[int, str]:
        for phase, items in self.sequence.items():
            if path in items:
                if phase == "post" and not self.post_enabled:
                    return 403, "<h1>Post-deletion pages are locked</h1><p>Delete the history first.</p>"
                index = items.index(path)
                self._log(phase, path, index + 1)
                label = "Search: " + path.split("q=", 1)[1].replace("+", " ") if "q=" in path else f"Page {index + 1}"
                title = f"BrowserLeak {phase} {index + 1}/{len(items)}"
                if index + 1 < len(items):
                    following = items[index + 1]
                    nav = (f'<script>setTimeout(function(){{location.assign("{following}")}},{self.delay_ms})</script>'
                           f"<p>Moving to the next page automatically...</p>" if self.auto else
                           f'<a href="{following}">Next page</a>')
                else:
                    nav = (f"<h2 style='color:#0a7d32'>All {len(items)} {phase} visits complete.</h2>"
                           "<p>Return to the BrowserLeak window for the next step.</p>")
                return 200, (f"<title>{title}</title><h1>BrowserLeak experiment: {phase}</h1>"
                             f"<p>{label} ({index + 1} of {len(items)})</p>{nav}")
        if path == "/":
            links = "".join(f'<li><a href="{items[0]}">Start {phase} ({len(items)} visits)</a></li>'
                            for phase, items in self.sequence.items() if items)
            return 200, f"<title>BrowserLeak</title><h1>BrowserLeak experiment</h1><ol>{links}</ol>"
        return 404, ""

    def start(self, background: bool = True):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # keep the console readable
                pass

            def do_GET(self):
                parts = urlsplit(self.path)
                path = parts.path + ("?" + parts.query if parts.query else "")
                status, body = server._page(path)
                if status == 404:
                    self.send_error(404, "Unknown test page")
                    return
                payload = ("<!doctype html><html><head><meta charset='utf-8'></head><body "
                           "style='font-family:Arial;margin:40px'>" + body + "</body></html>").encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        if background:
            threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        return self._httpd

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()


def find_profile_history(profile: Path) -> Path:
    candidates = [profile / "History", profile / "Default" / "History"]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"No History file under {profile} or its Default directory")


def capture_closed_profile(profile: Path, output: Path, confirm_closed: bool) -> dict:
    if not confirm_closed:
        raise ValueError("Close Chrome fully, then specify --confirm-closed. "
                         "For live evidence use a consistent VM/filesystem snapshot instead.")
    history = find_profile_history(profile)
    destination = output.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise FileExistsError(f"Evidence directory is not empty: {destination}")
    if destination == history.parent.resolve():
        raise ValueError("Evidence output must not be the source profile directory")
    destination.mkdir(parents=True, exist_ok=True)
    manifest = {"acquired_at_utc": datetime.now(timezone.utc).isoformat(),
                "source_profile": str(history.parent),
                "method": "copy after Chrome closed; NOT an acquisition of live WAL state",
                "files": {}}
    for name in ("History", "History-wal", "History-shm", "History-journal"):
        source = history.parent / name
        if source.is_file():
            target = destination / name
            shutil.copy2(source, target)
            manifest["files"][name] = {"size": target.stat().st_size, "sha256": sha256(target)}
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest
