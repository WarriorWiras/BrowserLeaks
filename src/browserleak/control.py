"""Positive control: delete the known visits with SQLite secure_delete OFF.

Chrome compiles SQLite with SQLITE_SECURE_DELETE, so its own history deletion
overwrites deleted records with zeros. The control repeats the same deletion on a
copy of the PRE-deletion evidence with secure_delete OFF, which is the only
difference. If BrowserLeak recovers the visits from the control but not from the
real deletion, the recovery method works and Chrome's secure delete is what
prevents recovery.


The source evidence is never modified.
"""
from __future__ import annotations

import csv
import json
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .forensics import CHROME_EPOCH, sha256


def _chrome_time(moment: datetime) -> int:
    return int((moment - CHROME_EPOCH) / timedelta(microseconds=1))


def make_control(evidence: Path, ground_truth: Path, output: Path,
                 post_count: int = 0, port: int = 8765) -> dict:
    evidence, output = Path(evidence), Path(output)
    source = evidence / "History"
    if not source.is_file():
        raise FileNotFoundError(f"No History file in {evidence}")
    if post_count < 0:
        raise ValueError("post_count must not be negative")
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"Output folder must be empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    for name in ("History", "History-wal"):
        if (evidence / name).is_file():
            shutil.copy2(evidence / name, output / name)

    with Path(ground_truth).open(newline="", encoding="utf-8") as stream:
        urls = sorted({r["url"] for r in csv.DictReader(stream) if r.get("phase") == "baseline"})
    if not urls:
        raise ValueError("No baseline rows in ground truth")

    target = output / "History"
    con = sqlite3.connect(str(target))
    con.row_factory = sqlite3.Row
    try:
        # Fold any WAL into the copy and use a rollback journal, as Chrome on Windows does.
        con.execute("PRAGMA journal_mode=DELETE")
        con.execute("PRAGMA secure_delete=OFF")  # the ONLY difference from Chrome's deletion
        marks = ",".join("?" * len(urls))
        ids = [r[0] for r in con.execute(f"SELECT id FROM urls WHERE url IN ({marks})", urls)]
        if not ids:
            raise ValueError("None of the baseline URLs are in this History. "
                             "Use the PRE-deletion capture.")
        id_marks = ",".join("?" * len(ids))
        url_template = dict(con.execute("SELECT * FROM urls WHERE id=?", (ids[0],)).fetchone())
        visit_template = dict(con.execute("SELECT * FROM visits WHERE url=? LIMIT 1", (ids[0],)).fetchone())
        start = max(r[0] for r in con.execute(
            f"SELECT visit_time FROM visits WHERE url IN ({id_marks})", ids))
        # Delete one visit and one URL at a time, as Chrome's history backend does.
        visit_ids = [r[0] for r in con.execute(
            f"SELECT id FROM visits WHERE url IN ({id_marks}) ORDER BY id", ids)]
        for visit_id in visit_ids:
            con.execute("DELETE FROM visits WHERE id=?", (visit_id,))
        for url_id in ids:
            con.execute("DELETE FROM urls WHERE id=?", (url_id,))
        con.commit()

        base = CHROME_EPOCH + timedelta(microseconds=start)
        for number in range(1, post_count + 1):
            when = _chrome_time(base + timedelta(seconds=number))
            url_row = dict(url_template, id=None,
                           url=f"http://127.0.0.1:{port}/visit/post/{number:04d}",
                           title=f"BrowserLeak post {number}", last_visit_time=when, visit_count=1)
            columns = [c for c in url_row if c != "id"]
            cursor = con.execute(
                f"INSERT INTO urls ({','.join(columns)}) VALUES ({','.join('?' * len(columns))})",
                [url_row[c] for c in columns])
            visit_row = dict(visit_template, id=None, url=cursor.lastrowid, visit_time=when)
            columns = [c for c in visit_row if c != "id"]
            con.execute(
                f"INSERT INTO visits ({','.join(columns)}) VALUES ({','.join('?' * len(columns))})",
                [visit_row[c] for c in columns])
            con.commit()
    finally:
        con.close()

    manifest = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "type": "POSITIVE CONTROL - not a real Chrome deletion",
        "source_history_sha256": sha256(source),
        "control_history_sha256": sha256(target),
        "method": ("Copied pre-deletion History; deleted the baseline urls/visits rows one at a time "
                   "with PRAGMA secure_delete=OFF"),
        "baseline_urls_in_truth": len(urls),
        "deleted_visit_rows": len(visit_ids),
        "deleted_url_rows": len(ids),
        "simulated_post_deletion_visits": post_count,
    }
    (output / "control_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest
