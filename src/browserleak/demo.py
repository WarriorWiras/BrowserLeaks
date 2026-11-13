"""Self-contained proof of the recovery pipeline on a SYNTHETIC WAL SQLite database.

This is not Chrome evidence and MUST NOT be cited as Chrome recovery performance.
"""
from __future__ import annotations

import csv
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .forensics import analyse, save_json
from .validation import markdown_report, validate_analysis


def create_demo(output: Path) -> dict:
    output = output.resolve()
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"Demo output must be empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    evidence = output / "evidence"
    evidence.mkdir()
    ground_truth = output / "ground_truth.csv"
    with tempfile.TemporaryDirectory(prefix="browserleak_demo_") as temporary:
        source = Path(temporary) / "History"
        con = sqlite3.connect(str(source))
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA wal_autocheckpoint=0")
            con.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER)")
            con.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)")
            con.commit()
            events = []
            base = datetime(2026, 10, 19, 2, 0, tzinfo=timezone.utc)
            for i in range(1, 11):
                url = f"http://127.0.0.1:8765/visit/baseline/{i:04d}"
                dt = base + timedelta(seconds=i)
                chrome_timestamp = 11644473600000000 + int(dt.timestamp() * 1_000_000)
                con.execute("INSERT INTO urls VALUES (?,?,?,?)", (i, url, f"Page {i}", 1))
                con.execute("INSERT INTO visits VALUES (?,?,?)", (i, i, chrome_timestamp))
                events.append({"phase": "baseline", "url": url,
                               "visited_at_utc": dt.isoformat(), "page_number": i})
            con.commit()
            con.execute("DELETE FROM visits")
            con.execute("DELETE FROM urls")
            con.commit()
            # The database must be copied while the WAL still exists.
            for name in ("History", "History-wal", "History-shm"):
                path = Path(temporary) / name
                if path.exists():
                    shutil.copy2(path, evidence / name)
        finally:
            con.close()
    with ground_truth.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["phase", "url", "visited_at_utc", "page_number"])
        writer.writeheader()
        writer.writerows(events)
    analysis = analyse(evidence)
    validation = validate_analysis(analysis, ground_truth)
    save_json(output / "analysis.json", analysis)
    save_json(output / "validation.json", validation)
    (output / "report.md").write_text(markdown_report(analysis, validation), encoding="utf-8")
    return validation
