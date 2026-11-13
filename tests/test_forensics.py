from __future__ import annotations

import csv
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from browserleak.forensics import analyse, chrome_to_utc, committed_wal_frames, decode_varint
from browserleak.validation import validate_analysis


def test_decode_varint():
    assert decode_varint(b"\x7f", 0) == (127, 1)
    assert decode_varint(b"\x81\x00", 0) == (128, 2)


def test_chrome_timestamp():
    assert chrome_to_utc(0) == ""
    assert chrome_to_utc(11644473600000000) == "1970-01-01T00:00:00+00:00"


def test_missing_wal():
    assert committed_wal_frames(b"", 4096) == ([], [])


def test_recovers_deleted_visits_from_committed_wal(tmp_path):
    db = tmp_path / "History"
    con = sqlite3.connect(db)
    assert con.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    con.execute("PRAGMA wal_autocheckpoint=0")
    con.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER)")
    con.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)")
    con.commit()

    start = datetime(2026, 10, 19, 2, 0, tzinfo=timezone.utc)
    chrome_offset = 11644473600000000
    events = []
    for i in range(1, 11):
        url = f"http://127.0.0.1:8765/visit/baseline/{i:04d}"
        at = start + timedelta(seconds=i)
        visit_time = chrome_offset + int(at.timestamp() * 1_000_000)
        con.execute("INSERT INTO urls VALUES (?,?,?,?)", (i, url, f"Page {i}", 1))
        con.execute("INSERT INTO visits VALUES (?,?,?)", (i, i, visit_time))
        events.append({"phase": "baseline", "url": url,
                       "visited_at_utc": at.isoformat(), "page_number": i})
    con.commit()
    con.execute("DELETE FROM visits")
    con.execute("DELETE FROM urls")
    con.commit()

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    for name in ("History", "History-wal", "History-shm"):
        source = tmp_path / name
        if source.exists():
            shutil.copyfile(source, evidence / name)

    result = analyse(evidence)
    full = [c for c in result["candidates"] if c["level"] == "visit"]
    assert len(full) == 10, full
    assert result["wal_committed_frames"] > 0
    assert all(c["source"] == "wal" for c in full)
    assert result["active_visit_count"] == 0
    assert result["active_url_count"] == 0

    ground_truth = tmp_path / "ground_truth.csv"
    with ground_truth.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["phase", "url", "visited_at_utc", "page_number"])
        w.writeheader()
        w.writerows(events)
    report = validate_analysis(result, ground_truth)
    assert report["correct_recoveries"] == 10, report
    assert report["recovery_rate_percent"] == 100.0
    assert report["false_recoveries"] == 0
    con.close()
