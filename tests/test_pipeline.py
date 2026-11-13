"""Tests for the integrated pipeline, positive control, experiment server and summaries."""
from __future__ import annotations

import csv
import json
import sqlite3
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from browserleak.control import make_control
from browserleak.experiment import ExperimentServer
from browserleak.forensics import CHROME_EPOCH
from browserleak.pipeline import recover
from browserleak.summary import overwrite_curve, summarise_runs

URLS = ("CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT,url LONGVARCHAR,title LONGVARCHAR,"
        "visit_count INTEGER DEFAULT 0 NOT NULL,typed_count INTEGER DEFAULT 0 NOT NULL,"
        "last_visit_time INTEGER NOT NULL,hidden INTEGER DEFAULT 0 NOT NULL)")
VISITS = ("CREATE TABLE visits(id INTEGER PRIMARY KEY AUTOINCREMENT,url INTEGER NOT NULL,"
          "visit_time INTEGER NOT NULL,from_visit INTEGER,external_referrer_url TEXT,"
          "transition INTEGER DEFAULT 0 NOT NULL,segment_id INTEGER,visit_duration INTEGER DEFAULT 0 NOT NULL)")


def chrome_profile(folder: Path, count: int = 20) -> Path:
    """A PRE-deletion History with Chrome's urls/visits layout plus the ground truth log."""
    folder.mkdir(parents=True)
    con = sqlite3.connect(folder / "History")
    con.execute(URLS)
    con.execute(VISITS)
    rows, start = [], datetime(2026, 11, 11, 13, 0, tzinfo=timezone.utc)
    for i in range(1, count + 1):
        moment = start + timedelta(seconds=i)
        when = int((moment - CHROME_EPOCH) / timedelta(microseconds=1))
        url = f"http://127.0.0.1:8765/visit/baseline/{i:04d}"
        cur = con.execute("INSERT INTO urls(url,title,visit_count,typed_count,last_visit_time,hidden) "
                          "VALUES (?,?,1,0,?,0)", (url, f"BrowserLeak baseline {i}/{count}", when))
        con.execute("INSERT INTO visits(url,visit_time,from_visit,external_referrer_url,transition,"
                    "segment_id,visit_duration) VALUES (?,?,0,'',805306368,0,1500000)", (cur.lastrowid, when))
        rows.append({"phase": "baseline", "url": url, "visited_at_utc": moment.isoformat(), "page_number": i})
    con.commit()
    con.close()
    truth = folder.parent / "ground_truth.csv"
    with truth.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return truth


def test_control_recovers_all_and_flags_records(tmp_path):
    truth = chrome_profile(tmp_path / "evidence_predelete")
    manifest = make_control(tmp_path / "evidence_predelete", truth, tmp_path / "control")
    assert manifest["deleted_visit_rows"] == 20
    result = recover(tmp_path / "control", truth, tmp_path / "out", "A", "immediate", "control")
    assert result["correctly_recovered"] == 20
    assert result["incorrectly_recovered"] == 0
    assert result["deleted_urls_still_in_current_history"] == 0
    with (tmp_path / "out" / "recovered_records.csv").open(encoding="utf-8") as stream:
        records = list(csv.DictReader(stream))
    full = [r for r in records if r["record_type"] == "full_visit"]
    assert len(full) == 20 and all(r["ground_truth_match"] == "Yes" for r in full)
    assert all(r["scenario"] == "A" and r["database_table"] == "visits" and r["recovery_source"] for r in full)


def test_pre_deletion_evidence_is_not_counted_as_recovery(tmp_path):
    truth = chrome_profile(tmp_path / "evidence_predelete")
    result = recover(tmp_path / "evidence_predelete", truth, tmp_path / "out")
    assert result["correctly_recovered"] == 0
    assert result["deleted_urls_still_in_current_history"] == 20


def test_secure_delete_leaves_nothing(tmp_path):
    truth = chrome_profile(tmp_path / "evidence")
    con = sqlite3.connect(tmp_path / "evidence" / "History")
    con.execute("PRAGMA secure_delete=ON")
    for i in range(1, 21):
        con.execute("DELETE FROM visits WHERE id=?", (i,))
        con.execute("DELETE FROM urls WHERE id=?", (i,))
    con.commit()
    con.close()
    result = recover(tmp_path / "evidence", truth, tmp_path / "out")
    assert result["correctly_recovered"] == 0
    assert result["deleted_urls_present_in_raw_bytes"] == 0


def test_post_deletion_visits_overwrite_and_curve(tmp_path):
    run = tmp_path / "A"
    truth = chrome_profile(run / "evidence_predelete")
    csv_file, svg_file = overwrite_curve(run, [0, 10, 50])
    with csv_file.open(encoding="utf-8") as stream:
        rates = {int(r["post_deletion_visits"]): int(r["correctly_recovered"]) for r in csv.DictReader(stream)}
    assert rates[0] == 20 and rates[0] > rates[10] > rates[50] == 0
    assert svg_file.read_text(encoding="utf-8").startswith("<svg")
    assert truth.exists()


def test_summary_across_runs(tmp_path):
    run = tmp_path / "A"
    truth = chrome_profile(run / "evidence_predelete")
    make_control(run / "evidence_predelete", truth, run / "evidence_control")
    recover(run / "evidence_control", truth, run / "results_control", "A", "immediate", "control")
    (run / "scenario.json").write_text(json.dumps({"name": "A", "scenario": "A", "condition": "immediate",
                                                   "post_visits": 0}), encoding="utf-8")
    csv_file, md_file, svg_file = summarise_runs(tmp_path, tmp_path / "summary")
    assert "100.0%" in md_file.read_text(encoding="utf-8")


def test_server_logs_ground_truth_and_locks_post_pages(tmp_path):
    log = tmp_path / "truth.csv"
    server = ExperimentServer(8797, log, pages=2, searches=1, post_count=1)
    server.start()
    try:
        base = "http://127.0.0.1:8797"
        for path in ("/visit/baseline/0001", "/visit/baseline/0002", "/search?q=browser+forensics"):
            assert urllib.request.urlopen(base + path).status == 200
        assert server.done("baseline")
        with pytest.raises(urllib.error.HTTPError):
            urllib.request.urlopen(base + "/visit/post/0001")
        server.enable_post()
        assert urllib.request.urlopen(base + "/visit/post/0001").status == 200
    finally:
        server.stop()
    with log.open(encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    assert [r["phase"] for r in rows] == ["baseline"] * 3 + ["post"]
    assert rows[2]["url"] == "http://127.0.0.1:8797/search?q=browser+forensics"
