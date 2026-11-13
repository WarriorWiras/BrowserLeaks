"""Tests for evidence acquisition, timestamps, the pre-deletion check and the scenario plan."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from browserleak.experiment import capture_closed_profile
from browserleak.forensics import CHROME_EPOCH, analyse, chrome_to_utc
from browserleak.scenario import SCENARIOS
from browserleak.validation import verify_baseline

from test_pipeline import chrome_profile


def profile_with_history(tmp_path: Path) -> Path:
    profile = tmp_path / "profile"
    chrome_profile(profile / "Default")
    (profile / "Default" / "History-journal").write_bytes(b"")
    return profile


def test_capture_requires_confirmation_that_chrome_is_closed(tmp_path):
    with pytest.raises(ValueError):
        capture_closed_profile(profile_with_history(tmp_path), tmp_path / "evidence", confirm_closed=False)


def test_capture_refuses_a_non_empty_output_folder(tmp_path):
    out = tmp_path / "evidence"
    out.mkdir()
    (out / "existing.txt").write_text("x")
    with pytest.raises(FileExistsError):
        capture_closed_profile(profile_with_history(tmp_path), out, confirm_closed=True)


def test_capture_copies_history_and_journal_with_hashes(tmp_path):
    profile = profile_with_history(tmp_path)
    manifest = capture_closed_profile(profile, tmp_path / "evidence", confirm_closed=True)
    assert set(manifest["files"]) == {"History", "History-journal"}
    for name, info in manifest["files"].items():
        copied = tmp_path / "evidence" / name
        assert info["sha256"] == hashlib.sha256(copied.read_bytes()).hexdigest()
        assert copied.read_bytes() == (profile / "Default" / name).read_bytes()
    saved = json.loads((tmp_path / "evidence" / "manifest.json").read_text(encoding="utf-8"))
    assert saved["files"] == manifest["files"]


def test_analysis_does_not_modify_evidence(tmp_path):
    profile = profile_with_history(tmp_path)
    capture_closed_profile(profile, tmp_path / "evidence", confirm_closed=True)
    before = {p.name: p.read_bytes() for p in (tmp_path / "evidence").iterdir()}
    analyse(tmp_path / "evidence")
    after = {p.name: p.read_bytes() for p in (tmp_path / "evidence").iterdir()}
    assert before == after


def test_chrome_timestamp_conversion_matches_equation_1():
    moment = datetime(2026, 11, 11, 13, 27, 2, 139701, tzinfo=timezone.utc)
    chrome_time = (int(moment.timestamp()) + 11644473600) * 10**6 + moment.microsecond
    assert chrome_to_utc(chrome_time) == moment.isoformat()
    assert chrome_to_utc(0) == "" and CHROME_EPOCH.year == 1601


def test_pre_deletion_check_finds_all_saved_visits(tmp_path):
    profile = profile_with_history(tmp_path)
    capture_closed_profile(profile, tmp_path / "evidence", confirm_closed=True)
    report = verify_baseline(analyse(tmp_path / "evidence"), profile / "ground_truth.csv")
    assert report["correct_recoveries"] == report["expected_deleted_visits"] == 20


def test_scenario_plan_matches_the_proposal():
    assert {k: v["post"] for k, v in SCENARIOS.items()} == {"A": 0, "B": 100, "C": 500, "D": 0, "E": 0, "F": 1000}
    assert SCENARIOS["D"]["state"] == "reopen" and SCENARIOS["E"]["state"] == "restart"


def test_capture_refuses_to_write_into_the_profile(tmp_path):
    profile = profile_with_history(tmp_path)
    with pytest.raises((ValueError, FileExistsError)):
        capture_closed_profile(profile, profile / "Default", confirm_closed=True)


def test_header_reconstruction_rejects_random_bytes(tmp_path):
    import random
    import shutil
    from browserleak.carving import run
    truth = chrome_profile(tmp_path / "evidence")
    history = tmp_path / "evidence" / "History"
    data = bytearray(history.read_bytes())
    page_size = int.from_bytes(data[16:18], "big")
    rng = random.Random(1234)
    # Fill every page except the schema page with random bytes inside valid empty leaf pages.
    for page in range(1, len(data) // page_size):
        start = page * page_size
        data[start:start + page_size] = bytes([13, 0, 0, 0, 0, 0, 0, 0]) + bytes(rng.getrandbits(8) for _ in range(page_size - 8))
    noisy = tmp_path / "noisy" / "History"
    noisy.parent.mkdir()
    noisy.write_bytes(bytes(data))
    result = run(noisy, truth)
    assert result["linked_visit_candidates"] == 0
    assert result["validation"]["confirmed_matches"] == 0
