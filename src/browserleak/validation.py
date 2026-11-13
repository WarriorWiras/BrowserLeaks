"""Validate full recovered visits against independent local HTTP server observations."""
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from .forensics import chrome_to_utc


def load_ground_truth(path: Path, phase: str = "baseline") -> list[dict]:
    with Path(path).open(newline="", encoding="utf-8") as stream:
        rows = [r for r in csv.DictReader(stream) if r.get("phase") == phase]
    if not rows:
        raise ValueError(f"No rows found for phase {phase!r} in ground truth log")
    for row in rows:
        row["at"] = datetime.fromisoformat(row["visited_at_utc"].replace("Z", "+00:00"))
        if row["at"].tzinfo is None:
            raise ValueError("Ground truth timestamps must include timezone")
    return rows


def match_visits(visits: list[dict], truth: list[dict], tolerance_seconds: float) -> dict:
    if tolerance_seconds < 0:
        raise ValueError("tolerance_seconds must be nonnegative")
    seen = set()
    deduplicated = []
    for row in visits:
        key = (row.get("url"), row.get("visit_time_raw"))
        if not row.get("url") or not row.get("visit_time_utc") or key in seen:
            continue
        seen.add(key)
        deduplicated.append(row)
    # Match the closest eligible timestamp for each candidate, one to one.
    possible = []
    for i, found in enumerate(deduplicated):
        found_at = datetime.fromisoformat(found["visit_time_utc"])
        for j, expected in enumerate(truth):
            if found["url"] != expected["url"]:
                continue
            difference = abs((found_at - expected["at"]).total_seconds())
            if difference <= tolerance_seconds:
                possible.append((difference, i, j))
    matched_candidates, matched_truth = set(), set()
    pairs = []
    for delta, i, j in sorted(possible):
        if i not in matched_candidates and j not in matched_truth:
            matched_candidates.add(i)
            matched_truth.add(j)
            pairs.append({"url": truth[j]["url"],
                          "expected_time": truth[j]["visited_at_utc"],
                          "recovered_time": deduplicated[i]["visit_time_utc"],
                          "time_difference_seconds": round(delta, 3),
                          "source": deduplicated[i].get("source"),
                          "page": deduplicated[i].get("page"),
                          "frame": deduplicated[i].get("frame")})
    good = len(matched_candidates)
    total = len(truth)
    false = len(deduplicated) - good
    return {"expected_deleted_visits": total,
            "reported_full_visit_candidates": len(deduplicated),
            "correct_recoveries": good,
            "missed_visits": total - good,
            "false_recoveries": false,
            "recovery_rate_percent": round(100 * good / total, 2) if total else 0,
            "precision_percent": round(100 * good / len(deduplicated), 2) if deduplicated else 0,
            "matches": pairs,
            "unmatched_candidates": [deduplicated[i] for i in range(len(deduplicated))
                                     if i not in matched_candidates]}


def validate_analysis(analysis: dict, ground_truth: Path, tolerance_seconds: float = 10) -> dict:
    truth = load_ground_truth(ground_truth)
    full = [r for r in analysis["candidates"] if r["level"] == "visit"]
    report = match_visits(full, truth, tolerance_seconds)
    report["partial_url_candidates"] = sum(
        1 for r in analysis["candidates"] if r["level"] != "visit")
    report["tolerance_seconds"] = tolerance_seconds
    source_counts = {}
    for match in report["matches"]:
        name = match.get("source") or "unspecified"
        source_counts[name] = source_counts.get(name, 0) + 1
    report["correct_recoveries_by_source"] = source_counts
    report["processing_seconds"] = analysis.get("processing_seconds")
    report["evidence_hashes"] = analysis.get("hashes", {})
    report["caution"] = ("Only independently matched full visits count as correct recoveries. "
                         "The ground truth must accurately represent visits deliberately removed in this trial.")
    return report


def verify_baseline(analysis: dict, ground_truth: Path, tolerance_seconds: float = 10) -> dict:
    # Before deletion, analyse() only returns inactive records. Compare directly
    # against the active tables in a disposable SQLite copy.
    from .forensics import _active_database
    _, active, _ = _active_database(Path(analysis["evidence_path"]))
    url_map = {r["id"]: r["url"] for r in active["urls"]}
    visits = [{"url": url_map.get(r["url"]),
               "visit_time_raw": r["visit_time"],
               "visit_time_utc": chrome_to_utc(r["visit_time"])}
              for r in active["visits"]]
    report = match_visits(visits, load_ground_truth(ground_truth), tolerance_seconds)
    report["note"] = "This verifies generated visits were recorded before deletion; it is not a recovery rate."
    return report


def markdown_report(analysis: dict, validation: dict) -> str:
    s = analysis["settings"]
    lines = ["# BrowserLeak experiment report", "",
             "## Evidence integrity", ""]
    for name, digest in analysis["hashes"].items():
        lines.append(f"- {name}: SHA-256 `{digest}`")
    lines.extend(["", "## SQLite conditions", "",
                  f"- Page size: {s['page_size']} bytes",
                  f"- Secure delete: {s['secure_delete']}",
                  f"- Journal mode: {s['journal_mode']}",
                  f"- Journal files acquired: {', '.join(s.get('journal_files_present') or []) or 'none'}",
                  f"- Committed WAL frames examined: {analysis['wal_committed_frames']}",
                  f"- Processing time: {analysis.get('processing_seconds', 'not recorded')} seconds",
                  "", "## Validation", "",
                  f"- Expected deleted visits: {validation['expected_deleted_visits']}",
                  f"- Correctly recovered visits: {validation['correct_recoveries']}",
                  f"- Missed visits: {validation['missed_visits']}",
                  f"- False recovery candidates: {validation['false_recoveries']}",
                  f"- Recovery rate: {validation['recovery_rate_percent']}%",
                  f"- Precision: {validation['precision_percent']}%",
                  f"- Partial URL candidates (not counted as visits): {validation['partial_url_candidates']}",
                  "", "## Recovery sources", "",
                  *[f"- {source}: {count} confirmed matches"
                    for source, count in validation.get("correct_recoveries_by_source", {}).items()],
                  "", "## Interpretation", "",
                  "Candidates must be assessed alongside the ground truth and acquisition notes.",
                  "A missing deleted record does not imply that it was never visited.",
                  "", "## Limitations", ""])
    lines.extend("- " + x for x in analysis["limitations"])
    if analysis["warnings"]:
        lines.extend(["", "## Warnings", ""])
        lines.extend("- " + x for x in analysis["warnings"])
    return "\n".join(lines) + "\n"
