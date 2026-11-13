"""Full BrowserLeak recovery on one evidence folder.

Combines every recovery method, validates against the independent ground truth
and writes the per-record output described in the project proposal:
URL, visit time, database table, recovery source, recovery status,
experiment condition and ground-truth match.
"""
from __future__ import annotations

import csv
import json
import time
from pathlib import Path

from . import carving
from .forensics import analyse, save_json
from .validation import load_ground_truth, match_visits

RECORD_FIELDS = ["scenario", "condition", "evidence", "recovery_status", "ground_truth_match",
                 "record_type", "url", "visit_time_utc", "database_table", "recovery_source",
                 "link_method", "page", "offset"]


def raw_occurrences(evidence: Path, truth: list[dict]) -> int:
    """Count deleted URLs whose bytes still appear anywhere in the acquired files."""
    data = b"".join((evidence / name).read_bytes()
                    for name in ("History", "History-wal", "History-journal")
                    if (evidence / name).is_file())
    return sum(1 for row in {r["url"] for r in truth} if row.encode("utf-8") in data)


def still_active(analysis: dict, evidence: Path, truth: list[dict]) -> int:
    """How many of the deleted URLs are still in Chrome's current (logical) history."""
    from .forensics import _active_database
    _, active, _ = _active_database(evidence)
    current = {row["url"] for row in active["urls"]}
    return sum(1 for url in {r["url"] for r in truth} if url in current)


def recover(evidence: Path, ground_truth: Path, output: Path, scenario: str = "",
            condition: str = "", evidence_kind: str = "", tolerance: float = 2.0) -> dict:
    evidence, output = Path(evidence), Path(output)
    output.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    analysis = analyse(evidence)
    carved = carving.run(evidence / "History")
    seconds = round(time.perf_counter() - started, 4)

    full, partial = [], []
    for c in analysis["candidates"]:
        item = {"url": c["url"], "visit_time_raw": c["visit_time_raw"],
                "visit_time_utc": c["visit_time_utc"], "source": c["source"],
                "page": c["page"], "offset": c["offset"], "link_method": "url_id",
                "table": "visits" if c["level"] == "visit" else "urls"}
        (full if c["level"] == "visit" else partial).append(dict(item, record_type=c["level"]))
    for f in carved["findings"]:
        raw_time = f["decoded_record"].get("visit_time")
        item = {"url": f["url"], "visit_time_raw": raw_time, "visit_time_utc": f["visit_time_utc"] or "",
                "source": f["source"], "page": f["page"], "offset": f["offset"],
                "link_method": f.get("link_method") or "", "table": f["table"]}
        if f["level"] == "linked_visit_candidate":
            full.append(dict(item, record_type="visit"))
        elif f["url"]:
            partial.append(dict(item, record_type=f["level"]))

    truth = load_ground_truth(ground_truth, "baseline")
    report = match_visits(full, truth, tolerance)
    matched = {(m["url"], m["recovered_time"]) for m in report["matches"]}
    deleted_urls = {r["url"] for r in truth}

    rows, seen = [], set()
    for c in full:
        key = (c["url"], c["visit_time_raw"])
        if key in seen:
            continue
        seen.add(key)
        good = (c["url"], c["visit_time_utc"]) in matched
        rows.append({**c, "recovery_status": "correctly_recovered" if good else "incorrectly_recovered",
                     "ground_truth_match": "Yes" if good else "No", "record_type": "full_visit"})
    for c in partial:
        key = (c["url"], c["record_type"])
        if key in seen:
            continue
        seen.add(key)
        rows.append({"recovery_status": "partial_url_not_counted",
                     "ground_truth_match": "URL only" if any(c["url"].startswith(u) for u in deleted_urls) else "No",
                     **c})
    found = {m["url"] + "|" + m["expected_time"] for m in report["matches"]}
    for t in truth:
        if t["url"] + "|" + t["visited_at_utc"] not in found:
            rows.append({"recovery_status": "not_recovered", "ground_truth_match": "No",
                         "record_type": "deleted_visit", "url": t["url"],
                         "visit_time_utc": t["visited_at_utc"], "table": "", "source": "",
                         "link_method": "", "page": "", "offset": ""})
    for r in rows:
        r.update(scenario=scenario, condition=condition, evidence=evidence_kind,
                 database_table=r.get("table", ""), recovery_source=r.get("source", ""))

    by_source: dict[str, int] = {}
    for m in report["matches"]:
        by_source[m["source"] or "unspecified"] = by_source.get(m["source"] or "unspecified", 0) + 1
    result = {
        "scenario": scenario, "condition": condition, "evidence": evidence_kind,
        "evidence_path": str(evidence), "evidence_hashes": analysis["hashes"],
        "sqlite": analysis["settings"],
        "deleted_visits": report["expected_deleted_visits"],
        "correctly_recovered": report["correct_recoveries"],
        "not_recovered": report["missed_visits"],
        "incorrectly_recovered": report["false_recoveries"],
        "recovery_rate_percent": report["recovery_rate_percent"],
        "recovery_accuracy_percent": report["precision_percent"] if report["reported_full_visit_candidates"] else None,
        "partial_url_records": sum(1 for r in rows if r["recovery_status"] == "partial_url_not_counted"),
        "correct_by_recovery_source": by_source,
        "deleted_urls_found_as_url_only": sum(
            1 for u in deleted_urls
            if any(r["recovery_status"] == "partial_url_not_counted" and (r["url"] or "").startswith(u)
                   for r in rows)),
        "deleted_urls_still_in_current_history": still_active(analysis, evidence, truth),
        "deleted_urls_present_in_raw_bytes": raw_occurrences(evidence, truth),
        "processing_seconds": seconds,
        "tolerance_seconds": tolerance,
        "matches": report["matches"],
        "warnings": analysis["warnings"],
        "limitations": analysis["limitations"] + carved["limitations"],
    }
    save_json(output / "result.json", result)
    with (output / "recovered_records.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=RECORD_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    (output / "report.md").write_text(markdown(result), encoding="utf-8")
    return result


def markdown(r: dict) -> str:
    accuracy = "n/a (nothing reported)" if r["recovery_accuracy_percent"] is None else f"{r['recovery_accuracy_percent']}%"
    lines = [f"# BrowserLeak result: scenario {r['scenario']} ({r['evidence']})", "",
             f"Condition: {r['condition']}", "", "## Recovery performance", "",
             "| Metric | Value |", "|---|---|",
             f"| Deleted visits (ground truth) | {r['deleted_visits']} |",
             f"| Correctly recovered | {r['correctly_recovered']} |",
             f"| Not recovered | {r['not_recovered']} |",
             f"| Incorrectly recovered | {r['incorrectly_recovered']} |",
             f"| Recovery rate | {r['recovery_rate_percent']}% |",
             f"| Recovery accuracy (precision) | {accuracy} |",
             f"| Partial URL-only records (not counted) | {r['partial_url_records']} |",
             f"| Deleted URLs found only as URL text | {r['deleted_urls_found_as_url_only']} |",
             f"| Processing time | {r['processing_seconds']} s |",
             f"| Deleted URLs still in current history | {r['deleted_urls_still_in_current_history']} |",
             f"| Deleted URLs present anywhere in raw bytes | {r['deleted_urls_present_in_raw_bytes']} |",
             "", "## Recovery sources (correct recoveries)", ""]
    lines += [f"- {k}: {v}" for k, v in r["correct_by_recovery_source"].items()] or ["- none"]
    lines += ["", "## SQLite evidence", "",
              f"- Page size: {r['sqlite']['page_size']} bytes",
              f"- Journal mode: {r['sqlite']['journal_mode']}",
              f"- Journal files acquired: {', '.join(r['sqlite']['journal_files_present']) or 'none'}",
              f"- Secure delete: {r['sqlite']['secure_delete']}", "", "## Evidence integrity (SHA-256)", ""]
    lines += [f"- {k}: `{v}`" for k, v in r["evidence_hashes"].items()]
    lines += ["", "## Limitations", ""] + [f"- {x}" for x in r["limitations"]]
    return "\n".join(lines) + "\n"


def write_json(path: Path, data: dict) -> None:
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
