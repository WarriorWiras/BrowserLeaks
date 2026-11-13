"""Cross-scenario summary table, bar chart and overwrite curve (SVG, no extra packages)."""
from __future__ import annotations

import csv
import shutil
import html
import json
from pathlib import Path


SUMMARY_FIELDS = ["run", "scenario", "condition", "post_visits", "evidence", "deleted_visits",
                  "correctly_recovered", "not_recovered", "incorrectly_recovered",
                  "recovery_rate_percent", "recovery_accuracy_percent",
                  "deleted_urls_still_in_current_history", "deleted_urls_present_in_raw_bytes",
                  "correct_by_recovery_source", "processing_seconds"]


def summarise_runs(root: Path, output: Path) -> tuple[Path, Path, Path]:
    """Collect every finished scenario run into one CSV, Markdown table and SVG chart."""
    root, output = Path(root), Path(output)
    rows = []
    for state_file in sorted(root.glob("*/scenario.json")):
        state = json.loads(state_file.read_text(encoding="utf-8"))
        for kind in ("real", "control"):
            result_file = state_file.parent / f"results_{kind}" / "result.json"
            if not result_file.is_file():
                continue
            r = json.loads(result_file.read_text(encoding="utf-8"))
            rows.append({"run": state["name"], "scenario": state["scenario"], "condition": state["condition"],
                         "post_visits": state["post_visits"],
                         "evidence": "Real Chrome" if kind == "real" else "Control (secure_delete OFF)",
                         **{k: r.get(k) for k in SUMMARY_FIELDS[5:]}})
    if not rows:
        raise FileNotFoundError(f"No finished scenario runs under {root}")
    for row in rows:
        row["correct_by_recovery_source"] = "; ".join(f"{k}={v}" for k, v in (row["correct_by_recovery_source"] or {}).items())
    output.mkdir(parents=True, exist_ok=True)
    csv_file, md_file, svg_file = output / "summary.csv", output / "summary.md", output / "summary.svg"
    with csv_file.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    header = ["Run", "Condition", "Evidence", "Deleted", "Correct", "Incorrect", "Recovery rate",
              "Accuracy", "Left in raw bytes", "Sources"]
    md = ["# BrowserLeak results across scenarios", "",
          "| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    for r in rows:
        accuracy = "n/a" if r["recovery_accuracy_percent"] is None else f"{r['recovery_accuracy_percent']}%"
        md.append(f"| {r['run']} | {r['condition']} | {r['evidence']} | {r['deleted_visits']} | "
                  f"{r['correctly_recovered']} | {r['incorrectly_recovered']} | {r['recovery_rate_percent']}% | "
                  f"{accuracy} | {r['deleted_urls_present_in_raw_bytes']} | {r['correct_by_recovery_source'] or '-'} |")
    md += ["", "Recovery rate = correctly recovered / deleted visits x 100. "
           "Accuracy = correctly recovered / all full visits reported x 100.",
           "Real Chrome deletion uses Chrome's own secure delete. The control repeats the same deletion "
           "with secure_delete OFF."]
    md_file.write_text("\n".join(md) + "\n", encoding="utf-8")

    runs = list(dict.fromkeys(r["run"] for r in rows))
    lookup = {(r["run"], r["evidence"].split()[0]): float(r["recovery_rate_percent"] or 0) for r in rows}
    labels = {r["run"]: (r["run"], f"+{r['post_visits']} visits" if r["post_visits"] else
                         {"D": "reopened", "E": "restarted"}.get(r["scenario"], "immediate")) for r in rows}
    group = 150
    width = max(720, 120 + group * len(runs))
    height, left, top, bottom = 460, 80, 70, 360
    plot_h, plot_w = bottom - top, width - left - 40
    colours = {"Real": "#5b6770", "Control": "#2a7de1"}
    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" font-family="Arial">',
           '<rect width="100%" height="100%" fill="white"/>',
           '<text x="20" y="30" font-size="18" font-weight="bold">Deleted Chrome history recovered by BrowserLeak</text>',
           '<text x="20" y="52" font-size="13" fill="#444">Recovery rate per scenario: real Chrome deletion vs positive control</text>']
    for pct in (0, 25, 50, 75, 100):
        y = bottom - pct / 100 * plot_h
        svg += [f'<line x1="{left}" x2="{left + plot_w}" y1="{y}" y2="{y}" stroke="#e3e3e3"/>',
                f'<text x="{left - 8}" y="{y + 4}" font-size="12" text-anchor="end">{pct}%</text>']
    step = plot_w / len(runs)
    for i, run in enumerate(runs):
        centre = left + step * (i + 0.5)
        for j, kind in enumerate(("Real", "Control")):
            if (run, kind) not in lookup:
                continue
            rate = max(0.0, min(100.0, lookup[(run, kind)]))
            h = rate / 100 * plot_h
            x = centre - 46 + j * 48
            svg += [f'<rect x="{x}" y="{bottom - h}" width="44" height="{max(h, 1.5)}" fill="{colours[kind]}"/>',
                    f'<text x="{x + 22}" y="{bottom - h - 6}" font-size="12" text-anchor="middle">{rate:.0f}%</text>']
        name, sub = labels[run]
        svg += [f'<text x="{centre}" y="{bottom + 20}" font-size="13" text-anchor="middle" font-weight="bold">{html.escape(name)}</text>',
                f'<text x="{centre}" y="{bottom + 37}" font-size="12" text-anchor="middle" fill="#444">{html.escape(sub)}</text>']
    ly = height - 40
    for k, (kind, label) in enumerate((("Real", "Real Chrome deletion (secure delete ON)"),
                                       ("Control", "Positive control (secure_delete OFF)"))):
        x = left + k * 330
        svg += [f'<rect x="{x}" y="{ly - 11}" width="14" height="14" fill="{colours[kind]}"/>',
                f'<text x="{x + 20}" y="{ly}" font-size="13">{label}</text>']
    svg.append("</svg>")
    svg_file.write_text("\n".join(svg), encoding="utf-8")
    return csv_file, md_file, svg_file


def overwrite_curve(run_folder: Path, counts: list[int], output: Path | None = None) -> tuple[Path, Path]:
    """Effect of post-deletion activity: controls with increasing simulated visits.

    Every point starts from the same PRE-deletion evidence, deletes the known visits with
    secure_delete OFF, then adds N simulated visits before recovery.
    """
    from .control import make_control
    from .pipeline import recover
    run_folder = Path(run_folder)
    truth, pre = run_folder / "ground_truth.csv", run_folder / "evidence_predelete"
    output = Path(output or run_folder / "curve")
    if output.exists():
        shutil.rmtree(output)
    rows = []
    for n in sorted(set(counts)):
        evidence = output / f"control_post{n}"
        make_control(pre, truth, evidence, post_count=n)
        r = recover(evidence, truth, output / f"results_post{n}", run_folder.name,
                    f"control + {n} simulated visits", "positive control")
        rows.append({"post_deletion_visits": n, "deleted_visits": r["deleted_visits"],
                     "correctly_recovered": r["correctly_recovered"],
                     "incorrectly_recovered": r["incorrectly_recovered"],
                     "recovery_rate_percent": r["recovery_rate_percent"],
                     "deleted_urls_found_as_url_only": r["deleted_urls_found_as_url_only"]})
        print(f"  +{n:>4} visits: recovered {r['correctly_recovered']}/{r['deleted_visits']} "
              f"({r['recovery_rate_percent']}%), incorrect {r['incorrectly_recovered']}", flush=True)
    csv_file, svg_file = output / "curve.csv", output / "curve.svg"
    with csv_file.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    width, height, left, right, top, bottom = 760, 470, 80, 40, 70, 350
    plot_w, plot_h = width - left - right, bottom - top
    xs = [str(r["post_deletion_visits"]) for r in rows]
    step = plot_w / max(1, len(rows) - 1)
    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" font-family="Arial">',
           '<rect width="100%" height="100%" fill="white"/>',
           '<text x="20" y="30" font-size="18" font-weight="bold">Effect of post-deletion browsing on recovery</text>',
           '<text x="20" y="52" font-size="13" fill="#444">Positive control (secure_delete OFF), same deleted visits, increasing new visits</text>']
    for pct in (0, 25, 50, 75, 100):
        y = bottom - pct / 100 * plot_h
        svg += [f'<line x1="{left}" x2="{left + plot_w}" y1="{y}" y2="{y}" stroke="#e3e3e3"/>',
                f'<text x="{left - 8}" y="{y + 4}" font-size="12" text-anchor="end">{pct}%</text>']
    series = [("recovery_rate_percent", "#2a7de1", "Full deleted visits recovered (URL + timestamp)"),
              ("url_only_percent", "#e08a1e", "Deleted URLs still found as URL text only")]
    for r in rows:
        r["url_only_percent"] = round(100 * r["deleted_urls_found_as_url_only"] / r["deleted_visits"], 2) if r["deleted_visits"] else 0
    for key, colour, _ in series:
        points = " ".join(f"{left + i * step:.1f},{bottom - float(r[key]) / 100 * plot_h:.1f}" for i, r in enumerate(rows))
        svg.append(f'<polyline points="{points}" fill="none" stroke="{colour}" stroke-width="3"/>')
        for i, r in enumerate(rows):
            svg.append(f'<circle cx="{left + i * step:.1f}" cy="{bottom - float(r[key]) / 100 * plot_h:.1f}" r="4" fill="{colour}"/>')
    for i, label in enumerate(xs):
        svg.append(f'<text x="{left + i * step:.1f}" y="{bottom + 20}" font-size="12" text-anchor="middle">{label}</text>')
    svg.append(f'<text x="{left + plot_w / 2}" y="{bottom + 42}" font-size="13" text-anchor="middle">New visits after deletion</text>')
    for k, (_, colour, label) in enumerate(series):
        svg += [f'<rect x="{left + k * 340}" y="{height - 46}" width="14" height="14" fill="{colour}"/>',
                f'<text x="{left + k * 340 + 20}" y="{height - 34}" font-size="13">{label}</text>']
    svg.append("</svg>")
    svg_file.write_text("\n".join(svg), encoding="utf-8")
    return csv_file, svg_file
