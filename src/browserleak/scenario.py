"""Reproducible scenario runner: one command per proposal scenario.

    python -m browserleak run --scenario A
    python -m browserleak finish --name E      (only after the Windows restart in scenario E)

Steps: known browsing (auto) -> pre-deletion capture and check -> deletion in
Chrome's own interface -> post-deletion condition -> post-deletion capture ->
recovery on real evidence -> positive control -> comparison.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .control import make_control
from .experiment import ExperimentServer, capture_closed_profile
from .pipeline import recover, write_json
from .validation import load_ground_truth

SCENARIOS = {
    "A": {"post": 0, "state": "closed", "condition": "Evidence acquired immediately after deletion"},
    "B": {"post": 100, "state": "closed", "condition": "100 additional visits after deletion"},
    "C": {"post": 500, "state": "closed", "condition": "500 additional visits after deletion"},
    "D": {"post": 0, "state": "reopen", "condition": "Chrome closed and reopened after deletion"},
    "E": {"post": 0, "state": "restart", "condition": "Windows restarted after deletion"},
    "F": {"post": 1000, "state": "closed", "condition": "1,000 additional visits after deletion"},
}


def say(step: str, text: str = "") -> None:
    print(f"\n=== {step} ===", flush=True)
    if text:
        print(text, flush=True)


def find_chrome(explicit: str | None) -> str:
    if explicit:
        return explicit
    candidates = []
    for variable in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
        if os.environ.get(variable):
            candidates.append(Path(os.environ[variable]) / "Google" / "Chrome" / "Application" / "chrome.exe")
    for path in candidates:
        if path.is_file():
            return str(path)
    for name in ("chrome", "google-chrome", "chromium", "chromium-browser"):
        found = shutil.which(name)
        if found:
            return found
    raise FileNotFoundError("Chrome not found. Pass --chrome with the full path to chrome.exe")


def launch(chrome: str, profile: Path, url: str, extra: list[str]) -> None:
    args = [chrome, f"--user-data-dir={profile}", "--no-first-run", "--no-default-browser-check",
            *extra, url]
    subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def chrome_running(profile: Path) -> bool:
    if any(os.path.lexists(profile / name) for name in ("lockfile", "SingletonLock")):
        if platform.system() != "Windows":
            return True
        try:  # On Windows also confirm a chrome.exe process uses this profile.
            output = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-CimInstance Win32_Process -Filter \"Name='chrome.exe'\" | "
                 "Select-Object -ExpandProperty CommandLine"],
                capture_output=True, text=True, timeout=30).stdout
            return str(profile).lower() in output.lower()
        except (OSError, subprocess.SubprocessError):
            return True
    return False


def wait_closed(profile: Path, message: str) -> None:
    print(message, flush=True)
    waited = 0
    while chrome_running(profile):
        time.sleep(1)
        waited += 1
        if waited % 30 == 0:
            print(f"  ...still waiting for Chrome to close ({waited}s). Close every window of the test profile.",
                  flush=True)
    time.sleep(2)  # let the file system settle after Chrome exits
    print("  Chrome is closed.", flush=True)


def wait_for(server: ExperimentServer, phase: str) -> None:
    total, last = server.total(phase), -1
    while not server.done(phase):
        count = len(server.served[phase])
        if count != last and (count % 25 == 0 or count == 1):
            print(f"  {count}/{total} {phase} visits", flush=True)
            last = count
        time.sleep(0.5)
    print(f"  {total}/{total} {phase} visits complete.", flush=True)


def run_scenario(scenario: str, name: str | None, root: Path, pages: int, searches: int,
                 post_count: int | None, port: int, chrome: str | None, delay_ms: int,
                 chrome_args: list[str]) -> Path | None:
    scenario = scenario.upper()
    if scenario not in SCENARIOS:
        raise ValueError(f"Scenario must be one of {', '.join(SCENARIOS)}")
    plan = dict(SCENARIOS[scenario])
    if post_count is not None:
        plan["post"] = post_count
        plan["condition"] = f"{post_count} additional visits after deletion"
    folder = (root / (name or scenario)).resolve()
    if folder.exists() and any(folder.iterdir()):
        raise FileExistsError(f"{folder} already exists. Use --name to give this run a new name, e.g. --name {scenario}2")
    folder.mkdir(parents=True, exist_ok=True)
    profile, truth = folder / "profile", folder / "ground_truth.csv"
    chrome = find_chrome(chrome)
    state = {"scenario": scenario, "name": folder.name, "condition": plan["condition"],
             "post_visits": plan["post"], "pages": pages, "searches": searches,
             "chrome": chrome, "started_utc": datetime.now(timezone.utc).isoformat()}
    write_json(folder / "scenario.json", state)

    server = ExperimentServer(port, truth, pages, searches, plan["post"], auto=True, delay_ms=delay_ms)
    try:
        server.start()
    except OSError as error:
        shutil.rmtree(folder, ignore_errors=True)
        raise SystemExit(f"Port {port} is already in use (is another BrowserLeak run still open? "
                         f"Press Ctrl+C there), or use --port 8766. Details: {error}")
    try:
        say(f"BrowserLeak scenario {scenario}: {plan['condition']}",
            f"Run folder: {folder}\nIndependent ground truth log: {truth}")

        say("Step 1/6  Known browsing activity",
            f"Opening a NEW, isolated Chrome profile. It will visit {pages} pages and {searches} searches "
            "by itself. Do not click anything.")
        launch(chrome, profile, server.start_url("baseline"), chrome_args)
        wait_for(server, "baseline")
        time.sleep(3)
        wait_closed(profile, "Now CLOSE the Chrome window (click the X). Waiting...")

        say("Step 2/6  Pre-deletion acquisition and check")
        pre = folder / "evidence_predelete"
        manifest = capture_closed_profile(profile, pre, True)
        print(f"  Copied: {', '.join(manifest['files'])}", flush=True)
        from .forensics import _active_database
        _, active, _ = _active_database(pre)
        saved = {r["url"] for r in active["urls"]}
        expected = {r["url"] for r in load_ground_truth(truth, "baseline")}
        print(f"  Chrome saved {len(expected & saved)}/{len(expected)} known visits before deletion.", flush=True)
        if len(expected & saved) < len(expected):
            print("  WARNING: not every visit was saved. Results will still be measured honestly.", flush=True)

        say("Step 3/6  Delete the history using Chrome's own interface",
            "Chrome will open again. In Chrome:\n"
            "  1. Press Ctrl+Shift+Delete (the 'Delete browsing data' window).\n"
            "  2. Time range: 'Last hour'. Tick ONLY 'Browsing history'.\n"
            "  3. Click 'Delete data'. Leave Chrome OPEN.")
        launch(chrome, profile, "chrome://history", chrome_args)
        input("Press Enter HERE after Chrome has deleted the history... ")
        state["deleted_utc"] = datetime.now(timezone.utc).isoformat()

        say("Step 4/6  Post-deletion condition", plan["condition"])
        if plan["post"]:
            server.enable_post()
            print(f"  Chrome will now make {plan['post']} new visits by itself. Do not click anything.", flush=True)
            launch(chrome, profile, server.start_url("post"), chrome_args)
            wait_for(server, "post")
            time.sleep(3)
        wait_closed(profile, "Now CLOSE the Chrome window. Waiting...")
        if plan["state"] == "reopen":
            print("  Reopening Chrome with the same profile (as a user would)...", flush=True)
            launch(chrome, profile, "about:blank", chrome_args)
            time.sleep(15)
            wait_closed(profile, "Now CLOSE the Chrome window again. Waiting...")
        state["post_condition_done_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(folder / "scenario.json", state)
    finally:
        server.stop()

    if plan["state"] == "restart":
        say("Restart required",
            "Restart Windows now (Start > Power > Restart). After logging back in, open PowerShell and run:\n"
            f"  cd {Path.cwd()}\n"
            "  $env:PYTHONPATH = (Resolve-Path .\\src).Path\n"
            f"  python -m browserleak finish --name {folder.name} --root {root}")
        return None
    return finish_scenario(folder)


def finish_scenario(folder: Path) -> Path:
    folder = Path(folder).resolve()
    state = json.loads((folder / "scenario.json").read_text(encoding="utf-8"))
    profile, truth = folder / "profile", folder / "ground_truth.csv"
    if chrome_running(profile):
        wait_closed(profile, "Chrome is still using the test profile. Close it. Waiting...")

    say("Step 5/6  Post-deletion acquisition")
    post = folder / "evidence_postdelete"
    manifest = capture_closed_profile(profile, post, True)
    for file, info in manifest["files"].items():
        print(f"  {file}: {info['size']} bytes, SHA-256 {info['sha256'][:16]}...", flush=True)

    say("Step 6/6  Recovery and validation against ground truth")
    real = recover(post, truth, folder / "results_real", state["name"], state["condition"], "real Chrome deletion")
    control_dir = folder / "evidence_control"
    make_control(folder / "evidence_predelete", truth, control_dir,
                 post_count=state["post_visits"])
    control = recover(control_dir, truth, folder / "results_control", state["name"], state["condition"],
                      "positive control (secure_delete OFF)")

    def line(label, key, fmt="{}"):
        a, b = real[key], control[key]
        print(f"  {label:<38}{fmt.format(a) if a is not None else 'n/a':>14}{fmt.format(b) if b is not None else 'n/a':>18}")

    say(f"RESULT  scenario {state['name']}: {state['condition']}")
    print(f"  {'':<38}{'Real Chrome':>14}{'Positive control':>18}")
    line("Deleted visits (ground truth)", "deleted_visits")
    line("Deleted URLs still in history (0 = OK)", "deleted_urls_still_in_current_history")
    line("Correctly recovered", "correctly_recovered")
    line("Incorrectly recovered", "incorrectly_recovered")
    line("Recovery rate", "recovery_rate_percent", "{}%")
    line("Recovery accuracy", "recovery_accuracy_percent", "{}%")
    line("Deleted URLs left in raw bytes", "deleted_urls_present_in_raw_bytes")
    line("Processing time (s)", "processing_seconds")
    print(f"  Recovery sources (control): {control['correct_by_recovery_source'] or 'none'}")
    print(f"  Recovery sources (real):    {real['correct_by_recovery_source'] or 'none'}")
    print(f"\n  Reports: {folder / 'results_real' / 'report.md'}\n           {folder / 'results_control' / 'report.md'}")
    print(f"  Per-record CSV: {folder / 'results_real' / 'recovered_records.csv'}")
    state["finished_utc"] = datetime.now(timezone.utc).isoformat()
    write_json(folder / "scenario.json", state)
    return folder


if __name__ == "__main__":
    sys.exit("Use: python -m browserleak run --scenario A")
