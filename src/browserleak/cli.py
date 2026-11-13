"""Command line interface: python -m browserleak <command>."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .forensics import analyse

SCENARIO_HELP = "A immediate, B +100 visits, C +500 visits, D Chrome reopened, E Windows restarted, F +1000 visits"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="browserleak",
        description="BrowserLeak: measure how much deleted Google Chrome history can be recovered from SQLite")
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="Guided experiment for one scenario (A-F)")
    run.add_argument("--scenario", required=True, help=SCENARIO_HELP)
    run.add_argument("--name", help="Run folder name (default: the scenario letter)")
    run.add_argument("--root", type=Path, default=Path("data/scenarios"))
    run.add_argument("--pages", type=int, default=15, help="Known pages visited before deletion")
    run.add_argument("--searches", type=int, default=5, help="Known searches made before deletion (max 10)")
    run.add_argument("--post-count", type=int, help="Override the number of post-deletion visits")
    run.add_argument("--port", type=int, default=8765)
    run.add_argument("--delay-ms", type=int, default=300, help="Delay between automatic page visits")
    run.add_argument("--chrome", help="Full path to chrome.exe if it is not found automatically")
    run.add_argument("--chrome-arg", action="append", default=[], help="Extra Chrome argument (repeatable)")

    finish = commands.add_parser("finish", help="Finish a run (after the Windows restart in scenario E)")
    finish.add_argument("--name", required=True)
    finish.add_argument("--root", type=Path, default=Path("data/scenarios"))

    summary = commands.add_parser("summary", help="Table and chart across all finished runs")
    summary.add_argument("--root", type=Path, default=Path("data/scenarios"))
    summary.add_argument("--out", type=Path, default=Path("data/summary"))

    curve = commands.add_parser("curve", help="Recovery against post-deletion visits, from one finished run")
    curve.add_argument("--name", required=True, help="Finished run folder name, e.g. A")
    curve.add_argument("--root", type=Path, default=Path("data/scenarios"))
    curve.add_argument("--counts", type=int, nargs="+", default=[0, 1, 2, 5, 10, 15, 20, 50, 100, 500, 1000])

    recover = commands.add_parser("recover", help="Full recovery and validation on any evidence folder")
    recover.add_argument("--evidence", type=Path, required=True)
    recover.add_argument("--ground-truth", type=Path, required=True)
    recover.add_argument("--out", type=Path, required=True)
    recover.add_argument("--label", default="manual")
    recover.add_argument("--tolerance", type=float, default=2.0, help="Timestamp tolerance in seconds")

    control = commands.add_parser("control", help="Positive control: same deletion with secure_delete OFF")
    control.add_argument("--evidence", type=Path, required=True, help="PRE-deletion evidence folder")
    control.add_argument("--ground-truth", type=Path, required=True)
    control.add_argument("--out", type=Path, required=True)
    control.add_argument("--post-count", type=int, default=0, help="Simulated post-deletion visits")

    capture = commands.add_parser("capture", help="Copy and hash History files from a CLOSED Chrome profile")
    capture.add_argument("--profile", type=Path, required=True)
    capture.add_argument("--out", type=Path, required=True)
    capture.add_argument("--confirm-closed", action="store_true")

    baseline = commands.add_parser("verify-baseline", help="Check that Chrome saved the known visits (pre-deletion)")
    baseline.add_argument("--evidence", type=Path, required=True)
    baseline.add_argument("--ground-truth", type=Path, required=True)
    baseline.add_argument("--tolerance", type=float, default=10.0)

    demo = commands.add_parser("demo", help="Synthetic WAL recovery demonstration (no Chrome needed)")
    demo.add_argument("--out", type=Path, default=Path("data/demo"))
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "run":
        from .scenario import run_scenario
        run_scenario(args.scenario, args.name, args.root, args.pages, args.searches, args.post_count,
                     args.port, args.chrome, args.delay_ms, args.chrome_arg)
    elif args.command == "finish":
        from .scenario import finish_scenario
        finish_scenario(args.root / args.name)
    elif args.command == "summary":
        from .summary import summarise_runs
        for path in summarise_runs(args.root, args.out):
            print(f"Written: {path}")
    elif args.command == "curve":
        from .summary import overwrite_curve
        for path in overwrite_curve(args.root / args.name, args.counts):
            print(f"Written: {path}")
    elif args.command == "recover":
        from .pipeline import recover
        r = recover(args.evidence, args.ground_truth, args.out, args.label, "", args.label, args.tolerance)
        print(f"Recovered {r['correctly_recovered']}/{r['deleted_visits']} deleted visits "
              f"({r['recovery_rate_percent']}%); incorrect: {r['incorrectly_recovered']}")
        print(f"Sources: {r['correct_by_recovery_source'] or 'none'}\nReport: {args.out / 'report.md'}")
    elif args.command == "control":
        from .control import make_control
        print(json.dumps(make_control(args.evidence, args.ground_truth, args.out, args.post_count), indent=2))
    elif args.command == "capture":
        from .experiment import capture_closed_profile
        print(json.dumps(capture_closed_profile(args.profile, args.out, args.confirm_closed), indent=2))
    elif args.command == "verify-baseline":
        from .validation import verify_baseline
        print(json.dumps(verify_baseline(analyse(args.evidence), args.ground_truth, args.tolerance), indent=2))
    elif args.command == "demo":
        from .demo import create_demo
        result = create_demo(args.out)
        print("SYNTHETIC SQLITE DEMO (not a Chrome experiment)")
        print(f"Correctly recovered: {result['correct_recoveries']} / {result['expected_deleted_visits']}")
        print(f"Report: {args.out / 'report.md'}")


if __name__ == "__main__":
    main()
