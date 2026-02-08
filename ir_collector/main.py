from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path
import sys

from ir_collector.collectors.system import collect_system
from ir_collector.collectors.processes import collect_processes
from ir_collector.collectors.network import collect_network
from ir_collector.report.markdown import write_markdown_report


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="linux-ir-collector",
        description="Incident Response collector for Linux (system/process/network snapshot).",
    )
    p.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output directory. If omitted, creates report_YYYY-mm-dd_HHMMSS in current dir.",
    )
    p.add_argument(
        "--no-report",
        action="store_true",
        help="Do not generate report.md (collect raw artifacts only).",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()

    ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    out_dir = Path(args.output) if args.output else Path(f"report_{ts}")
    out_dir.mkdir(parents=True, exist_ok=True)

    # Run collectors
    results = {}
    results["system"] = collect_system(out_dir)
    results["processes"] = collect_processes(out_dir)
    results["network"] = collect_network(out_dir)

    if not args.no_report:
        write_markdown_report(out_dir, results)

    print(f"[+] Done. Output: {out_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
