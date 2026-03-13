from __future__ import annotations
import os
import sys

if os.geteuid() != 0:
    print("[ERROR] Ten program wymaga uprawnień root.")
    print("        Uruchom: sudo python3 main.py")
    sys.exit(1)

from pathlib import Path
import argparse
from datetime import datetime
from ir_collector.collectors.system import collect_system
from ir_collector.collectors.processes import collect_processes
from ir_collector.collectors.network import collect_network
from ir_collector.report.markdown import write_markdown_report
from ir_collector.utils.ownership import chown_tree_to_sudo_user
from ir_collector.collectors.users import collect_users
from ir_collector.collectors.logs import collect_logs
from ir_collector.collectors.persistence import collect_persistence
from ir_collector.analysis.severity import calculate_severity
from ir_collector.utils.hashing import generate_checksums
from ir_collector.report.json_export import write_json_report

# Parsowanie argumentów
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="linux-ir-collector",
        description="Incident Response collector for Linux (system/process/network snapshot).",
    )
    # katalog wyjściowy
    p.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output directory. If omitted, creates report_YYYY-mm-dd_HHMMSS in current dir.",
    )
    # Pominięcie generowania raportu (tylko surowe artefakty)
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
    os.chmod(out_dir, 0o700)

    results = {}
    for name, func in [
        ("system", collect_system),
        ("processes", collect_processes),
        ("network", collect_network),
        ("users", collect_users),
        ("logs", collect_logs),
        ("persistence", collect_persistence),
    ]:
        try:
            print(f"[*] Collecting {name}...")
            results[name] = func(out_dir)
        except Exception as e:
            print(f"[WARN] Collector '{name}' failed: {e}")
            results[name] = {"error": str(e)}

    level, reasons = calculate_severity(results)
    results["severity"] = {
        "level": level,
        "reasons": reasons,
    }

    if not args.no_report:
        write_markdown_report(out_dir, results)
        write_json_report(out_dir, results) 

    generate_checksums(out_dir)  
    print("[+] Checksums written to checksums.sha256")

    changed = chown_tree_to_sudo_user(out_dir)
    if changed:
        print("[+] Ownership changed to the invoking user (SUDO_UID/GID).")

    print(f"[+] Done. Output: {out_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
