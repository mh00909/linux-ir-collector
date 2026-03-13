from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from ir_collector.utils.fs import write_text


def write_json_report(out_dir: Path, results: dict) -> None:
    report = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "output_directory": str(out_dir.resolve()),
        "results": results,
    }
    write_text(out_dir / "report.json", json.dumps(report, indent=2) + "\n")