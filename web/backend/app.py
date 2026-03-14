from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="IR Collector UI")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


REPORTS_ROOT = Path(__file__).parent.parent.parent


def _find_reports() -> list[dict]:
    reports = []
    for p in sorted(REPORTS_ROOT.glob("report_*"), reverse=True):
        json_file = p / "report.json"
        if json_file.exists():
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
                reports.append({
                    "id": p.name,
                    "generated": data.get("generated"),
                    "severity": data.get("results", {}).get("severity", {}).get("level", "UNKNOWN"),
                    "reasons": data.get("results", {}).get("severity", {}).get("reasons", []),
                })
            except Exception:
                continue
    return reports


@app.get("/api/reports")
def list_reports():
    return _find_reports()


@app.get("/api/reports/{report_id}")
def get_report(report_id: str):
    # zabezpieczenie przed path traversal
    safe_id = Path(report_id).name
    json_file = REPORTS_ROOT / safe_id / "report.json"
    if not json_file.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return json.loads(json_file.read_text(encoding="utf-8"))


@app.get("/api/reports/{report_id}/timeline")
def get_timeline(report_id: str):
    safe_id = Path(report_id).name
    timeline_file = REPORTS_ROOT / safe_id / "timeline.txt"
    if not timeline_file.exists():
        raise HTTPException(status_code=404, detail="Timeline not found")
    return {"lines": timeline_file.read_text(encoding="utf-8").splitlines()}