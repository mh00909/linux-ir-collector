from __future__ import annotations

from pathlib import Path
from datetime import datetime

from ir_collector.utils.fs import write_text


def write_markdown_report(out_dir: Path, results: dict) -> None:
    now = datetime.now().isoformat(timespec="seconds")

    lines = []
    lines.append("# Linux IR Collector Report")
    lines.append("")
    lines.append(f"- Generated: `{now}`")
    lines.append(f"- Output directory: `{out_dir.resolve()}`")
    lines.append("")
    lines.append("## Collected modules")
    lines.append("")

    for module_name, info in results.items():
        files = info.get("files", [])
        errors = info.get("errors", [])
        lines.append(f"### {module_name}")
        lines.append(f"- Files: {len(files)}")
        if errors:
            lines.append(f"- Errors: {len(errors)} (see details below)")
        else:
            lines.append("- Errors: 0")
        for f in files[:10]:
            lines.append(f"  - `{f}`")
        if len(files) > 10:
            lines.append(f"  - ... ({len(files)-10} more)")
        lines.append("")


    # Findings
    lines.append("## Findings (basic heuristics)")
    lines.append("")

    logs_info = results.get("logs", {})
    findings = logs_info.get("findings", {}) or {}

    if findings:
        lines.append(f"- SSH log source: `{findings.get('log_source', 'unknown')}`")
        lines.append(f"- `Failed password` count: **{findings.get('failed_password_count', 0)}**")
        lines.append(f"- Unique source IPs: **{findings.get('unique_source_ips', 0)}**")
        lines.append("")

        top = findings.get("top_source_ips", []) or []
        if top:
            lines.append("### Top source IPs")
            lines.append("")
            lines.append("| IP | Count |")
            lines.append("|---|---:|")
            for item in top:
                ip = item.get("ip", "unknown")
                count = item.get("count", 0)
                lines.append(f"| `{ip}` | {count} |")
            lines.append("")
        else:
            lines.append("No IP addresses extracted from `Failed password` lines.")
            lines.append("")
    else:
        lines.append("No heuristic findings available (no logs collected or parsing failed).")
        lines.append("")

    lines.append("## Persistence (summary)")
    lines.append("")

    pers_info = results.get("persistence", {})
    pers_find = pers_info.get("findings", {}) or {}

    if pers_find:
        lines.append(f"- Enabled services (unit-files): **{pers_find.get('enabled_services_count', 0)}**")
        lines.append(f"- Timers listed: **{pers_find.get('timers_listed_count', 0)}**")
        cron_dirs = pers_find.get("cron_dirs_present", []) or []
        if cron_dirs:
            lines.append(f"- Cron dirs present: `{', '.join(cron_dirs)}`")
        else:
            lines.append("- Cron dirs present: (none detected)")
        lines.append(f"- Autostart entries: system **{pers_find.get('autostart_entries_system', 0)}**, user **{pers_find.get('autostart_entries_user', 0)}**")
        lines.append("")
        lines.append("Artifacts saved under `persistence/` (cron/, systemd/, autostart/).")
        lines.append("")
    else:
        lines.append("No persistence findings available.")
        lines.append("")

    severity = results.get("severity")
    if severity:
        lines.append("## Overall Risk Assessment")
        lines.append("")
        lines.append(f"**Risk Level:** {severity['level']}**")
        lines.append("")
        lines.append("### Reasons:")
        lines.append("")
        for r in severity["reasons"]:
            lines.append(f"- {r}")
        lines.append("")


    lines.append("## Errors (if any)")
    lines.append("")
    any_err = False
    for module_name, info in results.items():
        for e in info.get("errors", []):
            any_err = True
            lines.append(f"- **{module_name}** cmd=`{' '.join(e['cmd'])}` rc=`{e['rc']}`")
            if e.get("stderr"):
                lines.append(f"  - stderr: `{e['stderr'].strip()[:200]}`")
    if not any_err:
        lines.append("No errors reported.")
    lines.append("")

    write_text(out_dir / "report.md", "\n".join(lines))
