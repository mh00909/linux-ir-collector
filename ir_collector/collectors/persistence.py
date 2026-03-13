from __future__ import annotations

import os
from pathlib import Path
from typing import List

from ir_collector.utils.fs import write_text
from ir_collector.utils.shell import run


# Helpers
SUSPICIOUS_KEYWORDS = [
    "curl",
    "wget",
    "bash",
    "sh ",
    "nc ",
    "python",
    "/tmp",
    "/var/tmp",
    "base64",
]


def _read_file_best_effort(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return f"[ERROR] Could not read {path}: {e}\n"


def _list_dir_files(dir_path: Path) -> str:
    try:
        files = [p.name for p in dir_path.iterdir() if p.is_file()]
        return "\n".join(sorted(files)) + ("\n" if files else "")
    except Exception as e:
        return f"[ERROR] Could not list {dir_path}: {e}\n"


def _extract_suspicious_lines(text: str) -> List[str]:
    hits = []
    for line in text.splitlines():
        lower = line.lower()
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in lower:
                hits.append(line.strip())
                break
    return hits


# Main collector

def collect_persistence(out_dir: Path) -> dict:
    base = out_dir / "persistence"
    collected: dict = {"files": [], "errors": [], "findings": {}}

    # CRON
    cron_files = [Path("/etc/crontab")]
    cron_dirs = [
        Path("/etc/cron.d"),
        Path("/etc/cron.daily"),
        Path("/etc/cron.hourly"),
        Path("/etc/cron.weekly"),
        Path("/etc/cron.monthly"),
    ]

    # Save system crontab
    for p in cron_files:
        if p.exists():
            out = base / "cron" / p.name
            write_text(out, _read_file_best_effort(p))
            collected["files"].append(str(out.relative_to(out_dir)))

    # Save cron directory listings
    for d in cron_dirs:
        if d.exists() and d.is_dir():
            out_list = base / "cron" / f"{d.name}_listing.txt"
            write_text(out_list, _list_dir_files(d))
            collected["files"].append(str(out_list.relative_to(out_dir)))

    # Current user crontab
    res = run(["crontab", "-l"], timeout_s=15)
    out = base / "cron" / "crontab_current_user.txt"
    write_text(out, res.stdout if res.stdout else res.stderr)
    collected["files"].append(str(out.relative_to(out_dir)))
    if res.returncode != 0:
        collected["errors"].append(
            {"cmd": res.cmd, "stderr": res.stderr, "rc": res.returncode}
        )

    # (If running via sudo) collect original user
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        res2 = run(["crontab", "-u", sudo_user, "-l"], timeout_s=15)
        out2 = base / "cron" / f"crontab_sudo_user_{sudo_user}.txt"
        write_text(out2, res2.stdout if res2.stdout else res2.stderr)
        collected["files"].append(str(out2.relative_to(out_dir)))
        if res2.returncode != 0:
            collected["errors"].append(
                {"cmd": res2.cmd, "stderr": res2.stderr, "rc": res2.returncode}
            )

    # SYSTEMD
    cmds = {
        "systemd_list_timers.txt": [
            "systemctl",
            "list-timers",
            "--all",
            "--no-pager",
        ],
        "systemd_unit_files_services.txt": [
            "systemctl",
            "list-unit-files",
            "--type=service",
            "--no-pager",
        ],
        "systemd_unit_files_timers.txt": [
            "systemctl",
            "list-unit-files",
            "--type=timer",
            "--no-pager",
        ],
    }

    for fname, cmd in cmds.items():
        resx = run(cmd, timeout_s=25)
        outp = base / "systemd" / fname
        write_text(outp, resx.stdout if resx.stdout else resx.stderr)
        collected["files"].append(str(outp.relative_to(out_dir)))
        if resx.returncode != 0:
            collected["errors"].append(
                {"cmd": resx.cmd, "stderr": resx.stderr, "rc": resx.returncode}
            )

    # AUTOSTART

    sys_autostart = Path("/etc/xdg/autostart")
    user_autostart = Path.home() / ".config" / "autostart"

    if sys_autostart.exists() and sys_autostart.is_dir():
        out_list = base / "autostart" / "etc_xdg_autostart_listing.txt"
        write_text(out_list, _list_dir_files(sys_autostart))
        collected["files"].append(str(out_list.relative_to(out_dir)))

    if user_autostart.exists() and user_autostart.is_dir():
        out_list = base / "autostart" / "user_autostart_listing.txt"
        write_text(out_list, _list_dir_files(user_autostart))
        collected["files"].append(str(out_list.relative_to(out_dir)))

    # FINDINGS
    findings = {}

    # Enabled services count
    services_txt = base / "systemd" / "systemd_unit_files_services.txt"
    if services_txt.exists():
        text = services_txt.read_text(encoding="utf-8", errors="replace")
        enabled = sum(
            1
            for line in text.splitlines()
            if line.strip().endswith(" enabled") and ".service" in line
        )
        findings["enabled_services_count"] = enabled

    # Timers count
    timers_txt = base / "systemd" / "systemd_list_timers.txt"
    if timers_txt.exists():
        text = timers_txt.read_text(encoding="utf-8", errors="replace")
        timers = sum(1 for l in text.splitlines() if ".timer" in l)
        findings["timers_listed_count"] = timers

    # Cron directories present
    findings["cron_dirs_present"] = [
        d.name for d in cron_dirs if d.exists() and d.is_dir()
    ]

    # Autostart counts
    try:
        findings["autostart_entries_system"] = (
            len([p for p in sys_autostart.iterdir() if p.is_file()])
            if sys_autostart.exists()
            else 0
        )
    except OSError:
        findings["autostart_entries_system"] = -1

    try:
        findings["autostart_entries_user"] = (
            len([p for p in user_autostart.iterdir() if p.is_file()])
            if user_autostart.exists()
            else 0
        )
    except OSError:
        findings["autostart_entries_user"] = -1

    # Suspicious heuristics
    suspicious_cron_entries = []
    cron_dir = base / "cron"
    if cron_dir.exists():
        for f in cron_dir.glob("*.txt"):
            text = f.read_text(encoding="utf-8", errors="replace")
            suspicious_cron_entries.extend(_extract_suspicious_lines(text))

    findings["suspicious_cron_entries"] = suspicious_cron_entries[:20]

    suspicious_services = []
    if services_txt.exists():
        text = services_txt.read_text(encoding="utf-8", errors="replace")
        suspicious_services.extend(_extract_suspicious_lines(text))

    findings["suspicious_systemd_entries"] = suspicious_services[:20]

    collected["findings"] = findings
    return collected
