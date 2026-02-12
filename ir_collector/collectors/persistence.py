from __future__ import annotations

import os
from pathlib import Path

from ir_collector.utils.fs import write_text
from ir_collector.utils.shell import run


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


def collect_persistence(out_dir: Path) -> dict:
    base = out_dir / "persistence"
    collected: dict = {"files": [], "errors": [], "findings": {}}

    cron_files = [
        Path("/etc/crontab"),
    ]
    cron_dirs = [
        Path("/etc/cron.d"),
        Path("/etc/cron.daily"),
        Path("/etc/cron.hourly"),
        Path("/etc/cron.weekly"),
        Path("/etc/cron.monthly"),
    ]

    for p in cron_files:
        if p.exists():
            out = base / "cron" / p.name
            write_text(out, _read_file_best_effort(p))
            collected["files"].append(str(out.relative_to(out_dir)))

    for d in cron_dirs:
        if d.exists() and d.is_dir():
            out_list = base / "cron" / f"{d.name}_listing.txt"
            write_text(out_list, _list_dir_files(d))
            collected["files"].append(str(out_list.relative_to(out_dir)))

    res = run(["crontab", "-l"], timeout_s=15)
    out = base / "cron" / "crontab_current_user.txt"
    write_text(out, res.stdout if res.stdout else res.stderr)
    collected["files"].append(str(out.relative_to(out_dir)))
    if res.returncode != 0:
        collected["errors"].append({"cmd": res.cmd, "stderr": res.stderr, "rc": res.returncode})

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        res2 = run(["crontab", "-u", sudo_user, "-l"], timeout_s=15)
        out2 = base / "cron" / f"crontab_sudo_user_{sudo_user}.txt"
        write_text(out2, res2.stdout if res2.stdout else res2.stderr)
        collected["files"].append(str(out2.relative_to(out_dir)))
        if res2.returncode != 0:
            collected["errors"].append({"cmd": res2.cmd, "stderr": res2.stderr, "rc": res2.returncode})

    cmds = {
        "systemd_list_timers.txt": ["systemctl", "list-timers", "--all", "--no-pager"],
        "systemd_unit_files_services.txt": ["systemctl", "list-unit-files", "--type=service", "--no-pager"],
        "systemd_unit_files_timers.txt": ["systemctl", "list-unit-files", "--type=timer", "--no-pager"],
    }

    for fname, cmd in cmds.items():
        resx = run(cmd, timeout_s=25)
        outp = base / "systemd" / fname
        write_text(outp, resx.stdout if resx.stdout else resx.stderr)
        collected["files"].append(str(outp.relative_to(out_dir)))
        if resx.returncode != 0:
            collected["errors"].append({"cmd": resx.cmd, "stderr": resx.stderr, "rc": resx.returncode})

    sys_autostart = Path("/etc/xdg/autostart")
    if sys_autostart.exists() and sys_autostart.is_dir():
        out_list = base / "autostart" / "etc_xdg_autostart_listing.txt"
        write_text(out_list, _list_dir_files(sys_autostart))
        collected["files"].append(str(out_list.relative_to(out_dir)))

    home = Path.home()
    user_autostart = home / ".config" / "autostart"
    if user_autostart.exists() and user_autostart.is_dir():
        out_list = base / "autostart" / "user_autostart_listing.txt"
        write_text(out_list, _list_dir_files(user_autostart))
        collected["files"].append(str(out_list.relative_to(out_dir)))


    findings = {}

    services_txt = (base / "systemd" / "systemd_unit_files_services.txt")
    if services_txt.exists():
        text = services_txt.read_text(encoding="utf-8", errors="replace")
        enabled = 0
        for line in text.splitlines():
            if line.strip().endswith(" enabled") and ".service" in line:
                enabled += 1
        findings["enabled_services_count"] = enabled

    timers_txt = (base / "systemd" / "systemd_list_timers.txt")
    if timers_txt.exists():
        text = timers_txt.read_text(encoding="utf-8", errors="replace")
        timers = sum(1 for l in text.splitlines() if ".timer" in l)
        findings["timers_listed_count"] = timers

    present_cron_dirs = [d.name for d in cron_dirs if d.exists() and d.is_dir()]
    findings["cron_dirs_present"] = present_cron_dirs

    sys_count = 0
    if sys_autostart.exists() and sys_autostart.is_dir():
        sys_count = len([p for p in sys_autostart.iterdir() if p.is_file()])
    user_count = 0
    if user_autostart.exists() and user_autostart.is_dir():
        user_count = len([p for p in user_autostart.iterdir() if p.is_file()])
    findings["autostart_entries_system"] = sys_count
    findings["autostart_entries_user"] = user_count

    collected["findings"] = findings
    return collected
