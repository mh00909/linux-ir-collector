from __future__ import annotations

import os
from pathlib import Path
from typing import List

from ir_collector.collectors.base import BaseCollector
from ir_collector.utils.fs import write_text
from ir_collector.utils.shell import run


SUSPICIOUS_KEYWORDS = ["curl", "wget", "bash", "sh ", "nc ", "python",
                       "/tmp", "/var/tmp", "base64"]

CRON_FILES = [Path("/etc/crontab")]
CRON_DIRS = [
    Path("/etc/cron.d"), Path("/etc/cron.daily"), Path("/etc/cron.hourly"),
    Path("/etc/cron.weekly"), Path("/etc/cron.monthly"),
]


class PersistenceCollector(BaseCollector):
    name = "persistence"

    def _read_file(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return f"[ERROR] Could not read {path}: {e}\n"

    def _list_dir(self, path: Path) -> str:
        try:
            files = sorted(p.name for p in path.iterdir() if p.is_file())
            return "\n".join(files) + ("\n" if files else "")
        except Exception as e:
            return f"[ERROR] Could not list {path}: {e}\n"

    def _suspicious_lines(self, text: str) -> List[str]:
        hits = []
        for line in text.splitlines():
            if any(kw in line.lower() for kw in SUSPICIOUS_KEYWORDS):
                hits.append(line.strip())
        return hits

    def _collect_cron(self) -> None:
        for p in CRON_FILES:
            if p.exists():
                out = self.base / "cron" / p.name
                write_text(out, self._read_file(p))
                self._add_file(out)

        for d in CRON_DIRS:
            if d.exists() and d.is_dir():
                out = self.base / "cron" / f"{d.name}_listing.txt"
                write_text(out, self._list_dir(d))
                self._add_file(out)

        res = run(["crontab", "-l"], timeout_s=15)
        out = self.base / "cron" / "crontab_current_user.txt"
        write_text(out, res.stdout if res.stdout else res.stderr)
        self._add_file(out)
        if res.returncode != 0:
            self._add_error(res.cmd, res.stderr, res.returncode)

        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            res2 = run(["crontab", "-u", sudo_user, "-l"], timeout_s=15)
            out2 = self.base / "cron" / f"crontab_{sudo_user}.txt"
            write_text(out2, res2.stdout if res2.stdout else res2.stderr)
            self._add_file(out2)
            if res2.returncode != 0:
                self._add_error(res2.cmd, res2.stderr, res2.returncode)

    def _collect_systemd(self) -> None:
        cmds = {
            "systemd_list_timers.txt": ["systemctl", "list-timers", "--all", "--no-pager"],
            "systemd_unit_files_services.txt": ["systemctl", "list-unit-files",
                                                "--type=service", "--no-pager"],
            "systemd_unit_files_timers.txt": ["systemctl", "list-unit-files",
                                              "--type=timer", "--no-pager"],
        }
        for fname, cmd in cmds.items():
            res = run(cmd, timeout_s=25)
            out = self.base / "systemd" / fname
            write_text(out, res.stdout if res.stdout else res.stderr)
            self._add_file(out)
            if res.returncode != 0:
                self._add_error(res.cmd, res.stderr, res.returncode)

    def _collect_autostart(self) -> None:
        for label, path in [
            ("etc_xdg_autostart", Path("/etc/xdg/autostart")),
            ("user_autostart", Path.home() / ".config" / "autostart"),
        ]:
            if path.exists() and path.is_dir():
                out = self.base / "autostart" / f"{label}_listing.txt"
                write_text(out, self._list_dir(path))
                self._add_file(out)

    def _build_findings(self) -> dict:
        findings: dict = {}

        services_txt = self.base / "systemd" / "systemd_unit_files_services.txt"
        if services_txt.exists():
            text = services_txt.read_text(encoding="utf-8", errors="replace")
            findings["enabled_services_count"] = sum(
                1 for l in text.splitlines()
                if l.strip().endswith(" enabled") and ".service" in l
            )

        timers_txt = self.base / "systemd" / "systemd_list_timers.txt"
        if timers_txt.exists():
            text = timers_txt.read_text(encoding="utf-8", errors="replace")
            findings["timers_listed_count"] = sum(1 for l in text.splitlines() if ".timer" in l)

        findings["cron_dirs_present"] = [d.name for d in CRON_DIRS if d.exists()]

        for label, path in [
            ("autostart_entries_system", Path("/etc/xdg/autostart")),
            ("autostart_entries_user", Path.home() / ".config" / "autostart"),
        ]:
            try:
                findings[label] = len(list(path.iterdir())) if path.exists() else 0
            except OSError:
                findings[label] = -1

        cron_dir = self.base / "cron"
        suspicious_cron: list = []
        if cron_dir.exists():
            for f in cron_dir.glob("*.txt"):
                suspicious_cron.extend(
                    self._suspicious_lines(f.read_text(encoding="utf-8", errors="replace"))
                )
        findings["suspicious_cron_entries"] = suspicious_cron[:20]

        suspicious_systemd: list = []
        if services_txt.exists():
            suspicious_systemd.extend(
                self._suspicious_lines(services_txt.read_text(encoding="utf-8", errors="replace"))
            )
        findings["suspicious_systemd_entries"] = suspicious_systemd[:20]

        return findings

    def collect(self) -> dict:
        self._collect_cron()
        self._collect_systemd()
        self._collect_autostart()
        self.collected["findings"] = self._build_findings()
        return self.collected


def collect_persistence(out_dir: Path) -> dict:
    return PersistenceCollector(out_dir).collect()