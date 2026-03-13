from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from ir_collector.collectors.base import BaseCollector
from ir_collector.utils.fs import write_text
from ir_collector.utils.shell import run


IPV4_RE = re.compile(
    r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b'
)


class LogsCollector(BaseCollector):
    name = "logs"

    def _tail_lines(self, text: str, n: int) -> str:
        lines = text.splitlines()
        return "\n".join(lines[-n:]) + ("\n" if lines else "")

    def _analyze_failed_password(self, log_text: str) -> dict:
        failed_lines = [l for l in log_text.splitlines() if "Failed password" in l]
        ips = [m.group(1) for l in failed_lines if (m := IPV4_RE.search(l))]
        counts = Counter(ips)
        return {
            "failed_password_count": len(failed_lines),
            "unique_source_ips": len(counts),
            "top_source_ips": [{"ip": ip, "count": c} for ip, c in counts.most_common(10)],
        }

    def _read_log(self, path: Path, max_lines: int) -> str:
        try:
            return self._tail_lines(
                path.read_text(encoding="utf-8", errors="replace"), max_lines
            )
        except OSError as e:
            self._add_error([str(path)], str(e), 1)
            return ""

    def collect(self, max_lines: int = 2000) -> dict:
        log_text = ""
        source = "unavailable"

        auth_log = Path("/var/log/auth.log")
        secure_log = Path("/var/log/secure")

        if auth_log.exists():
            log_text = self._read_log(auth_log, max_lines)
            source = "auth.log"
        elif secure_log.exists():
            log_text = self._read_log(secure_log, max_lines)
            source = "secure"
        else:
            res = run(["journalctl", "_COMM=sshd", "--no-pager", "-n", str(max_lines)],
                      timeout_s=25)
            if res.returncode == 0 and res.stdout.strip():
                log_text = res.stdout
                source = "journald(_COMM=sshd)"
            else:
                source = "journald(fallback)"
                log_text = res.stdout or res.stderr
                self._add_error(res.cmd, res.stderr, res.returncode)

        write_text(self.base / "auth_tail.txt", log_text)
        self._add_file(self.base / "auth_tail.txt")

        findings = self._analyze_failed_password(log_text)
        findings["log_source"] = source
        self.collected["findings"] = findings

        write_text(self.base / "bruteforce_summary.json",
                   json.dumps(findings, indent=2) + "\n")
        self._add_file(self.base / "bruteforce_summary.json")

        return self.collected


def collect_logs(out_dir: Path) -> dict:
    return LogsCollector(out_dir).collect()