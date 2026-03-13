from __future__ import annotations

from pathlib import Path

from ir_collector.utils.fs import write_text
from ir_collector.utils.shell import run
from ir_collector.collectors.base import BaseCollector

    
class SystemCollector(BaseCollector):
    name = "system"

    def collect(self) -> dict:
        cmds = {
            "uname.txt": ["uname", "-a"],
            "uptime.txt": ["uptime"],
            "date.txt": ["date", "-Iseconds"],
            "hostnamectl.txt": ["hostnamectl"],
        }

        for fname, cmd in cmds.items():
            res = run(cmd, timeout_s=15)
            write_text(self.base / fname, res.stdout if res.stdout else res.stderr)
            self._add_file(self.base / fname)
            if res.returncode != 0:
                self._add_error(res.cmd, res.stderr, res.returncode)

        osr = Path("/etc/os-release")
        if osr.exists():
            write_text(self.base / "os-release.txt",
                       osr.read_text(encoding="utf-8", errors="replace"))
            self._add_file(self.base / "os-release.txt")

        return self.collected


def collect_system(out_dir: Path) -> dict:
    return SystemCollector(out_dir).collect()