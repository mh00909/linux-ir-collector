from __future__ import annotations

from pathlib import Path

from ir_collector.collectors.base import BaseCollector
from ir_collector.utils.fs import write_text
from ir_collector.utils.shell import run


class ProcessesCollector(BaseCollector):
    name = "processes"

    def collect(self) -> dict:
        cmds = {
            "ps_auxww.txt": ["ps", "auxww"],
            "top_once.txt": ["top", "-b", "-n", "1"],
            "systemctl_failed.txt": ["systemctl", "--failed", "--no-pager"],
        }

        for fname, cmd in cmds.items():
            res = run(cmd, timeout_s=20)
            write_text(self.base / fname, res.stdout if res.stdout else res.stderr)
            self._add_file(self.base / fname)
            if res.returncode != 0:
                self._add_error(res.cmd, res.stderr, res.returncode)

        return self.collected


def collect_processes(out_dir: Path) -> dict:
    return ProcessesCollector(out_dir).collect()