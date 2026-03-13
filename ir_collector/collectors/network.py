from __future__ import annotations

from pathlib import Path

from ir_collector.collectors.base import BaseCollector
from ir_collector.utils.fs import write_text
from ir_collector.utils.shell import run


class NetworkCollector(BaseCollector):
    name = "network"

    def collect(self) -> dict:
        cmds = {
            "ip_addr.txt": ["ip", "a"],
            "ip_route.txt": ["ip", "route"],
            "ss_listening.txt": ["ss", "-tulnp"],
        }

        for fname, cmd in cmds.items():
            res = run(cmd, timeout_s=20)
            write_text(self.base / fname, res.stdout if res.stdout else res.stderr)
            self._add_file(self.base / fname)
            if res.returncode != 0:
                self._add_error(res.cmd, res.stderr, res.returncode)

        resolv = Path("/etc/resolv.conf")
        if resolv.exists():
            write_text(self.base / "resolv.conf.txt",
                       resolv.read_text(encoding="utf-8", errors="replace"))
            self._add_file(self.base / "resolv.conf.txt")

        return self.collected


def collect_network(out_dir: Path) -> dict:
    return NetworkCollector(out_dir).collect()