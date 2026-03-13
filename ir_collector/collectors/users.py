from __future__ import annotations

from pathlib import Path

from ir_collector.collectors.base import BaseCollector
from ir_collector.utils.fs import write_text
from ir_collector.utils.shell import run


class UsersCollector(BaseCollector):
    name = "users"

    def _read_file(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return f"[ERROR] Could not read {path}: {e}"

    def collect(self) -> dict:
        for path, fname in [
            (Path("/etc/passwd"),  "passwd.txt"),
            (Path("/etc/group"),   "group.txt"),
            (Path("/etc/shadow"),  "shadow.txt"),
            (Path("/etc/sudoers"), "sudoers.txt"),
        ]:
            if path.exists():
                write_text(self.base / fname, self._read_file(path))
                self._add_file(self.base / fname)

        sudoers_d = Path("/etc/sudoers.d")
        if sudoers_d.exists() and sudoers_d.is_dir():
            listing = "\n".join(sorted(p.name for p in sudoers_d.iterdir() if p.is_file()))
            write_text(self.base / "sudoers_d_listing.txt", listing + "\n")
            self._add_file(self.base / "sudoers_d_listing.txt")

        cmds = {
            "last_50.txt":    ["last", "-n", "50"],
            "who.txt":        ["who"],
            "id_current.txt": ["id"],
            "sudo_group.txt": ["getent", "group", "sudo"],
        }

        for fname, cmd in cmds.items():
            res = run(cmd, timeout_s=20)
            write_text(self.base / fname, res.stdout if res.stdout else res.stderr)
            self._add_file(self.base / fname)
            if res.returncode != 0:
                self._add_error(res.cmd, res.stderr, res.returncode)

        return self.collected


def collect_users(out_dir: Path) -> dict:
    return UsersCollector(out_dir).collect()