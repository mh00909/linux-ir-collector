from __future__ import annotations

from pathlib import Path

from ir_collector.utils.fs import write_text
from ir_collector.utils.shell import run


def collect_system(out_dir: Path) -> dict:
    base = out_dir / "system"
    collected = {"files": [], "errors": []}

    cmds = {
        "uname.txt": ["uname", "-a"],
        "uptime.txt": ["uptime"],
        "date.txt": ["date", "-Iseconds"],
        "hostnamectl.txt": ["hostnamectl"],
    }

    for fname, cmd in cmds.items():
        res = run(cmd)
        write_text(base / fname, res.stdout if res.stdout else res.stderr)
        collected["files"].append(str((base / fname).relative_to(out_dir)))
        if res.returncode != 0:
            collected["errors"].append({"cmd": res.cmd, "stderr": res.stderr, "rc": res.returncode})

    # OS release (file copy as text)
    osr = Path("/etc/os-release")
    if osr.exists():
        write_text(base / "os-release.txt", osr.read_text(encoding="utf-8", errors="replace"))
        collected["files"].append(str((base / "os-release.txt").relative_to(out_dir)))

    return collected
