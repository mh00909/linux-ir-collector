from __future__ import annotations

from pathlib import Path

from ir_collector.utils.fs import write_text
from ir_collector.utils.shell import run


def collect_processes(out_dir: Path) -> dict:
    base = out_dir / "processes"
    collected = {"files": [], "errors": []}

    cmds = {
        "ps_auxww.txt": ["ps", "auxww"],
        "top_once.txt": ["top", "-b", "-n", "1"],
        "systemctl_failed.txt": ["systemctl", "--failed", "--no-pager"],
    }

    for fname, cmd in cmds.items():
        res = run(cmd, timeout_s=20)
        write_text(base / fname, res.stdout if res.stdout else res.stderr)
        collected["files"].append(str((base / fname).relative_to(out_dir)))
        if res.returncode != 0:
            collected["errors"].append({"cmd": res.cmd, "stderr": res.stderr, "rc": res.returncode})

    return collected
