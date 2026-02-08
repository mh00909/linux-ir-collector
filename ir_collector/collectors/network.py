from __future__ import annotations

from pathlib import Path

from ir_collector.utils.fs import write_text
from ir_collector.utils.shell import run


def collect_network(out_dir: Path) -> dict:
    base = out_dir / "network"
    collected = {"files": [], "errors": []}

    cmds = {
        "ip_addr.txt": ["ip", "a"],
        "ip_route.txt": ["ip", "route"],
        "ss_listening.txt": ["ss", "-tulnp"],
    }

    for fname, cmd in cmds.items():
        res = run(cmd, timeout_s=20)
        write_text(base / fname, res.stdout if res.stdout else res.stderr)
        collected["files"].append(str((base / fname).relative_to(out_dir)))
        if res.returncode != 0:
            collected["errors"].append({"cmd": res.cmd, "stderr": res.stderr, "rc": res.returncode})

    # DNS info (best effort)
    resolv = Path("/etc/resolv.conf")
    if resolv.exists():
        write_text(base / "resolv.conf.txt", resolv.read_text(encoding="utf-8", errors="replace"))
        collected["files"].append(str((base / "resolv.conf.txt").relative_to(out_dir)))

    return collected
