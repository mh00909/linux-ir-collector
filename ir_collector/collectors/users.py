from __future__ import annotations

from pathlib import Path

from ir_collector.utils.fs import write_text
from ir_collector.utils.shell import run


def _read_file_best_effort(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return f"[ERROR] Could not read {path}: {e}"


def collect_users(out_dir: Path) -> dict:
    base = out_dir / "users"
    collected = {"files": [], "errors": []}

    # Copies of key account files
    passwd = Path("/etc/passwd")
    group = Path("/etc/group")
    shadow = Path("/etc/shadow")  # requires sudo; still best-effort

    if passwd.exists():
        write_text(base / "passwd.txt", _read_file_best_effort(passwd))
        collected["files"].append(str((base / "passwd.txt").relative_to(out_dir)))

    if group.exists():
        write_text(base / "group.txt", _read_file_best_effort(group))
        collected["files"].append(str((base / "group.txt").relative_to(out_dir)))

    if shadow.exists():
        # do NOT parse; just snapshot for IR (may fail without sudo)
        write_text(base / "shadow.txt", _read_file_best_effort(shadow))
        collected["files"].append(str((base / "shadow.txt").relative_to(out_dir)))

    # Sudoers
    sudoers = Path("/etc/sudoers")
    if sudoers.exists():
        write_text(base / "sudoers.txt", _read_file_best_effort(sudoers))
        collected["files"].append(str((base / "sudoers.txt").relative_to(out_dir)))

    sudoers_d = Path("/etc/sudoers.d")
    if sudoers_d.exists() and sudoers_d.is_dir():
        listing = "\n".join(sorted([p.name for p in sudoers_d.iterdir() if p.is_file()]))
        write_text(base / "sudoers_d_listing.txt", listing + ("\n" if listing else ""))
        collected["files"].append(str((base / "sudoers_d_listing.txt").relative_to(out_dir)))

    # Recent logins
    cmds = {
        "last_50.txt": ["last", "-n", "50"],
        "who.txt": ["who"],
        "id_current.txt": ["id"],
        "sudo_group.txt": ["getent", "group", "sudo"],
    }

    for fname, cmd in cmds.items():
        res = run(cmd, timeout_s=20)
        write_text(base / fname, res.stdout if res.stdout else res.stderr)
        collected["files"].append(str((base / fname).relative_to(out_dir)))
        if res.returncode != 0:
            collected["errors"].append({"cmd": res.cmd, "stderr": res.stderr, "rc": res.returncode})

    return collected
