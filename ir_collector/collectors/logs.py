from __future__ import annotations

from collections import Counter
import json
import re
from pathlib import Path

from ir_collector.utils.fs import write_text
from ir_collector.utils.shell import run


IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _tail_lines(text: str, n: int) -> str:
    lines = text.splitlines()
    return "\n".join(lines[-n:]) + ("\n" if lines else "")


def _analyze_failed_password(log_text: str) -> dict:
    """
    Very lightweight SSH brute-force heuristic:
    counts 'Failed password' occurrences and extracts IPs from those lines.
    """
    failed_lines = []
    for line in log_text.splitlines():
        if "Failed password" in line:
            failed_lines.append(line)

    ips = []
    for line in failed_lines:
        m = IPV4_RE.search(line)
        if m:
            ips.append(m.group(1))

    counts = Counter(ips)
    top = [{"ip": ip, "count": c} for ip, c in counts.most_common(10)]

    return {
        "failed_password_count": len(failed_lines),
        "unique_source_ips": len(counts),
        "top_source_ips": top,
    }


def collect_logs(out_dir: Path, max_lines: int = 2000) -> dict:
    base = out_dir / "logs"
    collected = {"files": [], "errors": [], "findings": {}}

    log_text = ""

    # Prefer /var/log/auth.log (Debian/Ubuntu)
    auth_log = Path("/var/log/auth.log")
    secure_log = Path("/var/log/secure")  # RHEL/CentOS

    if auth_log.exists():
        log_text = auth_log.read_text(encoding="utf-8", errors="replace")
        log_text = _tail_lines(log_text, max_lines)
        source = "auth.log"
    elif secure_log.exists():
        log_text = secure_log.read_text(encoding="utf-8", errors="replace")
        log_text = _tail_lines(log_text, max_lines)
        source = "secure"
    else:
        # Fallback to journald (best effort)
        # Try sshd logs (works on many distros)
        res = run(["journalctl", "_COMM=sshd", "--no-pager", "-n", str(max_lines)], timeout_s=25)
        if res.returncode == 0 and res.stdout.strip():
            log_text = res.stdout
            source = "journald(_COMM=sshd)"
        else:
            # last fallback: auth facility may be named differently; store error
            source = "journald(fallback)"
            log_text = res.stdout if res.stdout else res.stderr
            collected["errors"].append({"cmd": res.cmd, "stderr": res.stderr, "rc": res.returncode})

    write_text(base / "auth_tail.txt", log_text)
    collected["files"].append(str((base / "auth_tail.txt").relative_to(out_dir)))

    findings = _analyze_failed_password(log_text)
    findings["log_source"] = source
    collected["findings"] = findings

    write_text(base / "bruteforce_summary.json", json.dumps(findings, indent=2) + "\n")
    collected["files"].append(str((base / "bruteforce_summary.json").relative_to(out_dir)))

    return collected
