from __future__ import annotations

from dataclasses import dataclass
import subprocess
from typing import Iterable, Optional


@dataclass
class CmdResult:
    cmd: list[str]
    stdout: str
    stderr: str
    returncode: int


def run(cmd: Iterable[str], timeout_s: int = 15) -> CmdResult:
    """
    Run a command safely and return captured output.
    No shell=True.
    """
    cmd_list = list(cmd)
    try:
        p = subprocess.run(
            cmd_list,
            text=True,
            capture_output=True,
            timeout=timeout_s,
            check=False,
        )
        return CmdResult(cmd_list, p.stdout, p.stderr, p.returncode)
    except subprocess.TimeoutExpired as e:
        return CmdResult(cmd_list, e.stdout or "", (e.stderr or "") + "\n[TIMEOUT]", 124)
    except FileNotFoundError:
        return CmdResult(cmd_list, "", "Command not found", 127)
    except Exception as e:
        return CmdResult(cmd_list, "", f"Unhandled error: {e}", 1)
