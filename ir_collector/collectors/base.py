from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path


class BaseCollector(ABC):
    name: str = ""

    def __init__(self, out_dir: Path) -> None:
        self.out_dir = out_dir
        self.base = out_dir / self.name
        self.collected: dict = {"files": [], "errors": [], "findings": {}}

    @abstractmethod
    def collect(self) -> dict:
        raise NotImplementedError

    def _add_file(self, path: Path) -> None:
        self.collected["files"].append(str(path.relative_to(self.out_dir)))

    def _add_error(self, cmd: list, stderr: str, rc: int) -> None:
        self.collected["errors"].append({"cmd": cmd, "stderr": stderr, "rc": rc})