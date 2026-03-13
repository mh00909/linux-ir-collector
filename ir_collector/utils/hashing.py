from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def generate_checksums(out_dir: Path) -> Path:
    lines = []
    for path in sorted(out_dir.rglob("*")):
        if path.is_file() and path.name != "checksums.sha256":
            digest = sha256_file(path)
            rel = path.relative_to(out_dir)
            lines.append(f"{digest}  {rel}")

    checksum_file = out_dir / "checksums.sha256"
    checksum_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return checksum_file