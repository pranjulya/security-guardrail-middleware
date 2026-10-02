"""Review 02 / L11: no personal absolute paths or host names in tracked files."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PERSONAL = re.compile(
    r"/Users/[A-Za-z0-9._-]+/|/home/(?!runner/)[A-Za-z0-9._-]+/|[A-Za-z0-9-]+\.local\b"
)
ALLOWED_SUFFIXES = {".py", ".md", ".toml", ".txt", ".json", ".jsonl", ".yml", ".yaml", ".csv", ""}


def _tracked_files() -> list[Path]:
    try:
        out = subprocess.run(
            ["git", "ls-files"],  # noqa: S607 - git from PATH in a test
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    return [ROOT / line for line in out.splitlines() if line]


def test_no_personal_paths_or_hostnames_in_tracked_files():
    offenders = []
    for path in _tracked_files():
        if path.suffix not in ALLOWED_SUFFIXES or not path.is_file():
            continue
        if path.name.startswith("requirements") and path.suffix == ".txt":
            continue  # hashed locks: package names like "*.local" never appear, but skip bulk
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for match in PERSONAL.finditer(text):
            offenders.append(f"{path.relative_to(ROOT)}: {match.group(0)}")
    assert offenders == []
