"""Review 02 / M9, L13: CI exists, is least-privilege, pinned, and covers the
required checks; dependency locks are hashed and auditable."""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github" / "workflows" / "ci.yml"


def _workflow() -> dict:
    return yaml.safe_load(CI.read_text())


def test_workflow_is_read_only_and_actions_are_sha_pinned():
    wf = _workflow()
    assert wf["permissions"] == {"contents": "read"}
    uses = re.findall(r"uses:\s*(\S+)", CI.read_text())
    assert uses
    for ref in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), ref
    for job in wf["jobs"].values():
        for step in job["steps"]:
            if "uses" in step and step["uses"].startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False


def test_workflow_runs_every_required_check():
    text = CI.read_text()
    for needle in (
        "--require-hashes --no-deps -r requirements-lock.txt",
        "pytest",
        "ruff check .",
        "ruff format --check .",
        "mypy",
        "bandit",
        "pip-audit --strict",
        "gitleaks git",
        "sha256sum -c",
    ):
        assert needle in text, needle


def test_dependabot_covers_pip_and_actions():
    cfg = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())
    ecosystems = {u["package-ecosystem"] for u in cfg["updates"]}
    assert ecosystems == {"pip", "github-actions"}


def test_locks_are_fully_hashed():
    for name in ("requirements-lock.txt", "requirements-dev-lock.txt"):
        text = (ROOT / name).read_text()
        entries = [line for line in text.splitlines() if line and not line[0].isspace()]
        entries = [e for e in entries if not e.startswith("#")]
        assert entries, name
        blocks = re.split(r"\n(?=\S)", text)
        for block in blocks:
            if block.startswith("#") or not block.strip():
                continue
            assert "--hash=sha256:" in block, block.splitlines()[0]
    dev = (ROOT / "requirements-dev-lock.txt").read_text()
    for tool in ("ruff==", "mypy==", "bandit==", "pip-audit==", "pytest=="):
        assert tool in dev, tool
    assert "cryptography==" not in (ROOT / "requirements-lock.txt").read_text()


def _load_strip():
    path = ROOT / "tools" / "strip_url_requirements.py"
    spec = importlib.util.spec_from_file_location("strip_url_requirements", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_strip_url_requirements_drops_only_url_entries():
    mod = _load_strip()
    text = (
        "# header\n"
        "aaa==1.0 \\\n    --hash=sha256:00\n    # via x\n"
        "model @ https://example.invalid/m.whl#sha256=ff \\\n    --hash=sha256:ff\n"
        "zzz==2.0 \\\n    --hash=sha256:11\n"
    )
    out, dropped = mod.strip_url_requirements(text)
    assert dropped == ["model"]
    assert "model @" not in out and "sha256:ff" not in out
    assert "aaa==1.0" in out and "zzz==2.0" in out and "sha256:11" in out
