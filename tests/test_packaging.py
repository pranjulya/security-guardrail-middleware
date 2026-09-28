"""Review 02 / H7: packaging metadata that a clean install/build depends on."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

PYPROJECT = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())


def _setuptools_floor() -> tuple[int, ...]:
    for req in PYPROJECT["build-system"]["requires"]:
        match = re.fullmatch(r"setuptools>=(\d+(?:\.\d+)*)", req.replace(" ", ""))
        if match:
            return tuple(int(p) for p in match.group(1).split("."))
    raise AssertionError("setuptools floor missing")


def test_spdx_license_string_has_compatible_setuptools_floor():
    if isinstance(PYPROJECT["project"].get("license"), str):  # PEP 639 form
        assert _setuptools_floor() >= (77,)


def test_spacy_model_is_pinned_by_url_and_hash_not_pypi_name():
    deps = PYPROJECT["project"]["dependencies"]
    model = [d for d in deps if d.replace("_", "-").startswith("en-core-web-lg")]
    assert len(model) == 1
    spec = model[0]
    assert " @ https://github.com/explosion/spacy-models/releases/download/" in spec
    assert re.search(r"#sha256=[0-9a-f]{64}$", spec)


def test_model_version_matches_documented_detector_version():
    from guardrails.pii import PiiRedactor

    spec = next(d for d in PYPROJECT["project"]["dependencies"] if "en-core-web-lg" in d)
    version = re.search(r"en_core_web_lg-(\d+\.\d+\.\d+)-py3", spec).group(1)
    assert f"en_core_web_lg=={version}" in PiiRedactor(entities=[]).detector_version


def test_package_is_discoverable_from_src_layout():
    assert PYPROJECT["tool"]["setuptools"]["packages"]["find"]["where"] == ["src"]


def test_package_is_marked_typed() -> None:
    """PEP 561 marker ships with the package (L9/L10)."""
    import guardrails

    marker = Path(guardrails.__file__).with_name("py.typed")
    assert marker.is_file()
    assert "py.typed" in PYPROJECT["tool"]["setuptools"]["package-data"]["guardrails"]
    assert PYPROJECT["tool"]["mypy"]["strict"] is True


LOCK = Path(__file__).resolve().parents[1] / "requirements-lock.txt"


def _dep_names(reqs: list[str]) -> set[str]:
    return {re.split(r"[\s=<>@\[;]", r, maxsplit=1)[0].lower() for r in reqs}


def test_unused_vulnerable_anonymizer_dropped() -> None:
    """M8: presidio-anonymizer was unused and pinned a vulnerable cryptography."""
    assert "presidio-anonymizer" not in _dep_names(PYPROJECT["project"]["dependencies"])
    src = Path(__file__).resolve().parents[1] / "src"
    assert not any("presidio_anonymizer" in p.read_text() for p in src.rglob("*.py"))


def test_pytest_pinned_past_advisory() -> None:
    """M8: pytest >= 9.0.3 (CVE-2025-71176)."""
    (pin,) = [r for r in PYPROJECT["project"]["optional-dependencies"]["test"] if "pytest" in r]
    version = tuple(int(x) for x in pin.split("==")[1].split("#")[0].strip().split("."))
    assert version >= (9, 0, 3)


def test_lock_file_pins_everything_with_hashes() -> None:
    """M8: transitive dependencies are pinned with sha256 hashes."""
    text = LOCK.read_text()
    entries = re.findall(r"^([A-Za-z0-9_.\-]+)(?:==| @ )", text, flags=re.M)
    assert len(entries) >= 40
    blocks = re.split(r"\n(?=[A-Za-z0-9])", text.split("\n", 2)[2])
    for block in blocks:
        if block.strip() and not block.startswith("#"):
            assert "--hash=sha256:" in block, block.splitlines()[0]
    names = {e.lower() for e in entries}
    assert "presidio-anonymizer" not in names
    assert "cryptography" not in names
    for dep in ("presidio-analyzer==2.2.360", "spacy==3.8.16", "pytest==9.1.1"):
        assert re.search(rf"^{re.escape(dep)} ", text, flags=re.M), dep


ROOT = Path(__file__).resolve().parents[1]


def test_license_file_matches_declared_mit_license() -> None:
    """L10: the MIT license declared in pyproject ships as a LICENSE file."""
    assert PYPROJECT["project"]["license"] == "MIT"
    assert PYPROJECT["project"]["license-files"] == ["LICENSE"]
    text = (ROOT / "LICENSE").read_text()
    assert text.startswith("MIT License")
    assert "Permission is hereby granted, free of charge" in text


def test_governance_files_present() -> None:
    """L10: disclosure policy, code owners and contribution guide exist."""
    security = (ROOT / "SECURITY.md").read_text()
    assert "Reporting a vulnerability" in security
    assert "do not open a public issue" in security
    owners = (ROOT / ".github" / "CODEOWNERS").read_text()
    assert re.search(r"^\*\s+@pranjulya$", owners, re.MULTILINE)
    assert "Synthetic data only" in (ROOT / "CONTRIBUTING.md").read_text()


def test_built_wheel_contains_license_and_type_marker(tmp_path) -> None:
    """The wheel carries LICENSE (PEP 639) and py.typed (PEP 561)."""
    import subprocess
    import sys
    import zipfile

    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "-q", "-w", str(tmp_path), str(ROOT)],
        check=True,
        capture_output=True,
        timeout=300,
    )
    wheel = next(tmp_path.glob("security_guardrail_middleware-*.whl"))
    names = zipfile.ZipFile(wheel).namelist()
    assert any(n.endswith(".dist-info/licenses/LICENSE") for n in names), names
    assert "guardrails/py.typed" in names
