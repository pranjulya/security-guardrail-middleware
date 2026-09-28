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
