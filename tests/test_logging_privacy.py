"""Review 02 / M2: host DEBUG logging never captures analysed text."""

from __future__ import annotations

import logging
import subprocess
import sys

from guardrails.pii import PiiRedactor
from guardrails.policy import DEFAULT_POLICY, load_policy

POLICY = load_policy(DEFAULT_POLICY)
CANARY = "synthcanary"


def test_presidio_debug_records_do_not_reach_host_handlers(caplog) -> None:
    redactor = PiiRedactor(entities=POLICY.entities, thresholds=dict(POLICY.thresholds))
    with caplog.at_level(logging.DEBUG):
        redactor.redact(f"{CANARY} jane.doe@example.com called")
    assert CANARY not in caplog.text
    assert "jane.doe@example.com" not in caplog.text
    assert not [
        r for r in caplog.records if r.name.startswith("presidio") and r.levelno < logging.WARNING
    ]


def test_basic_config_debug_after_import_is_safe() -> None:
    """Mirror the PoC: a host calls logging.basicConfig(DEBUG) in a fresh process."""
    code = (
        "import io, logging\n"
        "buf = io.StringIO()\n"
        "logging.basicConfig(level=logging.DEBUG, stream=buf, force=True)\n"
        "from guardrails.pii import PiiRedactor\n"
        "from guardrails.policy import DEFAULT_POLICY, load_policy\n"
        "P = load_policy(DEFAULT_POLICY)\n"
        "PiiRedactor(entities=P.entities, thresholds=dict(P.thresholds))"
        f".redact('{CANARY} jane.doe@example.com called')\n"
        "print(repr(buf.getvalue()))\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, timeout=120
    ).stdout
    assert CANARY not in out
    assert "jane.doe@example.com" not in out


def test_warnings_still_propagate() -> None:
    logger = logging.getLogger("presidio-analyzer")
    assert logger.getEffectiveLevel() == logging.WARNING
    record = logger.makeRecord("presidio-analyzer", logging.WARNING, __file__, 1, "w", (), None)
    assert all(f.filter(record) for f in logger.filters)
