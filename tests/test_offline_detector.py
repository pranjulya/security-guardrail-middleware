"""Review 02 / L2: no runtime network egress or disk cache from tldextract."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

from guardrails import pii


def test_engine_uses_restricted_offline_registry() -> None:
    engine = pii._get_engine()
    names = sorted(type(r).__name__ for r in engine.registry.recognizers)
    assert "OfflineEmailRecognizer" in names
    assert "EmailRecognizer" not in names
    entities = {e for r in engine.registry.recognizers for e in r.supported_entities}
    assert {"EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "PERSON"} <= entities
    # No country-specific / unrelated recognizers are loaded any more.
    assert not [n for n in names if n.startswith(("It", "Es", "Pl", "Au", "In", "Sg"))]


def test_redaction_makes_no_network_calls_and_writes_no_cache(tmp_path: Path) -> None:
    code = textwrap.dedent(
        """
        import socket
        attempts = []
        def deny(*args, **kwargs):
            attempts.append(args)
            raise OSError("network disabled in test")
        socket.socket.connect = deny
        socket.create_connection = deny
        from guardrails.pii import PiiRedactor
        from guardrails.policy import DEFAULT_POLICY, load_policy
        P = load_policy(DEFAULT_POLICY)
        r = PiiRedactor(entities=P.entities, thresholds=dict(P.thresholds))
        out, action, _ = r.redact("mail jane.doe@example.co.uk now")
        print(action.value, out, len(attempts))
        """
    )
    env = {**os.environ, "HOME": str(tmp_path), "XDG_CACHE_HOME": str(tmp_path / "cache")}
    env.pop("TLDEXTRACT_CACHE", None)
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
        timeout=180,
        env=env,
    )
    action, out, attempts = result.stdout.split()[0], result.stdout, result.stdout.split()[-1]
    assert action == "REDACT"
    assert "[EMAIL_ADDRESS]" in out
    assert attempts == "0"
    assert not list(tmp_path.rglob("*tldextract*"))
