# Threat model and security operations

Assets: user text, model-facing context, response content, policy integrity, tool authority and audit privacy. Adversaries may control user text, retrieved documents and tool-result text, but do not control the trusted host process. A compromised host/dependency can bypass this library and is outside the library's enforcement claim.

| Threat | Control | Residual risk / verification |
|---|---|---|
| Direct instruction override | Bounded rule detection and structured host prompt | Novel wording bypass; held-out family tests |
| Indirect instructions in retrieved/tool text | Inspect at both boundaries; keep data separate | Model may still follow text; authorization remains external |
| Unauthorized action | Fixed read-only allowlist, trusted principal, strict arguments | Host implementation mistakes; denial and bypass tests |
| Sensitive output | Buffered PII inspection/redaction | Unrecognized categories/obfuscation can leak; report misses |
| Policy tampering | Reviewed versioned local policy, strict startup validation | Compromised filesystem/host is out of scope |
| Resource exhaustion | UTF-8 byte caps, block count, bounded concurrency/deadline | CPU detector cannot be force-killed by thread timer; no late release, optional phase 06 process isolation for termination |
| Telemetry disclosure | Allowlisted event schema, no bodies/mappings | Third-party defaults may leak; canary inspection |
| Dependency compromise | Pin package/model artifacts (hashed `requirements-lock.txt` / `requirements-dev-lock.txt`, model wheel by URL + sha256), license review, CI `pip-audit --strict` on both locks on every push/PR, weekly Dependabot version PRs, gitleaks secret scan | Pins alone do not establish provenance; the model wheel is not covered by pip-audit/OSV |

Do not place credentials or genuinely confidential instructions in prompts. Redaction is best-effort data minimization within declared coverage, not anonymization proof or legal compliance. All fixtures are synthetic and visibly labeled; avoid real account identifiers even in examples. Disable unneeded network egress in the local demo after dependencies/models are installed.

Incident: stop affected adapter or mark unready, preserve only content-free evidence and version metadata, restore last tested bundle, rerun canary and failure tests, then resume. If sensitive content was exposed, follow the deploying organization's incident process; this demo supplies no legal notification policy. A false-positive spike is investigated without switching to fail-open.
