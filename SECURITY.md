# Security policy

`security-guardrail-middleware` is a pre-1.0 research/portfolio project. It is
not yet approved for production use (see `docs/` for open items and
`docs/reviews/` for the security reviews).

## Supported versions

Only the latest commit on the default branch receives fixes. There are no
released versions yet (`version = "0.0.0"`).

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

- Preferred: use GitHub's private vulnerability reporting on this repository
  ("Security" tab → "Report a vulnerability"), if it is enabled.
- Otherwise: contact the maintainer, @pranjulya, through GitHub and ask for a
  private channel; do not include exploit details in the first message.

Please include the affected commit, a minimal reproduction using **synthetic
data only** (never real PII or credentials), the impact you observed, and any
suggested fix.

What to expect: acknowledgement within 7 days, an initial assessment within 14
days, and credit in the fix commit/PR unless you ask otherwise. This is a
best-effort, single-maintainer project; there is no bug bounty.

## Scope

In scope: the library under `src/guardrails/` (inspection pipeline, PII
redaction, injection rules, tool authorization, audit events), the optional
HTTP adapter, and the example/evaluation tooling in this repository.

Out of scope: vulnerabilities in third-party dependencies (report upstream;
we track them via pip-audit and Dependabot), denial of service that requires
more than the documented loopback deployment, and findings that depend on
running with real PII contrary to the documentation.

## Handling

Security fixes are developed on a private branch when possible, reviewed,
covered by a regression test, and described in `docs/reviews/`. CI runs
tests, ruff, mypy, bandit, pip-audit and gitleaks on every change.
