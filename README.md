# Security Guardrail Middleware

A small, auditable Python guardrail pipeline that aims to reduce prompt-injection risk, redact explicitly supported PII, and check input and output before they cross an application boundary.

> **Status: planning only.** There is no guardrail code in this repository yet. It contains the product spec, architecture, ADRs, phase plans, and learning notes. The phase 00 environment baseline is recorded in [docs/environment.md](docs/environment.md) and is pending threat-review acceptance. No security-effectiveness or performance result has been measured. See [Implementation.md](Implementation.md) for the current phase status.

## Planned design

- **In-process library** that evaluates bounded text at four named boundaries: `user_input`, `retrieved_content`, `tool_output` and `model_output`.
- **PII redaction** with Presidio for English text only. The configured entities are `EMAIL_ADDRESS`, `PHONE_NUMBER`, `CREDIT_CARD` and `PERSON`; detected spans are replaced with category labels.
- **Prompt-injection risk rules**, plus a host-owned tool authorization layer that works independently of the model. All tool proposals are treated as untrusted.
- **Buffered output**: responses are held until output evaluation completes, so nothing streams to the user before the checks finish.
- **Fail closed**: if a mandatory detector fails, the policy is invalid, the declared language is unsupported, or the deadline runs out, the result is `BLOCK` with no text.
- **Size limits**: each boundary text is limited to 16 KiB and each request to 64 KiB in aggregate. Oversize input is rejected, not truncated.
- **Content-free telemetry**: no raw content, detected values or content hashes appear in logs or events.
- **Optional HTTP adapter** (phase 06), only after the library passes evaluation.

Out of scope for V1 includes non-English text, country-specific identifiers, images/PDFs, arbitrary tool execution, real PII, and any claim of universal injection prevention.

## Phases

| Phase | Scope |
|---|---|
| 00 | Environment, threat model, fixtures |
| 01 | Policy, validated envelope, decisions |
| 02 | Bounded PII detection/redaction |
| 03 | Injection risk rules and tool authorization |
| 04 | Full buffered input-to-output flow |
| 05 | Held-out evaluation and release package |
| 06 | Optional HTTP service |

Detailed plans are in [implementation/](implementation/README.md).

## Environment (phase 00 baseline)

Python 3.12 is required, along with the pinned versions from [docs/environment.md](docs/environment.md):

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install presidio-analyzer==2.2.360 presidio-anonymizer==2.2.360 spacy==3.8.16 pytest==8.4.2
python -m spacy download en_core_web_lg
```

No GPU is required. Test fixtures must be synthetic only; see [tests/fixtures/README.md](tests/fixtures/README.md).

## Project structure

```
Implementation.md     # master plan: scope, defaults, phase status, review gates
pyproject.toml        # package metadata and pinned dependencies
docs/
  product/PRD.md      # requirements and proposed acceptance targets
  architecture/       # HLD, LLD and ADRs (proposed)
  evaluation/         # evaluation strategy
  operations/         # observability, security, production scenarios
  environment.md      # phase 00 environment baseline
  threat-review.md
implementation/       # per-phase plans (00-06)
Learning/             # concept notes, scenarios, interview Q&A
tests/fixtures/       # synthetic fixture conventions
```

## Documentation

- [PRD](docs/product/PRD.md), [HLD](docs/architecture/HLD.md), [LLD](docs/architecture/LLD.md), [ADRs](docs/architecture/ADRs/README.md)
- [Learning guide](Learning/README.md)

## License

Released under the MIT License. See [`LICENSE`](LICENSE).
