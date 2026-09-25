# Synthetic fixtures

All values synthetic. Never add real PII, production logs, or account identifiers.

## Conventions

- Text markers use `SYNTH_` prefix (e.g. `SYNTH_EMAIL_1`) so a privacy canary grep finds leaks.
- Each record: `fixture_id`, `boundary` (user_input | retrieved_content | tool_output | model_output), `language` (`en` only), `text`, `entity_spans` (original-text offsets), `expected` policy outcome, plus optional `attack_family` / `desired_attack_outcome`.
- Split policy: deduplicate and split by template family before generating variants. Development set (phase 02+ calibration) and held-out set (phase 05) are disjoint; repeated tuning on held-out data requires a fresh split.

## Planned files

- `tests/fixtures/pii-development.jsonl` (phase 02): golden original-text spans per supported entity.
- Phase 05 held-out: >=100 positives per PII category, 120 injection cases, 200 benign cases, 40 enforcement/failure cases. Manifest frozen before held-out execution with model settings, policy version, and file hashes (synthetic artifact hashes permitted).
