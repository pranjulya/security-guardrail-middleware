# Evaluation strategy

Status: DESIGN_ONLY. All results UNMEASURED. Evaluate detection, enforcement, utility and performance separately.

## Dataset and split

Create synthetic records with fixture_id, boundary, language, text, entity spans, expected policy outcome, attack family and desired attack outcome. Development set: at least 200 mixed cases for threshold selection. Freeze a separate held-out set: ≥100 positive entities for each of four PII categories, 120 injection cases (20 each direct override, indirect retrieval, tool-result instruction, encoding/Unicode, extraction attempt, multi-step persuasion), and 200 benign cases including quotations, names used as ordinary words and security education. Add 40 fixed enforcement/failure cases. Cases may overlap PII and injection labels but denominators must be explicit. Deduplicate and split by template family before generating variants to avoid near-duplicate leakage.

All values synthetic; no copied production logs. Include source/license/provenance for externally inspired cases and write original payload text. Model identity, tokenizer, generation settings and hashes of synthetic fixture files accompany reports. A hash of a synthetic fixture artifact is permitted; hashes of real request content are not.

## Metrics

PII: exact-span entity precision/recall/F1 by category; overlap-tolerant metric reported separately; residual supported-PII leakage after redaction; over-redaction rate and text utility examples. Injection detector: confusion matrix and false-positive rate by family/boundary. End-to-end attack success: whether a predefined forbidden outcome occurred using a pinned real model, compared with no-guardrail baseline. A refusal alone is not success if data already escaped. Use three repeated model trials per case and report variation and confidence intervals; never imply deterministic fixture tests measure model resistance.

Enforcement: 100% of fixed unauthorized-tool, mandatory-error, invalid-input and no-release cases must pass. Performance: warm/cold timings, p50/p95/p99, failures, memory, hardware, versions, input sizes, concurrency 1 and 4. Run ≥200 measured warm calls per size after 20 warmups; report order and raw content-free timing rows. Generation time is separate from middleware overhead.

Targets are in PRD and provisional until owner acceptance. Freeze thresholds before held-out use; repeated tuning on held-out data requires a fresh test split. If no model is available, mark attack prevention UNMEASURED and publish detector metrics only. No paid inference is assumed.

## Planned output and gate

Future reports/evaluation/<run-id>/ contains summary.md, metadata.json, metrics.csv and a synthetic failures table. No reports exist yet. Reviewer checks denominators, failed cases, CI uncertainty, fixture leakage and privacy canary. A single critical enforcement failure blocks release. Report scope limits prominently: English, four entities, finite attack families, selected model and hardware. Export only reviewed synthetic evidence to Project 11.
