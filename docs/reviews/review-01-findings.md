# Review 01 findings (post-phase-05 code review)

Date: 2026-09-25. Scope: phases 01–05 implementation. Status: all critical findings FIXED on branch `review-01-fixes`; verified by repro and regression.

## Findings and resolution

| ID | Severity | Finding | Evidence | Resolution |
|---|---|---|---|---|
| P1 | Critical | `_replace_union` compared group membership to last element end, not group max end; reverse-index replacement applied stale offsets | Nested spans rendered `[CREDIT_CARD]]0000000xyz` with digits leaking | Forward-sweep replacement over merged groups (`pii.py`); test `test_nested_spans_union_with_stale_index_guard` |
| P2 | Critical | Adjacent (touching) spans merged into one union, losing the second label — violates LLD "adjacent remain separate" | `a@b.co415-555-0132` rendered `[EMAIL_ADDRESS]` only | Merge only when `start < group_end`; test `test_adjacent_spans_stay_separate_with_own_labels` |
| P3 | Critical | Pipeline block/byte/deadline state never reset — one reused instance falsely blocked request 5 | 5 sequential single-block requests: req5 BLOCK LIMIT_EXCEEDED | Per-request state keyed by request_id (`_begin_request`/`_reset_request_state`); tests `test_new_request_resets_budget` |
| P4 | High | `repr(Decision)` / `str` contained raw `safe_text`; `ValidatedEnvelope` repr contained text | `SYNTH_LEAK` present in repr | `field(repr=False)`; test `test_repr_never_contains_text` |
| P5 | High | PHONE threshold changed 0.5→0.4 with digest change but version stayed `v1` | Policy diff in phase-05 | Version bumped to `v1.1`; digest changes per edit |
| P6 | High | `AnalyzerEngine()` constructed on every `_detect` (twice per inspect) — 434ms construction vs 2ms warm analyze | Eval p95 423/502ms | Module-level cached engine; p95 now 14.0/109.3ms @512B/4KiB (within budget) |
| G1 | Medium | Pipeline never emitted audit events; `build_event` orphaned | grep: no audit import in pipeline | Injected `event_sink`; every decision emits allowlisted content-free event; test `test_event_sink_receives_content_free_events_with_rule_ids` |
| G2 | Medium | `detect()` stopped after first match — simultaneous rules lost IDs | Only `block-direct-override` reported for combined text | Collect all rule IDs across views; test `test_simultaneous_rules_report_every_rule_id` |
| G3 | Medium | `InjectionFinding.matched` stored raw matched substring | Code inspection | Field removed; findings carry `rule_id` only |
| G4 | Medium | `pip install -e .` shipped no package (missing packages.find) — tests passed only via pytest pythonpath | `import guardrails` failed in venv | `[tool.setuptools.packages.find] where=["src"]`; installed import verified |
| H1 | Medium | `reports/` gitignored — evaluation evidence never committed | `git check-ignore` matched | Removed from `.gitignore`; `reports/evaluation/review01-postfix/` committed |
| H3 | Low | `examples/synthetic_assistant.py` had broken package-relative imports, REDACT short-circuit skipped the model, denial returned `detail`; fixture loader misnamed `load_jsonl` | Import never executed by tests | Imports fixed to `guardrails.*`; REDACT continues with safe text; fixed refusal; `load_fixture` |

## Regression evidence

- Full suite: 68 passed (was 61; +7 regression tests for the findings).
- Repro script rerun: all seven observed symptoms resolved.
- Eval rerun with cached engine: `reports/evaluation/review01-postfix/` (leakage 0, canary absent).

## Remaining (unchanged by this review)

- Held-out corpora not built; injection FP rate and attack prevention UNMEASURED.
- Cold-start-with-model, concurrency-4, rollback drill pending.
- ADR acceptance, threat-review acceptance, target acceptance pending owner.
