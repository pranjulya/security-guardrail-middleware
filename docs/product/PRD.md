# Product requirements

Status: PROPOSED; implementation NOT_STARTED. Owner: project author. Target user: a Python application developer integrating a text-based assistant who needs inspectable decisions and evidence of limitations.

## Problem and value

Untrusted user, retrieved and tool content can influence model behavior; sensitive text can also cross model, logging and response boundaries. The product provides one explicit policy contract rather than scattered string checks. It reduces measured risk on a bounded workload; it does not certify an application or guarantee that injection is blocked.

## Journeys and requirements

| ID | Journey / requirement | Acceptance owner |
|---|---|---|
| R1 | Developer passes a user_input, retrieved_content, tool_output or model_output envelope | Phase 01 rejects unknown boundary, malformed text and oversize requests |
| R2 | Synthetic English PII appears in text | Phase 02 replaces supported detected spans with category labels, exposes no raw spans in events |
| R3 | Text attempts instruction override or data exfiltration | Phase 03 returns policy rule reasons; a missed injection cannot grant tool capability |
| R4 | Model proposes a tool call | Host authorization validates fixed tool name, arguments and trusted principal; no model-supplied principal is accepted |
| R5 | Generated response includes disallowed text | Phase 04 blocks or redacts before any release; no user-visible streaming |
| R6 | Detector/policy fails | Mandatory checks fail closed with stable reason code and no result text |
| R7 | Operator investigates false blocks | Content-free event identifies boundary, policy/detector version and rule IDs; reproduce only with synthetic local cases |
| R8 | Reviewer assesses quality | Phase 05 publishes denominators, splits, misses and limitations; no real PII or unverified protection claim |

## Scope and exclusions

V1 supports UTF-8 English text and EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, PERSON. The application declares language; unsupported values block. Undeclared or mislabeled non-English content is a documented detection limitation, not magically recognized language coverage. Local model invocation is optional for end-to-end attack tests; deterministic fake model tests remain available. Four boundaries are mandatory integration points, not automatic hooks into every framework.

Exclude reversible pseudonymization, cross-request identity tracking, custom country identifiers, images/PDF OCR, broad toxicity moderation, autonomous remediation, arbitrary URL tools, stateful conversation memory, regulated compliance certification and public multi-tenancy. Input/output filtering means explicit boundary validation, injection rules and supported PII policy; it does not claim a general harmful-content classifier.

## Proposed acceptance targets

Security invariants: 100% pass on declared malformed-boundary, unauthorized-tool, mandatory-detector-error, and blocked-output-no-release cases. These are finite regression checks, not universal guarantees.

PII held-out target: entity-level exact-span recall ≥95% and precision ≥90% for each supported category, with at least 100 positive instances per category. Report overlapping-span handling and a separate any-span leakage rate. PERSON failure may require narrowing scope with owner approval, never silently dropping it.

Injection target: with a pinned optional model, ≥90% observed attack prevention on a preregistered 120-case held-out corpus and ≤5% false blocks on 200 benign cases. Without a real model run, report detector recall/false-positive rate only and mark end-to-end prevention UNMEASURED. Include baseline and repeat stochastic model trials three times; report counts and uncertainty.

Performance provisional budget: local warm-process p95 ≤200 ms per ≤4 KiB text at concurrency 1, excluding generation; p95 ≤800 ms per maximum aggregate request. Proposed cooperative inspection deadline: 2 seconds of cumulative detector/validation time per application request, excluding model/tool execution. A blocking synchronous detector cannot be preempted by this budget: check before and after each detector, then block without releasing text if the budget is exceeded. This is a no-late-release contract, not a guaranteed CPU termination deadline. Benchmark on recorded hardware, also measure cold startup and concurrency 4; do not claim these budgets are met yet.

## Release and change policy

No numerical target has been measured. An unmet security invariant blocks release. Quality/performance misses require tuning on development data or an explicitly accepted scope/target revision before a fresh held-out run. The public demo remains synthetic and local until separate hosting authorization.
