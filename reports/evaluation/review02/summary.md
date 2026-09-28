# Evaluation summary (review 02)

Run: `review02` — synthetic fixtures only; no real PII.
Policy: `v1.1@ae230164b8b68168` (version v1.1, digest ae230164b8b681685526930bd21a258e6320870773b0a56486e8a7eab3d00fb1).
Detector: `presidio-analyzer==2.2.360/en_core_web_lg==3.8.0`.

> **Honesty:** fixtures were authored by the same reviewer who fixed the
> detectors, after reading them. Numbers will overstate real accuracy.
> End-to-end attack prevention against a real model is **UNMEASURED**.

## PII per-category (held-out-sized author-written set)

| entity | n | precision [95% CI] | recall [95% CI] |
|---|---|---|---|
| CREDIT_CARD | 140 | 1.0000 [0.9733, 1.0000] | 1.0000 [0.9733, 1.0000] |
| EMAIL_ADDRESS | 150 | 1.0000 [0.9750, 1.0000] | 1.0000 [0.9750, 1.0000] |
| PERSON | 160 | 0.9935 [0.9644, 0.9989] | 0.9625 [0.9206, 0.9827] |
| PHONE_NUMBER | 140 | 1.0000 [0.9733, 1.0000] | 1.0000 [0.9733, 1.0000] |

Residual leakage cases: 6
Residual-PII BLOCKs: 0

## Obfuscated PII (M3)

| family | n | recall |
|---|---|---|
| email-zero-width | 8 | 1.0000 |
| email-fullwidth-at | 8 | 1.0000 |
| email-bracket-at-dot | 8 | 1.0000 |
| email-paren-at-dot | 8 | 1.0000 |
| email-spelled-at-dot | 8 | 0.0000 |
| card-zero-width | 8 | 1.0000 |
| card-fullwidth-digits | 8 | 1.0000 |
| card-dotted | 8 | 1.0000 |
| card-nbsp | 8 | 1.0000 |
| card-slash | 8 | 0.0000 |
| card-spelled-digits | 8 | 0.0000 |
| phone-fullwidth-digits | 8 | 1.0000 |
| phone-zero-width | 8 | 1.0000 |

Overall obfuscation recall: 0.7692

## Injection detection

Overall: 91/120 = 0.7583 [0.6745, 0.8261]

| family | n | detection rate |
|---|---|---|
| data-exfiltration | 15 | 0.6667 |
| destructive-action | 15 | 0.7333 |
| direct-override | 15 | 0.8000 |
| fake-delimiter | 15 | 0.8000 |
| indirect-injection | 15 | 0.8667 |
| obfuscated-override | 15 | 0.8667 |
| prompt-exfiltration | 15 | 0.8667 |
| roleplay-jailbreak | 15 | 0.4667 |

## False positives on benign text

PII FP rate: 19/200 = 0.0950 [0.0617, 0.1436]
Injection FP rate: 0/200 = 0.0000 [0.0000, 0.0188]

| family | n | PII FP | injection FP |
|---|---|---|---|
| business-numbers | 20 | 0.2500 | 0.0000 |
| code-snippet | 20 | 0.0000 | 0.0000 |
| dates-prices | 20 | 0.0000 | 0.0000 |
| model-reply | 20 | 0.0000 | 0.0000 |
| near-miss-wording | 20 | 0.0000 | 0.0000 |
| retrieved-doc | 20 | 0.0000 | 0.0000 |
| security-discussion | 20 | 0.0000 | 0.0000 |
| support-question | 20 | 0.0000 | 0.0000 |
| tech-terms | 20 | 0.7000 | 0.0000 |
| tool-json | 20 | 0.0000 | 0.0000 |

## Phone / PERSON false-positive trade-off (L1)

| case | hits |
|---|---|
| order-number | PHONE_NUMBER@0.4 |
| invoice-number | PHONE_NUMBER@0.75 |
| error-code | PERSON@0.85 |
| django | PERSON@0.85 |
| siri | PERSON@0.85 |
| alexa | (none) |

## Performance (warm process)

- benign@512B: p50 13.32ms p95 24.37ms p99 97.32ms max 97.32ms (n=30)
- pii-dense@512B: p50 37.94ms p95 42.04ms p99 63.58ms max 63.58ms (n=30)
- benign@4096B: p50 72.33ms p95 78.43ms p99 78.8ms max 78.8ms (n=30)
- pii-dense@4096B: p50 245.7ms p95 340.21ms p99 361.93ms max 361.93ms (n=30)
- benign@16384B: p50 309.75ms p95 344.26ms p99 349.52ms max 349.52ms (n=30)
- pii-dense@16384B: p50 1127.4ms p95 1381.39ms p99 1440.41ms max 1440.41ms (n=30)

## Concurrency

- concurrency 4: p50 355.32ms p95 431.11ms p99 441.66ms (n=40)
- concurrency 8: p50 777.72ms p95 836.17ms p99 846.15ms (n=80)

## Cold start (fresh interpreter)

- no_warm_up: import+build 73ms, warm_up skipped, first inspect 2000ms -> BLOCK DEADLINE_EXCEEDED
- with_warm_up: import+build 63ms, warm_up 2219ms, first inspect 6ms -> ALLOW

## Limits

- English only; 4 core entities; single host/hardware.
- Fixtures are author-written (not independent).
- No real model run: end-to-end attack prevention UNMEASURED.
- Privacy canary absent from exported artifacts (checked below).
