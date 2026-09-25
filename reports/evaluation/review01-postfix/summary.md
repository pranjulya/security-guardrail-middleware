# Evaluation summary

Run: review01-postfix (synthetic fixtures only; no real PII)
Policy: v1.1 digest ae230164b8b681685526930bd21a258e6320870773b0a56486e8a7eab3d00fb1

## PII per-category (development fixtures)

| entity | n | precision | recall |
|---|---|---|---|
| CREDIT_CARD | 1 | 1.0 | 1.0 |
| EMAIL_ADDRESS | 2 | 1.0 | 1.0 |
| PERSON | 2 | 1.0 | 1.0 |
| PHONE_NUMBER | 1 | 1.0 | 1.0 |

Residual leakage cases: 0

## Performance (local warm process, model/tool time excluded)

- 512B text: p50 13.42ms p95 14.04ms max 18.75ms (n=200)
- 4096B text: p50 98.69ms p95 109.31ms max 168.48ms (n=200)

## Limits

- English only; 4 entities; finite templates; single host/hardware.
- No real model run: end-to-end attack prevention UNMEASURED.
- Privacy canary absent from exported artifacts (checked below).
