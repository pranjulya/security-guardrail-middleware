# Production scenarios and drills

These are planned tabletop and automated drills, not claims of a production deployment.

| Scenario | Expected response | Evidence / recovery |
|---|---|---|
| Missing English NLP model | Startup unready; no inspection accepted | Startup test; reinstall pinned artifact and rerun canary |
| PII detector exception after generation | BLOCK; no buffered text released | Output sink receives zero bytes; recycle unhealthy worker |
| Benign quote about injection blocked | Stable refusal and reason event | Add synthetic minimal reproduction to development set; review policy, never edit held-out labels to win |
| Unicode spans overlap | Replace original-text union deterministically | Golden expected string; no original entity fragments |
| Retrieved paragraph requests a tool | Data remains untrusted; tool permissions unchanged | Fake-model integration and unauthorized-call counter |
| Model requests HTTP fetch or delete | TOOL_DENIED; never dispatch | Spy records zero calls |
| Oversized response | LIMIT_EXCEEDED; no truncation and release | 16 KiB+1 UTF-8 test including multibyte text |
| Telemetry collector unavailable | Security decisions unchanged; optional event export drops boundedly | No queue growth; restore exporter |
| Policy deployment malformed | New process never becomes ready | Keep prior healthy bundle; validate policy before deployment |
| Repeated expensive requests | Host bounds work; optional service returns 429 | Queue and memory load test, no fail-open |

Release drill: start clean environment, run benign/redacted/blocked cases, inject detector failure, verify privacy sinks, restore, and repeat. Record timestamps, versions and observed outcomes in a release report. No unsupported uptime or scale promise follows from a local drill.
