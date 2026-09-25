# Interview questions and answers

1. **Can this block all prompt injection?** No. It measures bounded risk reduction and enforces independent permissions; novel language and context can bypass detectors.
2. **Why a library first?** It exposes application boundaries directly and avoids a service/auth/network surface until a real client needs it.
3. **Why inspect tool output?** A tool may return attacker-controlled text even when the tool invocation itself is authorized.
4. **Why not trust redacted text?** Removing detected PII does not remove instructions or make a source authoritative.
5. **Why buffer output?** Once streamed, sensitive text cannot be recalled. This contract filters before release.
6. **What does fail closed cost?** Availability and perceived latency; users receive refusal during mandatory detector failure instead of uninspected data.
7. **How are PII claims bounded?** English text, four entities, pinned recognizers and reported per-entity metrics; unsupported categories are excluded explicitly.
8. **What is a Unicode span bug?** Indexing original text with offsets computed on a length-changing normalized view can redact the wrong characters.
9. **Why no reversible tokens?** They create sensitive state, key management and cross-request linkage beyond V1 needs.
10. **How do you investigate without payload logs?** Use versioned decisions and synthetic reproduction; inability to inspect raw production content is an intentional privacy tradeoff.
11. **Does a timeout cancel CPU work?** Not necessarily; host supervision and bounded admission prevent abandoned detector work from growing indefinitely.
12. **What convinces a reviewer?** Reproducible held-out results, failed cases, privacy canary evidence and zero unauthorized dispatch/release in fixed invariants, alongside candid limits.
