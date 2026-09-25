# Sources and verification notes

Primary documentation checked 2026-09-23. These inform proposed choices; package versions and operational compatibility must be rechecked in phase 00.

- [OWASP Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html): source for the direct/indirect injection distinction and layered defenses. Our bounded pipeline and quantitative targets are project design choices, not OWASP certification.
- [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html): further review reading for application-owned permissions and tool boundaries.
- [Presidio Analyzer](https://presidio.dataprivacystack.org/analyzer/): local text detection uses recognizers; model/language configuration matters. Four-category coverage is our proposed tested subset.
- [Presidio Anonymizer](https://presidio.dataprivacystack.org/anonymizer/): transformation of detected text spans. Irreversible category replacement is our chosen policy.

The older microsoft.github.io Presidio pages redirected to current Data Privacy Stack documentation during this planning session. Verify package ownership, artifact licenses and supported runtime versions before installing; do not copy an unpinned latest image reference from examples.
