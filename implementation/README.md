# Phase execution index

Planning delivery only. All phases NOT_STARTED. Read the master Definition of Done and global constraints before starting.

| Phase | Depends on | Deliverable |
|---|---|---|
| [00](phase-00-contract-and-environment.md) | Owner implementation approval | Compatibility and threat/fixture baseline |
| [01](phase-01-policy-and-boundaries.md) | 00 | Validated policy and decision contract |
| [02](phase-02-pii-redaction.md) | 01 | Original-text PII redaction |
| [03](phase-03-injection-and-tools.md) | 02 | Risk rules and deterministic tool boundary |
| [04](phase-04-buffered-integration.md) | 03 | All four boundaries and safe output release |
| [05](phase-05-evaluation-and-release.md) | 04 | Reviewed evaluation and operational evidence |
| [06](phase-06-optional-http.md) | 05 plus named consumer approval | Optional authenticated HTTP adapter |

Status progression: NOT_STARTED → IN_PROGRESS → IMPLEMENTED → TESTED → REVIEWED → COMPLETE. Record a separate blocking reason when dependencies or tests prevent progress; do not invent a competing status. IMPLEMENTED means scoped changes exist; TESTED requires recorded passing evidence; REVIEWED requires findings resolved; COMPLETE requires acceptance. Each phase records date, commit, actual checks/results, review findings and remaining limitations. Missing evidence means not complete. Future test paths in phase files are planned, not currently runnable artifacts.
