# Learning path

| Stage | Preparation | Practical evidence | Explain back |
|---|---|---|---|
| 00 | Read threat model and trust boundaries | Draw who controls each input | Why model output cannot grant authority |
| 01 | Study policy precedence and byte limits | Predict five decision outcomes | Fail closed versus fail open |
| 02 | Study offsets, recall and anonymization limits | Manually annotate Unicode spans | Why normalization breaks naive indexing |
| 03 | Study indirect injection and tool allowlists | Walk a malicious retrieved paragraph through flow | Why detection and authorization differ |
| 04 | Study release timing | Trace a late detector failure | Why buffering is a security choice |
| 05 | Study held-out evaluation | Interpret confusion matrix with denominators | Why a finite benchmark cannot prove universal defense |
| 06 optional | Study service boundaries and backpressure | Trace auth/body-limit rejection | Why a service is not automatically stronger |

Suggested pacing: one phase per focused learning session; do not advance based on elapsed time. Deliver a one-page note stating expected behavior, a counterexample, measured outcome and remaining uncertainty.
