# Observability and privacy

The core works without Project 09 or an external backend. Emit one completion event per boundary, with request_id, boundary, action, fixed reason codes, policy version, detector versions, duration and byte-count bucket. Do not log raw/sanitized text, detected values, spans, HTTP bodies, exception repr, prompts, tool arguments or content hashes. User-supplied IDs are not trusted labels.

Counters: decisions by boundary/action/reason; detector failures; deadline failures; tool denials. Histograms: inspection duration by boundary and coarse size bucket. Gauges: readiness and bounded work queue occupancy. Metric labels must be finite; policy/detector versions belong in resource metadata or events rather than uncontrolled time series.

Proposed alerts: any mandatory detector initialization failure prevents readiness; ≥3 detector errors in five minutes triggers investigation; block-rate ≥3× the prior day baseline for 15 minutes with ≥100 requests warns of attack or policy regression. In low-traffic demos rely on deterministic test alarms, not statistically meaningless rates. Latency above PRD budget warns, it never silently disables inspection.

Default retention is seven days of content-free events locally with restricted access, then deletion. Disable third-party SDK payload capture and HTTP access body logging. A synthetic canary containing unique PII markers must be absent from all logs, traces, error outputs and exported reports. Event exporter failure cannot release an otherwise blocked response; an allowed response may proceed if only optional telemetry is unavailable, with a bounded local error counter. Mandatory detectors remain fail closed.

Operator workflow: correlate opaque ID → identify policy/detector release → reproduce using approved synthetic fixture → compare prior policy → rollback the entire tested bundle if regression confirmed. Never ask a user to paste real sensitive content into an issue.
