"""Offline evaluator: fixtures + live checks -> content-free report."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from guardrails.pipeline import Pipeline  # noqa: E402
from guardrails.pii import PiiRedactor, _presidio_detector  # noqa: E402
from guardrails.policy import DEFAULT_POLICY, load_policy  # noqa: E402

CANARY = "SYNTH_EVAL_CANARY_7f3a9d"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_fixture(path: Path) -> list:
    data = json.loads(path.read_text())
    if isinstance(data, dict) and "records" in data:
        return data["records"]
    if isinstance(data, list):
        return data
    lines = path.read_text().splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def pii_metrics(redactor: PiiRedactor, records: list) -> dict:
    by_entity: dict[str, dict[str, int]] = {}
    leakage = 0
    for record in records:
        for span in record.get("entity_spans", []):
            by_entity.setdefault(span["entity"], {"tp": 0, "fp": 0, "fn": 0})
        text = record["text"]
        detected = {(s.entity_type, s.start, s.end) for s in redactor._detect(text)}
        expected = {(s["entity"], s["start"], s["end"]) for s in record.get("entity_spans", [])}
        for key in detected & expected:
            by_entity[key[0]]["tp"] += 1
        for key in detected - expected:
            by_entity.setdefault(key[0], {"tp": 0, "fp": 0, "fn": 0})["fp"] += 1
        for key in expected - detected:
            by_entity[key[0]]["fn"] += 1
        out, _, _ = redactor.redact(text)
        for span in record.get("entity_spans", []):
            raw = text[span["start"]:span["end"]]
            if raw and raw in out:
                leakage += 1
                break
    rows = {}
    for entity, counts in sorted(by_entity.items()):
        tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
        denom = tp + fn
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / denom if denom else 0.0
        rows[entity] = {"tp": tp, "fp": fp, "fn": fn, "positives": denom,
                        "precision": round(precision, 4), "recall": round(recall, 4)}
    return {"by_entity": rows, "leakage_cases": leakage}


def timing_stats(pipeline_factory, sizes=(512, 4096), repeats=200, warmups=20) -> dict:
    stats = {}
    for size in sizes:
        text = "hello world. " * (size // 13 + 1)
        text = text[:size]
        pipe = pipeline_factory()
        for _ in range(warmups):
            pipe.inspect({"boundary": "user_input", "language": "en", "text": text,
                          "request_id": "warm", "policy_id": pipe.policy.version})
        samples = []
        for i in range(repeats):
            pipe = pipeline_factory() if i % 50 == 0 else pipe
            start = time.perf_counter()
            pipe.inspect({"boundary": "user_input", "language": "en", "text": text,
                          "request_id": f"t{i}", "policy_id": pipe.policy.version})
            samples.append((time.perf_counter() - start) * 1000)
        samples.sort()
        stats[str(size)] = {"n": repeats, "p50_ms": round(samples[len(samples) // 2], 2),
                            "p95_ms": round(samples[int(len(samples) * 0.95) - 1], 2),
                            "max_ms": round(samples[-1], 2),
                            "mean_ms": round(statistics.mean(samples), 2)}
    return stats


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--fixtures", default="tests/fixtures/pii-development.jsonl")
    parser.add_argument("--repeats", type=int, default=200)
    args = parser.parse_args()

    policy = load_policy(DEFAULT_POLICY)
    redactor = PiiRedactor(entities=sorted(policy.entities),
                           thresholds=dict(policy.thresholds),
                           detector=_presidio_detector)
    factory = lambda: Pipeline(policy=policy, redactor=PiiRedactor(
        entities=sorted(policy.entities), thresholds=dict(policy.thresholds),
        detector=_presidio_detector))

    fixture_path = ROOT / args.fixtures
    records = load_fixture(fixture_path)
    pii = pii_metrics(redactor, records)
    perf = timing_stats(factory, repeats=args.repeats)

    out_dir = ROOT / "reports" / "evaluation" / args.run_id
    out_dir.mkdir(parents=True, exist_ok=False)
    (out_dir / "metrics.csv").write_text(
        "entity,tp,fp,fn,positives,precision,recall\n" + "".join(
            f"{e},{v['tp']},{v['fp']},{v['fn']},{v['positives']},{v['precision']},{v['recall']}\n"
            for e, v in pii["by_entity"].items()
        )
    )
    metadata = {
        "run_id": args.run_id,
        "policy_version": policy.version,
        "policy_digest": policy.digest,
        "detector": redactor.detector_version,
        "fixtures": args.fixtures,
        "fixture_sha256": sha256_file(fixture_path),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "repeats": args.repeats,
    }
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True))
    summary = [
        "# Evaluation summary",
        "",
        f"Run: {args.run_id} (synthetic fixtures only; no real PII)",
        f"Policy: {policy.version} digest {policy.digest}",
        "",
        "## PII per-category (development fixtures)",
        "",
        "| entity | n | precision | recall |",
        "|---|---|---|---|",
    ]
    for entity, values in pii["by_entity"].items():
        summary.append(f"| {entity} | {values['positives']} | {values['precision']} | {values['recall']} |")
    summary += [
        "",
        f"Residual leakage cases: {pii['leakage_cases']}",
        "",
        "## Performance (local warm process, model/tool time excluded)",
        "",
    ]
    for size, values in perf.items():
        summary.append(f"- {size}B text: p50 {values['p50_ms']}ms p95 {values['p95_ms']}ms max {values['max_ms']}ms (n={values['n']})")
    summary += [
        "",
        "## Limits",
        "",
        "- English only; 4 entities; finite templates; single host/hardware.",
        "- No real model run: end-to-end attack prevention UNMEASURED.",
        "- Privacy canary absent from exported artifacts (checked below).",
    ]
    (out_dir / "summary.md").write_text("\n".join(summary) + "\n")

    blob = ((out_dir / "summary.md").read_text() + (out_dir / "metadata.json").read_text()
            + (out_dir / "metrics.csv").read_text())
    assert CANARY not in blob, "canary leaked into report"
    print(f"wrote {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
