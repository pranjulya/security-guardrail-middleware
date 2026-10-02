"""Offline evaluator: fixtures + live checks -> content-free report (review 02, M10).

Honest about what the numbers mean: the fixtures under ``tests/fixtures/eval/``
were authored by the same reviewer who fixed the detectors, after reading them.
They are larger than the previous 6-record set and report Wilson 95% CIs, but
they are NOT independent held-out data. End-to-end attack prevention against a
real model is still unmeasured.

Uses only the public package API (``PiiRedactor.detect``, ``Pipeline``,
``detect_injection``). No ``sys.path`` hacks, no private imports.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import statistics

# subprocess only re-runs our own interpreter with fixed code (cold start).
import subprocess  # nosec B404
import sys
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any

from guardrails.contracts import Action
from guardrails.injection import detect as detect_injection
from guardrails.pii import PiiRedactor
from guardrails.pipeline import Pipeline
from guardrails.policy import DEFAULT_POLICY, load_policy

ROOT = Path(__file__).resolve().parents[1]
CANARY = "SYNTH_EVAL_CANARY_7f3a9d"
CORE_ENTITIES = ("PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD")
EVAL_DIR = ROOT / "tests" / "fixtures" / "eval"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        records.append(json.loads(line))
    return records


def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion (95% by default)."""
    if n <= 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n)
    return (max(0.0, (centre - margin) / denom), min(1.0, (centre + margin) / denom))


def _overlap(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def match_spans(
    expected: Sequence[dict[str, Any]], detected: Sequence[Any]
) -> tuple[int, int, int]:
    """Greedy one-to-one matching by type + any character overlap.

    Exact (start, end) equality is too brittle for multi-token entities whose
    detector boundaries vary slightly (PERSON especially). Overlap matching is
    the standard for NER evaluation and still catches full misses.
    """
    unused = list(detected)
    tp = 0
    for gold in expected:
        for i, pred in enumerate(unused):
            if pred.entity_type != gold["entity"]:
                continue
            if _overlap((gold["start"], gold["end"]), (pred.start, pred.end)):
                tp += 1
                unused.pop(i)
                break
    return tp, len(unused), len(expected) - tp


def pii_metrics(redactor: PiiRedactor, records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    by_entity: dict[str, dict[str, int]] = {e: {"tp": 0, "fp": 0, "fn": 0} for e in CORE_ENTITIES}
    by_family: dict[str, dict[str, int]] = {}
    leakage = 0
    residual = 0
    for record in records:
        text = record["text"]
        expected = record.get("entity_spans") or []
        detected = redactor.detect(text)
        tp, fp, fn = match_spans(expected, detected)
        entity_keys = {s["entity"] for s in expected} | {s.entity_type for s in detected}
        # Attribute counts to the entities that appear; FPs for an unexpected
        # type land on that type so they show up in the report.
        for entity in entity_keys:
            e_tp, e_fp, e_fn = match_spans(
                [s for s in expected if s["entity"] == entity],
                [s for s in detected if s.entity_type == entity],
            )
            bucket = by_entity.setdefault(entity, {"tp": 0, "fp": 0, "fn": 0})
            bucket["tp"] += e_tp
            bucket["fp"] += e_fp
            bucket["fn"] += e_fn
        family = record.get("family", "unknown")
        fam = by_family.setdefault(family, {"tp": 0, "fp": 0, "fn": 0, "n": 0})
        fam["tp"] += tp
        fam["fp"] += fp
        fam["fn"] += fn
        fam["n"] += 1
        out, action, _ = redactor.redact(text)
        if action is Action.BLOCK:
            residual += 1
        for span in expected:
            raw = text[span["start"] : span["end"]]
            if raw and raw in out:
                leakage += 1
                break
    rows = {}
    for entity, counts in sorted(by_entity.items()):
        tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
        pos = tp + fn
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / pos if pos else 0.0
        p_lo, p_hi = wilson(tp, tp + fp)
        r_lo, r_hi = wilson(tp, pos)
        rows[entity] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "positives": pos,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "precision_ci95": [round(p_lo, 4), round(p_hi, 4)],
            "recall_ci95": [round(r_lo, 4), round(r_hi, 4)],
        }
    return {
        "by_entity": rows,
        "by_family": by_family,
        "leakage_cases": leakage,
        "residual_blocks": residual,
    }


def injection_metrics(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    by_family: dict[str, dict[str, int]] = {}
    for record in records:
        family = record.get("family", "unknown")
        fam = by_family.setdefault(family, {"tp": 0, "fn": 0, "n": 0})
        fam["n"] += 1
        if detect_injection(record["text"]):
            fam["tp"] += 1
        else:
            fam["fn"] += 1
    total_tp = sum(f["tp"] for f in by_family.values())
    total_n = sum(f["n"] for f in by_family.values())
    rate = total_tp / total_n if total_n else 0.0
    lo, hi = wilson(total_tp, total_n)
    return {
        "by_family": {
            k: {
                **v,
                "detection_rate": round(v["tp"] / v["n"], 4) if v["n"] else 0.0,
            }
            for k, v in sorted(by_family.items())
        },
        "detection_rate": round(rate, 4),
        "detection_ci95": [round(lo, 4), round(hi, 4)],
        "n": total_n,
        "detected": total_tp,
    }


def false_positive_rates(
    redactor: PiiRedactor, records: Iterable[dict[str, Any]]
) -> dict[str, Any]:
    by_family: dict[str, dict[str, int]] = {}
    pii_fp = inj_fp = 0
    n = 0
    for record in records:
        n += 1
        family = record.get("family", "unknown")
        fam = by_family.setdefault(family, {"n": 0, "pii_fp": 0, "inj_fp": 0})
        fam["n"] += 1
        if redactor.detect(record["text"]):
            fam["pii_fp"] += 1
            pii_fp += 1
        if detect_injection(record["text"]):
            fam["inj_fp"] += 1
            inj_fp += 1
    return {
        "n": n,
        "pii_fp": pii_fp,
        "injection_fp": inj_fp,
        "pii_fp_rate": round(pii_fp / n, 4) if n else 0.0,
        "injection_fp_rate": round(inj_fp / n, 4) if n else 0.0,
        "pii_fp_ci95": [round(x, 4) for x in wilson(pii_fp, n)],
        "injection_fp_ci95": [round(x, 4) for x in wilson(inj_fp, n)],
        "by_family": {
            k: {
                **v,
                "pii_fp_rate": round(v["pii_fp"] / v["n"], 4) if v["n"] else 0.0,
                "injection_fp_rate": round(v["inj_fp"] / v["n"], 4) if v["n"] else 0.0,
            }
            for k, v in sorted(by_family.items())
        },
    }


def _percentile(sorted_samples: list[float], p: float) -> float:
    if not sorted_samples:
        return 0.0
    idx = min(len(sorted_samples) - 1, max(0, math.ceil(p * len(sorted_samples)) - 1))
    return sorted_samples[idx]


def _summarize(samples: list[float]) -> dict[str, Any]:
    samples = sorted(samples)
    return {
        "n": len(samples),
        "p50_ms": round(_percentile(samples, 0.50), 2),
        "p95_ms": round(_percentile(samples, 0.95), 2),
        "p99_ms": round(_percentile(samples, 0.99), 2),
        "max_ms": round(samples[-1], 2) if samples else 0.0,
        "mean_ms": round(statistics.mean(samples), 2) if samples else 0.0,
    }


def _benign_pad(n: int) -> str:
    return ("Orders ship within two business days. " * ((n // 37) + 1))[:n]


def _pii_dense(n: int) -> str:
    chunks = [
        "Contact Alice Johnson at alice.johnson@example.com or +1-415-555-0132. ",
        "Card on file 4111 1111 1111 1111. ",
        "Call Priya Patel on (212) 555-0199. ",
    ]
    text = ""
    i = 0
    while len(text.encode("utf-8")) < n:
        text += chunks[i % len(chunks)]
        i += 1
    # Trim to the byte budget without cutting mid-character.
    encoded = text.encode("utf-8")[:n]
    return encoded.decode("utf-8", errors="ignore")


def timing(
    factory: Callable[[], Pipeline],
    *,
    sizes: tuple[int, ...] = (512, 4096, 16384),
    repeats: int = 50,
    warmups: int = 5,
) -> dict[str, Any]:
    stats: dict[str, Any] = {}
    for size in sizes:
        for kind, builder in (("benign", _benign_pad), ("pii-dense", _pii_dense)):
            text = builder(size)
            pipe = factory()
            for _ in range(warmups):
                pipe.inspect(_env(pipe, text, "warm"))
            samples = []
            for i in range(repeats):
                start = time.perf_counter()
                pipe.inspect(_env(pipe, text, f"t{i}"))
                samples.append((time.perf_counter() - start) * 1000)
            stats[f"{kind}@{size}B"] = _summarize(samples)
    return stats


def concurrency(
    factory: Callable[[], Pipeline], workers: tuple[int, ...] = (4, 8)
) -> dict[str, Any]:
    text = _pii_dense(2048)
    out: dict[str, Any] = {}
    for w in workers:
        pipe = factory()
        barrier = threading.Barrier(w)
        samples: list[float] = []
        lock = threading.Lock()

        def worker(
            rid_base: int,
            *,
            _pipe: Pipeline = pipe,
            _barrier: threading.Barrier = barrier,
            _lock: threading.Lock = lock,
            _samples: list[float] = samples,
        ) -> None:
            _barrier.wait()
            for i in range(10):
                start = time.perf_counter()
                _pipe.inspect(_env(_pipe, text, f"c{rid_base}-{i}"))
                with _lock:
                    _samples.append((time.perf_counter() - start) * 1000)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(w)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        out[str(w)] = _summarize(samples)
    return out


_COLD_CODE = """
import json, time
t0 = time.perf_counter()
from guardrails.pipeline import Pipeline
from guardrails.policy import DEFAULT_POLICY, load_policy
p = Pipeline.from_policy(load_policy(DEFAULT_POLICY))
t1 = time.perf_counter()
warm_ms = None
if WARM:
    warm_ms = p.warm_up()
t2 = time.perf_counter()
d = p.inspect({"boundary": "user_input", "language": "en", "text": "hello world",
               "request_id": "cold", "policy_id": p.policy.policy_id})
t3 = time.perf_counter()
print(json.dumps({"import_ms": int((t1 - t0) * 1000), "warm_up_ms": warm_ms,
                  "first_inspect_ms": int((t3 - t2) * 1000), "action": d.action.value,
                  "reason_codes": [r.value for r in d.reason_codes]}))
"""


def cold_start() -> dict[str, Any]:
    """Fresh interpreters: first inspect without and with warm_up()."""
    out: dict[str, Any] = {}
    for label, warm in (("no_warm_up", False), ("with_warm_up", True)):
        # Fixed code, our own interpreter, no shell, no untrusted input.
        result = subprocess.run(  # noqa: S603  # nosec B603
            [sys.executable, "-c", f"WARM = {warm}\n" + _COLD_CODE],
            check=True,
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            timeout=180,
        )
        out[label] = json.loads(result.stdout.strip().splitlines()[-1])
    return out


def _env(pipe: Pipeline, text: str, request_id: str) -> dict[str, Any]:
    return {
        "boundary": "user_input",
        "language": "en",
        "text": text,
        "request_id": request_id,
        "policy_id": pipe.policy.policy_id,
    }


def phone_person_fp_examples(redactor: PiiRedactor) -> dict[str, Any]:
    """Document the L1 trade-off with concrete false-positive examples."""
    cases = [
        ("order-number", "Order 9040620724 shipped this morning."),
        ("invoice-number", "Invoice number 4251479784 for your records."),
        ("error-code", "Error code 0x80074005 appeared during install."),
        ("django", "Deploy the Django app with gunicorn behind nginx."),
        ("siri", "Ask Siri to set a timer for ten minutes."),
        ("alexa", "Alexa, play some jazz in the kitchen."),
    ]
    rows = []
    for name, text in cases:
        hits = [
            {"entity": s.entity_type, "start": s.start, "end": s.end, "score": round(s.score, 3)}
            for s in redactor.detect(text)
        ]
        rows.append({"case": name, "text": text, "hits": hits})
    return {"cases": rows, "note": "Measured against the default thresholds; see calibration.md."}


def _obfuscation_recall(by_family: dict[str, dict[str, int]]) -> str:
    tp = sum(v["tp"] for v in by_family.values())
    pos = sum(v["tp"] + v["fn"] for v in by_family.values())
    return f"{(tp / pos) if pos else 0.0:.4f}"


def write_report(
    out_dir: Path,
    *,
    policy: Any,
    redactor: PiiRedactor,
    fixture_paths: dict[str, Path],
    pii: dict[str, Any],
    obfuscated: dict[str, Any],
    injection: dict[str, Any],
    fps: dict[str, Any],
    perf: dict[str, Any],
    concurrent: dict[str, Any],
    cold: dict[str, Any],
    tradeoff: dict[str, Any],
    repeats: int,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=False)
    (out_dir / "metrics.csv").write_text(
        "entity,tp,fp,fn,positives,precision,recall,precision_lo,precision_hi,recall_lo,recall_hi\n"
        + "".join(
            f"{e},{v['tp']},{v['fp']},{v['fn']},{v['positives']},{v['precision']},"
            f"{v['recall']},{v['precision_ci95'][0]},{v['precision_ci95'][1]},"
            f"{v['recall_ci95'][0]},{v['recall_ci95'][1]}\n"
            for e, v in pii["by_entity"].items()
        ),
        encoding="utf-8",
    )
    (out_dir / "metrics.json").write_text(
        json.dumps(
            {
                "pii": pii,
                "obfuscated": obfuscated,
                "injection": injection,
                "false_positives": fps,
                "performance": perf,
                "concurrency": concurrent,
                "cold_start": cold,
                "phone_person_tradeoff": tradeoff,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    metadata = {
        "run_id": out_dir.name,
        "policy_version": policy.version,
        "policy_digest": policy.digest,
        "policy_id": policy.policy_id,
        "detector": redactor.detector_version,
        "fixtures": {k: str(v.relative_to(ROOT)) for k, v in fixture_paths.items()},
        "fixture_sha256": {k: sha256_file(v) for k, v in fixture_paths.items()},
        "python": platform.python_version(),
        "platform": platform.platform(),
        "repeats": repeats,
        "honesty": (
            "Fixtures are author-written after reading the detectors; they are "
            "NOT independent held-out data and will overstate real accuracy. "
            "No real model run: end-to-end attack prevention is UNMEASURED."
        ),
    }
    (out_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8"
    )

    def row(entity: str, values: dict[str, Any]) -> str:
        return (
            f"| {entity} | {values['positives']} | {values['precision']:.4f} "
            f"[{values['precision_ci95'][0]:.4f}, {values['precision_ci95'][1]:.4f}] | "
            f"{values['recall']:.4f} "
            f"[{values['recall_ci95'][0]:.4f}, {values['recall_ci95'][1]:.4f}] |"
        )

    summary = [
        "# Evaluation summary (review 02)",
        "",
        f"Run: `{out_dir.name}` — synthetic fixtures only; no real PII.",
        f"Policy: `{policy.policy_id}` (version {policy.version}, digest {policy.digest}).",
        f"Detector: `{redactor.detector_version}`.",
        "",
        "> **Honesty:** fixtures were authored by the same reviewer who fixed the",
        "> detectors, after reading them. Numbers will overstate real accuracy.",
        "> End-to-end attack prevention against a real model is **UNMEASURED**.",
        "",
        "## PII per-category (held-out-sized author-written set)",
        "",
        "| entity | n | precision [95% CI] | recall [95% CI] |",
        "|---|---|---|---|",
    ]
    for entity, values in pii["by_entity"].items():
        summary.append(row(entity, values))
    summary += [
        "",
        f"Residual leakage cases: {pii['leakage_cases']}",
        f"Residual-PII BLOCKs: {pii['residual_blocks']}",
        "",
        "## Obfuscated PII (M3)",
        "",
        "| family | n | recall |",
        "|---|---|---|",
    ]
    for family, values in obfuscated["by_family"].items():
        pos = values["tp"] + values["fn"]
        recall = values["tp"] / pos if pos else 0.0
        summary.append(f"| {family} | {values['n']} | {recall:.4f} |")
    summary += [
        "",
        ("Overall obfuscation recall: " + _obfuscation_recall(obfuscated["by_family"])),
        "",
        "## Injection detection",
        "",
        f"Overall: {injection['detected']}/{injection['n']} "
        f"= {injection['detection_rate']:.4f} "
        f"[{injection['detection_ci95'][0]:.4f}, {injection['detection_ci95'][1]:.4f}]",
        "",
        "| family | n | detection rate |",
        "|---|---|---|",
    ]
    for family, values in injection["by_family"].items():
        summary.append(f"| {family} | {values['n']} | {values['detection_rate']:.4f} |")
    summary += [
        "",
        "## False positives on benign text",
        "",
        f"PII FP rate: {fps['pii_fp']}/{fps['n']} = {fps['pii_fp_rate']:.4f} "
        f"[{fps['pii_fp_ci95'][0]:.4f}, {fps['pii_fp_ci95'][1]:.4f}]",
        f"Injection FP rate: {fps['injection_fp']}/{fps['n']} = {fps['injection_fp_rate']:.4f} "
        f"[{fps['injection_fp_ci95'][0]:.4f}, {fps['injection_fp_ci95'][1]:.4f}]",
        "",
        "| family | n | PII FP | injection FP |",
        "|---|---|---|---|",
    ]
    for family, values in fps["by_family"].items():
        summary.append(
            f"| {family} | {values['n']} | {values['pii_fp_rate']:.4f} | "
            f"{values['injection_fp_rate']:.4f} |"
        )
    summary += [
        "",
        "## Phone / PERSON false-positive trade-off (L1)",
        "",
        "| case | hits |",
        "|---|---|",
    ]
    for case in tradeoff["cases"]:
        hits = ", ".join(f"{h['entity']}@{h['score']}" for h in case["hits"]) or "(none)"
        summary.append(f"| {case['case']} | {hits} |")
    summary += [
        "",
        "## Performance (warm process)",
        "",
    ]
    for label, values in perf.items():
        summary.append(
            f"- {label}: p50 {values['p50_ms']}ms p95 {values['p95_ms']}ms "
            f"p99 {values['p99_ms']}ms max {values['max_ms']}ms (n={values['n']})"
        )
    summary += ["", "## Concurrency", ""]
    for workers, values in concurrent.items():
        summary.append(
            f"- concurrency {workers}: p50 {values['p50_ms']}ms p95 {values['p95_ms']}ms "
            f"p99 {values['p99_ms']}ms (n={values['n']})"
        )
    summary += [
        "",
        "## Cold start (fresh interpreter)",
        "",
    ]
    for label, values in cold.items():
        summary.append(
            f"- {label}: import+build {values.get('import_ms')}ms, warm_up "
            f"{values.get('warm_up_ms') if values.get('warm_up_ms') is not None else 'skipped'}"
            f"{'ms' if values.get('warm_up_ms') is not None else ''}, "
            f"first inspect {values.get('first_inspect_ms')}ms "
            f"-> {values.get('action')} {' '.join(values.get('reason_codes', []))}".rstrip()
        )
    summary += [
        "",
        "## Limits",
        "",
        "- English only; 4 core entities; single host/hardware.",
        "- Fixtures are author-written (not independent).",
        "- No real model run: end-to-end attack prevention UNMEASURED.",
        "- Privacy canary absent from exported artifacts (checked below).",
        "",
    ]
    (out_dir / "summary.md").write_text("\n".join(summary), encoding="utf-8")


def artifacts_contain_canary(out_dir: Path) -> bool:
    """True if the privacy canary appears in any exported artifact."""
    return any(
        CANARY in path.read_text(encoding="utf-8")
        for path in sorted(out_dir.iterdir())
        if path.is_file()
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--fixtures-dir", default=str(EVAL_DIR))
    parser.add_argument("--repeats", type=int, default=50)
    parser.add_argument("--skip-cold-start", action="store_true")
    args = parser.parse_args(argv)

    fixtures = Path(args.fixtures_dir)
    paths = {
        "pii": fixtures / "pii-heldout.jsonl",
        "obfuscated": fixtures / "pii-obfuscated.jsonl",
        "injection": fixtures / "injection.jsonl",
        "benign": fixtures / "benign.jsonl",
    }
    for path in paths.values():
        if not path.is_file():
            print(f"missing fixture: {path}", file=sys.stderr)
            return 2

    policy = load_policy(DEFAULT_POLICY)
    redactor = PiiRedactor.from_policy(policy)

    def factory() -> Pipeline:
        return Pipeline.from_policy(policy)

    # Warm once so the first measured sample isn't the model load.
    factory().warm_up()

    pii = pii_metrics(redactor, load_jsonl(paths["pii"]))
    obfuscated = pii_metrics(redactor, load_jsonl(paths["obfuscated"]))
    injection = injection_metrics(load_jsonl(paths["injection"]))
    fps = false_positive_rates(redactor, load_jsonl(paths["benign"]))
    perf = timing(factory, repeats=args.repeats)
    concurrent = concurrency(factory)
    cold: dict[str, Any] = {} if args.skip_cold_start else cold_start()
    tradeoff = phone_person_fp_examples(redactor)

    out_dir = ROOT / "reports" / "evaluation" / args.run_id
    write_report(
        out_dir,
        policy=policy,
        redactor=redactor,
        fixture_paths=paths,
        pii=pii,
        obfuscated=obfuscated,
        injection=injection,
        fps=fps,
        perf=perf,
        concurrent=concurrent,
        cold=cold,
        tradeoff=tradeoff,
        repeats=args.repeats,
    )

    if artifacts_contain_canary(out_dir):  # explicit: survives `python -O`
        print("canary leaked into report", file=sys.stderr)
        return 1
    print(f"wrote {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
