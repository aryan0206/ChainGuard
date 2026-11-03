"""Strict, dependency-free experiment accounting. No labels are generated here."""

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import statistics

DETECTORS = ("B0", "B1", "B2-R", "B2-S")
LABELS = {"AUTHORIZED", "UNAUTHORIZED"}


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _verified_json(ref, base_dir):
    _require(isinstance(ref, dict), "evidence reference required")
    path_text, expected = ref.get("path"), ref.get("sha256")
    _require(isinstance(path_text, str) and path_text, "evidence path required")
    _require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected), "evidence SHA-256 required")
    path = (base_dir / path_text).resolve()
    _require(path.is_file(), f"evidence file absent: {path}")
    raw = path.read_bytes()
    _require(hashlib.sha256(raw).hexdigest() == expected, f"evidence digest mismatch: {path}")
    return json.loads(raw)


def summarize(document, base_dir=Path.cwd()):
    """Count only externally qualified, frozen research cases.

    Positive means AUTHORIZED. FP is an unsafe authorization of an
    UNAUTHORIZED case; FN is an unnecessary denial of an AUTHORIZED case.
    INDETERMINATE is abstention and never silently scored as an error.
    """
    _require(document.get("schema") == "chainguard-research-observations-v1", "schema")
    rows = document.get("cases")
    _require(isinstance(rows, list), "cases must be a list")
    base_dir = Path(base_dir)
    seen = set()
    excluded = []
    eligible = []
    for row in rows:
        case_id = row.get("case_id")
        _require(isinstance(case_id, str) and case_id and case_id not in seen, "unique case_id required")
        seen.add(case_id)
        _require(isinstance(row.get("parent_id"), str) and row["parent_id"], "parent_id required")
        if row.get("classification") != "RESEARCH" or row.get("eligible") is not True:
            _require(bool(row.get("exclusion_reason")), "excluded case needs reason")
            excluded.append({"case_id": case_id, "reason": row["exclusion_reason"]})
            continue
        contract = _verified_json(document.get("frozen_contract"), base_dir)
        _require(contract.get("schema") == "chainguard-frozen-experiment-contract-v1", "frozen contract schema")
        _require(case_id in contract.get("case_ids", []), "case absent from frozen contract")
        _require(row.get("oracle_source") == "INDEPENDENT", "research requires independent oracle")
        _require(row.get("witness_status") == "COMPLETE", "research requires complete witness")
        _require(row.get("oracle_label") in LABELS, "definite independent label required")
        oracle = _verified_json(row.get("oracle_record"), base_dir)
        witness = _verified_json(row.get("witness_record"), base_dir)
        _require(oracle.get("case_id") == case_id and oracle.get("label") == row["oracle_label"], "oracle record mismatch")
        _require(witness.get("case_id") == case_id and witness.get("coverage") == "COMPLETE", "witness record incomplete")
        _require(isinstance(row.get("predictions"), dict), "predictions required")
        for detector, prediction in row["predictions"].items():
            _require(detector in DETECTORS, "unknown detector")
            _require(prediction in LABELS | {"INDETERMINATE", "UNKNOWN"}, "prediction label")
        eligible.append(row)
    outputs = {}
    for detector in DETECTORS:
        counts = Counter()
        parent_cases = defaultdict(list)
        for row in eligible:
            actual = row["oracle_label"]
            predicted = row["predictions"].get(detector, "UNKNOWN")
            counts["eligible"] += 1
            parent_cases[row["parent_id"]].append(row["case_id"])
            if predicted == "UNKNOWN":
                counts["unknown"] += 1
            elif predicted == "INDETERMINATE":
                counts["abstain"] += 1
            elif actual == "AUTHORIZED" and predicted == "AUTHORIZED":
                counts["tp"] += 1
            elif actual == "UNAUTHORIZED" and predicted == "UNAUTHORIZED":
                counts["tn"] += 1
            elif actual == "UNAUTHORIZED" and predicted == "AUTHORIZED":
                counts["fp_unsafe_allow"] += 1
            else:
                counts["fn_unnecessary_deny"] += 1
        definite = sum(counts[k] for k in ("tp", "tn", "fp_unsafe_allow", "fn_unnecessary_deny"))
        _require(definite + counts["abstain"] + counts["unknown"] == counts["eligible"], "denominator mismatch")
        outputs[detector] = {
            **{k: counts[k] for k in ("eligible", "tp", "tn", "fp_unsafe_allow", "fn_unnecessary_deny", "abstain", "unknown")},
            "definite_denominator": definite,
            "coverage": definite / counts["eligible"] if counts["eligible"] else None,
            "definite_error_rate": (counts["fp_unsafe_allow"] + counts["fn_unnecessary_deny"]) / definite if definite else None,
            "independent_parent_count": len(parent_cases),
        }
    paired = {}
    for first, second in (("B0", "B2-S"), ("B1", "B2-S"), ("B2-R", "B2-S")):
        by_parent = defaultdict(list)
        for row in eligible:
            a, b = row["predictions"].get(first), row["predictions"].get(second)
            if a in LABELS and b in LABELS:
                by_parent[row["parent_id"]].append((a == row["oracle_label"], b == row["oracle_label"]))
        paired[f"{first}_vs_{second}"] = {
            "paired_parent_denominator": len(by_parent),
            "paired_case_denominator": sum(map(len, by_parent.values())),
            "parent_accuracy_difference": {
                parent: sum(int(b) - int(a) for a, b in cells) / len(cells)
                for parent, cells in sorted(by_parent.items())
            },
            "inference": "NOT_CALCULATED; freeze independent-parent sample and analysis plan first",
        }
    return {
        "schema": "chainguard-research-metrics-v1",
        "classification": "RESEARCH" if eligible else "NO_ELIGIBLE_RESEARCH_OBSERVATIONS",
        "input_case_count": len(rows),
        "eligible_case_count": len(eligible),
        "eligible_parent_count": len({r["parent_id"] for r in eligible}),
        "excluded": excluded,
        "positive_label": "AUTHORIZED",
        "provenance_review": "REQUIRED: matching digests and metadata do not themselves prove assessor independence or truthful effects",
        "false_positive_definition": "UNAUTHORIZED predicted AUTHORIZED",
        "false_negative_definition": "AUTHORIZED predicted UNAUTHORIZED",
        "detectors": outputs,
        "paired": paired,
    }


def benchmark_summary(trials):
    """Descriptive timing only; invalid correctness cells are retained and excluded."""
    _require(isinstance(trials, list), "trials must be a list")
    grouped = defaultdict(list)
    failed = []
    for trial in trials:
        _require(trial.get("cell_id") and isinstance(trial.get("elapsed_ns"), int) and trial["elapsed_ns"] >= 0, "benchmark trial")
        if trial.get("correctness") is not True:
            failed.append(trial)
        else:
            grouped[trial["cell_id"]].append(trial["elapsed_ns"])
    return {"cells": {key: {"valid_trials": len(values), "median_ns": statistics.median(values),
                             "iqr_ns": (statistics.quantiles(values, n=4, method="inclusive")[2]
                                        - statistics.quantiles(values, n=4, method="inclusive")[0]) if len(values) >= 2 else None,
                             "p95_ns": None if len(values) < 20 else sorted(values)[int(0.95 * (len(values) - 1))]}
                      for key, values in sorted(grouped.items())},
            "failed_or_unknown_correctness": failed,
            "timing_repetitions_are_security_samples": False}


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result = summarize(json.loads(args.input.read_text(encoding="utf-8")), args.input.parent)
    if args.output.exists():
        raise FileExistsError(args.output)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"eligible_cases={result['eligible_case_count']} excluded={len(result['excluded'])}")


if __name__ == "__main__":
    main()
