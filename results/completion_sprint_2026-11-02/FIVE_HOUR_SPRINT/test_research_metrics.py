"""Arithmetic and provenance checks. Test vectors are not research observations."""

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from research_metrics import benchmark_summary, summarize


class ResearchMetricsTests(unittest.TestCase):
    @staticmethod
    def ref(base, name, value):
        raw = (json.dumps(value, sort_keys=True) + "\n").encode()
        (base / name).write_bytes(raw)
        return {"path": name, "sha256": hashlib.sha256(raw).hexdigest()}

    def test_development_rows_are_excluded(self):
        doc = {"schema": "chainguard-research-observations-v1", "cases": [
            {"case_id": "dev-1", "parent_id": "dev-parent", "classification": "DEVELOPMENT",
             "eligible": False, "exclusion_reason": "authored fixture", "oracle_label": "AUTHORIZED",
             "predictions": {"B0": "AUTHORIZED"}}]}
        result = summarize(doc)
        self.assertEqual(result["eligible_case_count"], 0)
        self.assertEqual(result["detectors"]["B0"]["eligible"], 0)
        self.assertEqual(len(result["excluded"]), 1)

    def test_confusion_coverage_unknown_and_parent_pairing(self):
        # Pure arithmetic vector; the digest and oracle flags are synthetic test data.
        cases = []
        for n, (parent, truth, b0, b2) in enumerate((
            ("p1", "AUTHORIZED", "AUTHORIZED", "AUTHORIZED"),
            ("p1", "UNAUTHORIZED", "AUTHORIZED", "UNAUTHORIZED"),
            ("p2", "AUTHORIZED", "UNAUTHORIZED", "INDETERMINATE"),
            ("p3", "UNAUTHORIZED", "UNKNOWN", "UNAUTHORIZED")), 1):
            cases.append({"case_id": f"arith-{n}", "parent_id": parent,
                          "classification": "RESEARCH", "eligible": True,
                          "oracle_source": "INDEPENDENT", "witness_status": "COMPLETE",
                          "oracle_label": truth, "predictions": {"B0": b0, "B2-S": b2}})
        with TemporaryDirectory() as temp:
            base = Path(temp)
            contract = self.ref(base, "contract.json", {"schema": "chainguard-frozen-experiment-contract-v1",
                                                        "case_ids": [r["case_id"] for r in cases]})
            for row in cases:
                row["oracle_record"] = self.ref(base, row["case_id"] + ".oracle.json",
                                                 {"case_id": row["case_id"], "label": row["oracle_label"]})
                row["witness_record"] = self.ref(base, row["case_id"] + ".witness.json",
                                                  {"case_id": row["case_id"], "coverage": "COMPLETE"})
            result = summarize({"schema": "chainguard-research-observations-v1",
                                "frozen_contract": contract, "cases": cases}, base)
        b0 = result["detectors"]["B0"]
        self.assertEqual((b0["tp"], b0["fp_unsafe_allow"], b0["fn_unnecessary_deny"], b0["unknown"]), (1, 1, 1, 1))
        self.assertEqual((b0["eligible"], b0["definite_denominator"], b0["independent_parent_count"]), (4, 3, 3))
        b2 = result["detectors"]["B2-S"]
        self.assertEqual((b2["tp"], b2["tn"], b2["abstain"], b2["eligible"]), (1, 2, 1, 4))
        pair = result["paired"]["B0_vs_B2-S"]
        self.assertEqual((pair["paired_parent_denominator"], pair["paired_case_denominator"]), (1, 2))
        self.assertEqual(pair["parent_accuracy_difference"]["p1"], 0.5)

    def test_research_without_oracle_or_witness_fails_closed(self):
        row = {"case_id": "x", "parent_id": "p", "classification": "RESEARCH", "eligible": True,
               "oracle_label": "AUTHORIZED", "predictions": {"B0": "AUTHORIZED"}}
        with TemporaryDirectory() as temp:
            base = Path(temp)
            contract = self.ref(base, "contract.json", {"schema": "chainguard-frozen-experiment-contract-v1",
                                                        "case_ids": ["x"]})
            with self.assertRaisesRegex(ValueError, "independent oracle"):
                summarize({"schema": "chainguard-research-observations-v1",
                           "frozen_contract": contract, "cases": [row]}, base)

    def test_benchmark_retains_failed_trials(self):
        result = benchmark_summary([{"cell_id": "c", "elapsed_ns": 10, "correctness": True},
                                    {"cell_id": "c", "elapsed_ns": 20, "correctness": True},
                                    {"cell_id": "c", "elapsed_ns": 1, "correctness": False}])
        self.assertEqual(result["cells"]["c"]["median_ns"], 15)
        self.assertEqual(result["cells"]["c"]["iqr_ns"], 5)
        self.assertIsNone(result["cells"]["c"]["p95_ns"])
        self.assertEqual(len(result["failed_or_unknown_correctness"]), 1)


if __name__ == "__main__":
    unittest.main()
