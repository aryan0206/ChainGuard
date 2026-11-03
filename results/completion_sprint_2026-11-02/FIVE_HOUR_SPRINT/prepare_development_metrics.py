"""Adapt retained H12 authored examples; every row is explicitly excluded."""

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / "H12-H16" / "e02_development_pair.json"
OUT = HERE / "development_metric_input.json"


def main():
    if OUT.exists():
        raise FileExistsError(OUT)
    raw = SOURCE.read_bytes()
    pair = json.loads(raw)
    if pair["status"] != "DEVELOPMENT_STAGED_ONLY":
        raise ValueError("Unexpected source class")
    rows = []
    for member in pair["members"]:
        release = next(row for row in member["replay"]["rows"] if row["call_id"] == member["call_id"])
        rows.append({
            "case_id": member["case_id"],
            "parent_id": "P-DEV-S4-REVOCATION-01",
            "classification": "DEVELOPMENT",
            "eligible": False,
            "exclusion_reason": "Authored staged label; no independent live commit/effect witness",
            "authored_label": member["development_authored_label"],
            "predictions": {finding["detector_id"]: finding["authorization"] for finding in release["findings"]},
            "b1_sha256": member["b1"]["sha256"],
        })
    OUT.write_text(json.dumps({"schema": "chainguard-research-observations-v1",
                               "classification": "DEVELOPMENT_INPUT_ONLY",
                               "source_sha256": hashlib.sha256(raw).hexdigest(),
                               "cases": rows}, indent=2) + "\n", encoding="utf-8")
    print(f"development_rows={len(rows)}")


if __name__ == "__main__":
    main()
