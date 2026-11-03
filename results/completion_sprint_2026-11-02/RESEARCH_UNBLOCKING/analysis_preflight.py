"""Development-only analysis preflight; never emits an E01-E13 research result."""

import hashlib
import json
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEV = HERE.parent / "H12-H16"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    pair = json.loads((DEV / "e02_development_pair.json").read_text(encoding="utf-8"))
    e13 = json.loads((DEV / "e13_postrun_analysis.json").read_text(encoding="utf-8"))
    if pair["status"] != "DEVELOPMENT_STAGED_ONLY" or e13["status"] != "DEVELOPMENT_STAGED_ONLY":
        raise ValueError("Refusing to process an unclassified source")
    members = pair["members"]
    if len(members) != 2 or not pair["byte_equal"]:
        raise ValueError("Expected one verified two-member development pair")
    b1_hashes = []
    labels = []
    for member in members:
        path = DEV / member["b1"]["file"]
        if not path.is_file() or path.stat().st_size != member["b1"]["bytes"]:
            raise ValueError(f"Missing or wrong-length B1 input: {path}")
        actual = digest(path)
        if actual != member["b1"]["sha256"]:
            raise ValueError(f"B1 digest mismatch: {path}")
        b1_hashes.append(actual)
        labels.append(member["development_authored_label"])
    if len(set(b1_hashes)) != 1:
        raise ValueError("B1 inputs are not byte-identical")
    counts = Counter(labels)
    if set(counts) != {"AUTHORIZED", "UNAUTHORIZED"}:
        raise ValueError("Expected opposite authored development labels")
    bound = min(counts["AUTHORIZED"], counts["UNAUTHORIZED"])
    result = {
        "classification": "DEVELOPMENT_ANALYSIS_PREFLIGHT_ONLY",
        "research_observations": 0,
        "eligible_research_parent_denominator": 0,
        "research_confidence_interval": None,
        "development_group_id": pair["group_id"],
        "development_pair_member_count": len(members),
        "identical_b1_sha256": b1_hashes[0],
        "development_authored_labels": dict(counts),
        "authored_label_group_bound": bound,
        "bound_is_research_result": False,
        "e13_development_pair": {
            "original": e13["original_case_id"],
            "transformed": e13["transformed_case_id"],
            "compared_rows": e13["compared_rows"],
            "b1_equal": e13["b1_input_bytes_equal_all_rows"],
            "reference_equal_after_renaming": e13["supporting_event_ids_equal_after_renamed_prefix"],
        },
        "exclusions": [
            "All development-authored labels excluded from research authorization denominators",
            "No independent live control/commit/effect witness",
            "No validation or held-out parent",
        ],
    }
    (HERE / "analysis_preflight_development.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    # A small rendering smoke check; the figure is explicitly barred from the report.
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="600" height="160" '
        'viewBox="0 0 600 160">'
        '<rect width="600" height="160" fill="white"/>'
        '<text x="20" y="42" font-family="sans-serif" font-size="19">'
        'DEVELOPMENT ONLY — authored E02 pair</text>'
        '<text x="20" y="78" font-family="sans-serif" font-size="15">'
        f'Identical B1 input; opposite authored labels; group bound {bound}</text>'
        '<text x="20" y="112" font-family="sans-serif" font-size="15">'
        'Eligible research parents: 0; no confidence interval</text>'
        '</svg>\n'
    )
    (HERE / "analysis_preflight_development.svg").write_text(svg, encoding="utf-8")
    print(json.dumps({"status": "DEVELOPMENT_ONLY_PASS", "research_observations": 0, "authored_bound": bound}))


if __name__ == "__main__":
    main()
