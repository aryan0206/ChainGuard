"""Recompute the frozen E03 pilot's descriptive counts from linked evidence."""

import json
from pathlib import Path

from research_metrics import summarize

HERE = Path(__file__).resolve().parent
source = HERE / "e03_metric_input.json"
target = HERE / "e03_pilot_metrics.json"
if target.exists():
    raise FileExistsError(target)
result = summarize(json.loads(source.read_text(encoding="utf-8")), HERE)
target.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(f"eligible={result['eligible_case_count']} excluded={len(result['excluded'])}")
