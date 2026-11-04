"""Fixed demo worker, launched with the existing runtime's Python interpreter."""

import asyncio
import json
from pathlib import Path
import sys


def execute(scenario, directory):
    if scenario == "live-authorization":
        from frontend_api.live_demo import execute as execute_live
        return execute_live(directory)
    if scenario == "mediation":
        from chainguard.client import exercise
        return {"report": asyncio.run(exercise()), "evidence": None}
    if scenario == "signed-evidence":
        from chainguard.m4 import execute_demo
        report = execute_demo(directory)
        # Public evidence only. Keys and assessor files never leave this workspace.
        package = json.loads((Path(directory) / "evidence.json").read_text())
        return {"report": report, "evidence": {
            "package": package,
            "verification": report["offline_verification"],
            "acceptance": {"status": "NOT_CHECKED", "reason": "M4 inspection does not perform M5 fresh submission."},
        }}
    raise ValueError("Unsupported scenario")


if __name__ == "__main__":
    print(json.dumps(execute(sys.argv[1], sys.argv[2]), ensure_ascii=True))
