"""Unexecuted M6Q entry for a future owner-pinned, current-source run."""

import importlib.util
import os
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
OLD = ROOT / "results/completion_sprint_2026-11-02/H22-H25/qualify_live.py"
OUT = HERE / "live_m6_current"


def main() -> int:
    assessor_pin = os.environ.get("CHAINGUARD_ASSESSOR_REVISION_PIN", "")
    runtime_pin = os.environ.get("CHAINGUARD_TRUSTED_CODE_REVISION", "")
    if not re.fullmatch(r"[0-9a-f]{40}", assessor_pin) or runtime_pin != assessor_pin:
        raise RuntimeError("Separate assessor and runtime revision pins must be equal 40-hex values")
    if assessor_pin == "8b27b5a980a87887be66c409c5a6a31d415a3326":
        raise RuntimeError("Prior revision is not accepted for current-source qualification")
    if OUT.exists():
        raise RuntimeError("Current-source M6Q output already exists")
    spec = importlib.util.spec_from_file_location("chainguard_m6q_prior_harness", OLD)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load retained M6Q harness")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.PIN = assessor_pin
    module.OUT = OUT
    return module.main()


if __name__ == "__main__":
    raise SystemExit(main())
