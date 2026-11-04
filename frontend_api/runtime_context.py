"""Host-owned checkout identity for the current M6 revision contract."""

import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
REVISION_ENV = "CHAINGUARD_TRUSTED_CODE_REVISION"


def checkout_revision():
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                              check=True, capture_output=True, text=True, timeout=5).stdout.strip()
    if len(revision) != 40 or any(c not in "0123456789abcdef" for c in revision):
        raise RuntimeError("Checkout revision could not be established")
    return revision


def runtime_environment():
    environment = {**os.environ, "PYTHONUTF8": "1", REVISION_ENV: checkout_revision()}
    # Assessor capture paths/endpoints belong to each fresh local run.
    environment.pop("CHAINGUARD_ASSESSOR_CHILD_WITNESS", None)
    environment.pop("CHAINGUARD_ASSESSOR_SINK_ENDPOINT", None)
    return environment
