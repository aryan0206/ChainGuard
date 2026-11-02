"""Assessor-held synthetic M6 observation stream, separate from audit storage.

These records are local observations under the trusted host/child assumption;
they are not signed evidence and do not prove truth against a dishonest host.
"""

import json
import os
from pathlib import Path
from threading import Lock


class WitnessWriter:
    def __init__(self, directory, db_path):
        root = Path(directory).resolve()
        if root == Path(db_path).resolve() or root.is_file():
            raise ValueError("Witness directory must be separate from audit storage")
        root.mkdir(parents=True, exist_ok=True)
        self.host_path = root / "host.jsonl"
        self.child_path = root / "child.jsonl"
        # Exclusive creation prevents a new run from silently reusing observations.
        with self.host_path.open("xb"):
            pass
        with self.child_path.open("xb"):
            pass
        self._lock = Lock()
        self._sequence = 0

    def record(self, event):
        with self._lock:
            self._sequence += 1
            line = json.dumps({"sequence": self._sequence, **event},
                              sort_keys=True, separators=(",", ":")) + "\n"
            with self.host_path.open("ab") as stream:
                stream.write(line.encode("utf-8"))
                stream.flush()
                os.fsync(stream.fileno())
