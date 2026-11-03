"""Verify pinned reference bytes against GitHub API blob IDs; no Git command."""

from datetime import datetime
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "e08_reference"
PIN = "3dd9690b5b6f9c4ef385289714b314d13f6ad9a1"
BLOBS = {
    "prototype/pep/enforcer.py": "ea565e0f7b33f10db2c230d5439427659ad3cf74",
    "prototype/pep/label_tracker.py": "2f1fe2662513519a68962227abd6c8802a86d5b9",
    "prototype/pep/rules.py": "1471e97a87ecd770912de2d025ed73b85e9e96af",
    "prototype/datatypes.py": "bf0d31c40d4a90298c1ddaa935912ed06f068186",
    "LICENSE": "5d56b657936e58acf198b5ac14e374d25b954b2f",
}


def main():
    rows = []
    for name, expected in BLOBS.items():
        raw = (SOURCE / name).read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        rows.append({"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                     "expected_git_blob_sha1": expected, "actual_git_blob_sha1": actual,
                     "exact_blob_match": actual == expected})
    report = {"schema": "chainguard-e08-reference-provenance-v1",
              "repository": "https://github.com/wilesanGH/mcp-pep-agent-security",
              "approved_commit": PIN,
              "source": "GitHub connector read-only fetch_file at approved commit; fetch_commit confirmed commit identity",
              "retrieved_local": datetime.now().astimezone().isoformat(),
              "rows": rows, "all_exact": all(r["exact_blob_match"] for r in rows),
              "execution_status": "SOURCE_PROVENANCE_ONLY; NO DIFFERENTIAL CONFORMANCE OR E08 COMPARISON"}
    out = HERE / "e08_reference_provenance.json"
    if out.exists():
        raise FileExistsError(out)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"exact_blobs={sum(r['exact_blob_match'] for r in rows)}/{len(rows)}")
    return 0 if report["all_exact"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
