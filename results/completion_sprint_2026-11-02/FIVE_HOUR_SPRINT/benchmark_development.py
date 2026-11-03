"""Development-only B2-R/B2-S timing and retained-state instrumentation."""

from dataclasses import asdict
from datetime import datetime
import hashlib
import json
from pathlib import Path
import platform
from statistics import median
import sys
from time import perf_counter_ns
import tracemalloc

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from workflow_fixtures import CONTRACTS  # noqa: E402
from chainguard.detectors import B2Reference, B2Streaming, equivalent  # noqa: E402
from chainguard.m2 import ReplayLedger  # noqa: E402
from chainguard.semantics import Policy, extract_current  # noqa: E402


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False) + "\n").encode("utf-8")


def deep_size(value, seen=None):
    """Approximate reachable Python object bytes; excludes interpreter/allocator overhead."""
    if seen is None:
        seen = set()
    if id(value) in seen:
        return 0
    seen.add(id(value))
    size = sys.getsizeof(value)
    if isinstance(value, dict):
        return size + sum(deep_size(k, seen) + deep_size(v, seen) for k, v in value.items())
    if isinstance(value, (list, tuple, set, frozenset)):
        return size + sum(deep_size(x, seen) for x in value)
    if hasattr(value, "__dict__"):
        return size + deep_size(vars(value), seen)
    slots = getattr(type(value), "__slots__", ())
    if isinstance(slots, str):
        slots = (slots,)
    return size + sum(deep_size(getattr(value, name), seen) for name in slots if hasattr(value, name))


def process_working_set_bytes():
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes
    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
    counters = Counters()
    counters.cb = ctypes.sizeof(counters)
    ctypes.windll.kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    ctypes.windll.psapi.GetProcessMemoryInfo.argtypes = (
        wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD)
    ctypes.windll.psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    handle = ctypes.windll.kernel32.GetCurrentProcess()
    ok = ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb)
    return int(counters.WorkingSetSize) if ok else None


def main():
    label = "_revision" if __import__("os").environ.get("CHAINGUARD_E12_RETRY") == "1" else ""
    out = HERE / f"e12_development_instrumentation{label}.json"
    input_dir = HERE / f"e12_development_inputs{label}"
    if out.exists() or input_dir.exists():
        raise FileExistsError("Development benchmark evidence already exists")
    input_dir.mkdir()
    tracemalloc.start()
    rows = []
    for contract in CONTRACTS:
        raw = encode(asdict(contract))
        input_path = input_dir / f"{contract.workflow_id}.json"
        input_path.write_bytes(raw)
        policy = Policy(contract.resources)
        ledger = ReplayLedger(policy)
        streaming = None
        for entry in contract.journal:
            facts = ledger.accept(entry)
            if entry.kind == "TASK_START":
                streaming = B2Streaming(entry.task_id, policy)
            for fact in facts:
                streaming.observe(fact)
            if entry.kind != "PROPOSAL":
                continue
            current = extract_current(entry.body, policy)
            history = tuple(ledger.tasks[entry.task_id]["history"])
            before_working = process_working_set_bytes()
            t0 = perf_counter_ns()
            reconstructed = B2Reference(entry.task_id, policy).evaluate(current, history, entry.event_id)
            t1 = perf_counter_ns()
            retained = streaming.evaluate(current, entry.event_id)
            t2 = perf_counter_ns()
            after_working = process_working_set_bytes()
            _, traced_peak = tracemalloc.get_traced_memory()
            rows.append({
                "workflow_id": contract.workflow_id,
                "call_id": entry.call_id,
                "parent_class": "DEVELOPMENT_FIXTURE",
                "input_file": str(input_path.relative_to(HERE)),
                "input_sha256": hashlib.sha256(raw).hexdigest(),
                "history_fact_count": len(history),
                "b2_reference_elapsed_ns": t1 - t0,
                "b2_streaming_elapsed_ns": t2 - t1,
                "streaming_retained_python_bytes_approx": deep_size(streaming),
                "process_working_set_before_bytes": before_working,
                "process_working_set_after_bytes": after_working,
                "tracemalloc_process_peak_bytes": traced_peak,
                "b2_equivalent": equivalent(reconstructed, retained),
                "b2_reference": asdict(reconstructed),
                "b2_streaming": asdict(retained),
            })
    report = {
        "classification": "DEVELOPMENT_INSTRUMENTATION_ONLY",
        "research_observations": 0,
        "research_workload_cells": 0,
        "started_source": "tests/workflow_fixtures.py existing nine authored development contracts",
        "created_local": datetime.now().astimezone().isoformat(),
        "python": platform.python_version(),
        "os": platform.platform(),
        "source_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                          for name in ("tests/workflow_fixtures.py", "chainguard/detectors.py",
                                       "chainguard/m2.py", "chainguard/semantics.py")},
        "measurement_boundaries": "perf_counter_ns around B2Reference reconstruction/evaluate then B2Streaming evaluate; stream.observe time excluded",
        "memory_limitations": "deep_size is approximate reachable Python state; working set and tracemalloc are whole-process and include allocator/other activity",
        "repetitions_per_cell": 1,
        "statistical_inference": "NONE",
        "rows": rows,
        "correctness_failures": [f"{r['workflow_id']}:{r['call_id']}" for r in rows if not r["b2_equivalent"]],
        "descriptive_median_reference_ns": median(r["b2_reference_elapsed_ns"] for r in rows),
        "descriptive_median_streaming_ns": median(r["b2_streaming_elapsed_ns"] for r in rows),
    }
    out.write_bytes(encode(report))
    print(f"development_prefixes={len(rows)} b2_disagreements={len(report['correctness_failures'])} research_cells=0")
    return 0 if not report["correctness_failures"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
