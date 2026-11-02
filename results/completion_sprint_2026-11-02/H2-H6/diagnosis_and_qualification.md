# H2–H6 startup diagnosis and live M6 qualification gate — 2 November 2026

## Part A: startup diagnosis

Inspection start was before the first recorded local clock read at 16:51:34.2164478 +05:30. Targeted execution ran 16:52:54.1424353–16:53:28.8354296 +05:30. No full-suite rerun occurred. This report makes no source, test, timeout, architecture, or protocol change.

The retained H0–H2 full discovery ran 466 tests in 1045.989 unittest seconds (1054.609 wall seconds), exit 1, with one setup error in `RuntimeTests.test_worker_rejects_auxiliary_label_with_tool_call_frame`. The traceback ends in `HostTask._startup()` waiting for a response in `queue.get(timeout=15)`; `HostTask.__init__` reports `M6 task did not become ready`. The tested rejection body never ran. The same test passed alone in H0–H2 (1 test, exit 0). The focused M6.4 run passed on retry; the first focused attempt ended with Windows exit -1073741510 and no unittest summary.

The startup path is `M6Host.open_task` -> `live_configuration` -> `HostTask` worker -> `LiveAuditSession` -> `LiveAuthorizationTask` -> `subprocess.Popen([sys.executable, '-u', '-m', 'chainguard.m6_controlled_server'], cwd=ROOT, env={**os.environ, 'PYTHONUTF8':'1'}, pipes for stdin/stdout/stderr)` -> `server/discover` and `tools/list` over stdio. Each handshake response has a 15-second wait. The stdout reader feeds a one-element response queue. The stderr reader retains only JSON records with controlled-server/local-sink components; other child stderr is discarded. The traceback cannot identify which handshake message stalled or whether the child was initializing, blocked, or resource-starved. There is no socket/port in this path.

`RuntimeTests.setUp` creates a fresh `TemporaryDirectory` and UUID-based task/session/monitor identity. `stop_task` is registered as cleanup only after `open_new_task` succeeds; on this setup failure the worker's own `finally` block closes audit storage, closes stdin, waits up to five seconds for the child, kills it if required, and joins readers. Read-only `Get-Process python` checks at approximately 16:51 and 16:54 found no Python process. A more detailed WMI process-command-line query returned Access denied. These later snapshots do not establish that no transient process leak occurred during full discovery. The temporary directories visible from the interrupted H0–H2 focused attempt are separate from this full-suite setup failure. No shared fixed temporary database name or TCP port was found.

The full run took 1045.989 unittest seconds versus the historical 670.885-second 466-pass run. This supports a slower execution environment but does not prove CPU, filesystem, antivirus, or process contention at the failed handshake. The likely immediately preceding test in unittest's name order, `test_timeout_and_malformed_response_halt_without_replay`, deliberately halts/reopens tasks and exercises response handling. A targeted two-test command ran that test followed by the failed case: both passed (2 tests in 30.213 unittest seconds, 34.591 wall seconds, exit 0). This one pass weakens a deterministic two-test ordering explanation; it cannot rule out cumulative suite state or intermittent load.

### Plausible causes, ranked by present support

1. Intermittent child startup delay or scheduler/filesystem contention crossing the fixed 15-second handshake wait. Supported by the timeout location, isolated/targeted passes, earlier recorded startup timeouts, and slower full run; the specific resource is unmeasured.
2. Cumulative full-suite process/thread/resource pressure or a longer test-order interaction. The failing test ran late in discovery; the immediate predecessor pair passed. No contemporaneous process, handle, CPU, or disk trace exists.
3. Child process startup exception or protocol stall hidden by filtered stderr. Possible because non-JSON stderr is discarded, but an early child exit would normally produce EOF rather than an empty response queue. No child stderr was retained for the failure.
4. Temporary-directory collision or port collision. Low support: UUID/temporary paths and stdio transport; no relevant port.

**Diagnosis: unresolved.** The smallest discriminating next experiment is a targeted run of the M6 runtime module under a lightweight external process/CPU/child-stderr observer, preserving child launch and handshake timings without changing source, tests, or timeout. Compare a fresh isolated module run with the same module after its preceding discovery modules if the first remains clean. Do not use a passing retry to relabel the failed full run.

## Part B: qualification gate

No live qualification case was executed. `M6Host.open_task` unconditionally calls `live_configuration()`, and that function executes `subprocess.run(['git', 'rev-parse', 'HEAD'])`. The owner's no-Git boundary and no-source-edit boundary therefore block an unmodified live run. This dependency was discovered after the targeted unittest command; that test indirectly exercised the application's internal Git call even though no Git shell command was issued by the operator. It is recorded here rather than hidden. No further execution was attempted after discovery.

The present controlled child emits `tool_received` and `sink_arrival` JSON events on stderr. The sink event provides destination and `payload_byte_count`, not exact received bytes or a digest. `HostTask.child_events` is an in-memory copy mediated by the host; the current API does not expose a separately captured assessor-held raw stderr stream. A driver could retain raw requests, control Future completions, child-event copies, and task responses separately from SQLite, but that would still leave sink-byte authenticity and independent reservation-commit witnesses below the Architecture Lock Section 18 final qualification contract. A signed clean-close package and offline verifier result can be produced only after an actual eligible run; none exists in this H2–H6 directory.

Planned case IDs and prewritten expectations are in `qualification_plan.json`; each is `BLOCKED`, with no observation asserted. No E01–E13 experiment was run or populated. H6–H9 should resolve the explicit no-Git runtime conflict and independent witness collection design with the owner before attempting a live claim, while preparing an evidence-aligned demo plan that does not convert internal tests into independent truth.

## Artifact index

- `targeted.run.json`: exact diagnostic command, local start/end, wall duration, exit code, raw log paths.
- `targeted.stderr.log`: raw verbose unittest output (2 passed).
- `targeted.stdout.log`: empty; unittest output went to stderr.
- `run_targeted.ps1`: execution/metadata wrapper, not application or test source.
- `qualification_plan.json`: frozen proposed case IDs/expectations; blocked, unexecuted.
- `diagnosis_and_qualification.md`: this read-only diagnosis and status report.
- H0–H2 inputs: `../H0-H2/full.stderr.log`, `../H0-H2/full.run.json`, `../H0-H2/isolated.stderr.log`, `../H0-H2/isolated.run.json`, and the focused-attempt files.
