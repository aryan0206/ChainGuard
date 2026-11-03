# Final professor demonstration readiness — 4 November 2026

## Run checklist

1. Use ordinary Windows PowerShell 5.1 as the `Laptop` account, with this repository and its existing `.venv\Scripts\python.exe` available. Keep `$env:TEMP` outside the repository. M4/M5 also need the repository's local revision metadata for their internal configuration lookup. No environment rebuild or package installation is part of this run.
2. From the repository root, run exactly:

   ```powershell
   .\scripts\demo\Run-ProfessorDemo.ps1
   ```

   The script resolves the repository relative to itself, so the invocation also works by absolute script path from another working directory. It takes no arguments.
3. Record the printed `Evidence and logs:` directory and final `Run manifest:` path. Check `run-manifest.json` for `status: PASSED`, nine `PASSED` steps, and process exit code 0 for each Python step. `M6Q-retained-inspection` is an in-process read-only check with a recorded zero, not a child process or a fresh M6 run.
4. For a failure, inspect `failed_step`, that step's `logs/<name>.stdout.log` and `.stderr.log`, and the preserved partial artifacts. The runner stops on the first unexpected failure and creates a fresh GUID directory on the next invocation. Never rerun a fixed-output historical M6Q script to refresh the display.

The observed owner run at `C:\Users\Laptop\AppData\Local\Temp\chainguard-professor-7a5207b6676c45cfb0d952f264dad748` completed all nine steps on 3 November 2026. Its manifest and raw logs are retained. A prior `preflight-imports` failure remains separately preserved at `C:\Users\Laptop\AppData\Local\Temp\chainguard-professor-77ea0b0f01504e8c88d01b04115ee7b2`; it is not a successful run. A new execution has different paths, IDs, timestamps, signatures and hashes.

## What the runner actually checks

| Step | Input and state | Expected output/check |
| --- | --- | --- |
| Python preflight | Existing `.venv` interpreter; quoted `-c` import argument | Version and `IMPORTS_OK`, exit 0; required retained M6Q files exist. |
| M1 | Scripted SDK client, proxy, controlled tools | JSON success → intentional tool error → recovered success. |
| M2 | Authored synthetic replay fixtures | No tool execution; fixture count agrees; B2-R/B2-S agree at every valid proposal prefix. |
| M3 | New `m3/audit.sqlite` in this run | Three tool outcomes `succeeded,failed,succeeded`; durable non-release audit; `CLOSED_UNSEALED`. |
| M4 | New `m4/` directory and fixture keys | New audit DB, expected inventory, signed package, six-dimension internal offline inspection; monitor exited before verification. |
| Standalone M4 verifier | M4 package plus separate expected/config/public-key files | Independent child process reports `INSPECT`, six dimensions `PASS`, `fresh_submission: NOT_CHECKED`. |
| M5 | New `m5/acceptance.sqlite`, new M4 run and synthetic cases | First submission `ACCEPTED`; after restart duplicate `REJECTED/ALREADY_ACCEPTED`; synthetic campaign and engineering checks pass. |
| M6Q retained inspection | Existing `results/.../live_m6_current/` JSON and witnesses | Eight historical case statuses/checks passed, recorded offline and fresh-process inspection dimensions passed, accepted readback and duplicate reason match. No live M6 execution or fresh cryptographic verification occurs in this step. |

M1, M2, M3 and M4 are separate flows. M5 invokes its own M4 run after expectation registration; it does not accept the preceding standalone M4 package. The M6 trusted-host path exists, but this runner only reads its retained M6Q engineering qualification. The [output guide](PROFESSOR_DEMO_OUTPUT_GUIDE.md) gives the exact JSON fields and artifact walk-through.

## Persistence and safe repeatability

- Each launch selects a new GUID folder under `$env:TEMP` and refuses a pre-existing run path. M3 writes only its new audit DB. M4 writes its new audit DB, package, configuration, expected inventory and synthetic fixture signing keys. M5 writes a separate new registry and fresh M4 artifacts. Standalone M4 inspection reads its package. M6Q reads retained JSON/witness files and does not open or alter the historical acceptance registry.
- The runner captures child stdout and stderr as separate raw files, records the argument array, start/end times, exit codes, checks and artifact paths in an atomically replaced manifest, and preserves failures. The process launcher passes quoted array elements directly to Python under PowerShell 5.1; the import preflight succeeded in the owner run.
- The successful owner manifest shows M5's 32 synthetic cases, 16 engineering checks, first acceptance and duplicate rejection. These validate bounded engineering behavior in that run. Source artifact SHA-256 digests in its M4 configuration (11 entries) and the retained M6 assessor context (15 entries) matched the current inspected source files. This does not independently rerun historical M6 effects or establish future environment stability.
- Fresh controlled M1 and M2 child runs on 4 November 2026 passed with exit 0 under the normal account; their stdout/stderr are at `C:\Users\Laptop\AppData\Local\Temp\chainguard-priority5-efdb0112815c48a3b8559ef724b943f9`. M2 reported replay-only execution and B2 agreement. M3–M5 were not rerun in this audit: the retained successful owner run supplies their direct output, and their internal local revision lookup would conflict with this audit's no-Git-operation boundary. The full professor suite was not executed again for this audit.
- Keep each run folder private. M4 and M5 contain unencrypted **synthetic fixture private keys**. Share selected redacted reports only after review. Do not copy its files into `results/` or present a repeated run as an independent research sample.

## During the presentation

Show the console step order, the manifest, M1 error recovery, M2 replay-only marker and B2 equivalence, M4 standalone verifier dimensions, M5 accepted/duplicate statuses, and retained M6Q case and witness records. Explain that signed integrity, finding reproduction, observed tool effects and registry acceptance answer different questions. A valid signature does not prove the observation true; acceptance does not prove benign behavior; duplicate evidence rejection does not prevent replay of a tool call. For the historical M6Q records, show `case_results.json`, `witness_primary/host.jsonl`, `child.jsonl`, `sink.jsonl`, `offline_verification.json`, `fresh_process_reinspection.json` and `fresh_submission_readback.json` read-only. M6Q-08 is a separate pre-dispatch persistence-fault branch with no clean signed export.

Useful individual commands, from the repository root in the same approved environment, are:

```powershell
.\.venv\Scripts\python.exe -B -m chainguard.client
.\.venv\Scripts\python.exe -B -m chainguard.m2
```

M3, M4 and M5 need **new** explicit output paths on every standalone invocation; use the fresh-path command examples in the [output guide](PROFESSOR_DEMO_OUTPUT_GUIDE.md), not historical locations. Do not invoke `run_current_qualification.ps1` or its fixed-output M6Q helpers against the retained evidence. The normal professor command above already handles the safe sequence.

## Claim boundary

This is a controlled local engineering demonstration, not one continuous M1–M6 event stream and not a completed E01–E13 research study. E03 remains contract incomplete (missing separately verifiable task-level objective acknowledgment); E09 is inconclusive (three of five A3 development dimensions matched, two schema-first mismatches, six variants without frozen cases); E11 has passing engineering methods but no A3T/A4T research qualification or independent case population. No E01–E13 experiment is fully contract-qualified. See the [claims register](CLAIMS_REGISTER.md), [results ledger](RESULTS_LEDGER.md), and [documentation freshness audit](DOCUMENTATION_FRESHNESS_AUDIT.md).
