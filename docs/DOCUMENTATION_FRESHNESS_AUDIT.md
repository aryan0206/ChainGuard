# Documentation freshness audit — 4 November 2026

## Scope and authority

This audit compared the current repository, professor runner, retained owner-run manifest and logs, and research status authorities. It checked the 69 repository Markdown files by inventory and targeted status/path searches, then read the active guides and relevant historical snapshots in detail. The [Architecture Lock](ARCHITECTURE_LOCK.md) remains the architecture authority; the [results ledger](RESULTS_LEDGER.md), [claims register](CLAIMS_REGISTER.md), and [3 November status reconciliation](../results/STATUS_RECONCILIATION_2026-11-03.md) govern current evidence claims. No methodology or historical result was changed.

Detailed reads included the root [README](../README.md), [professor output guide](PROFESSOR_DEMO_OUTPUT_GUIDE.md), [old readiness audit](PROFESSOR_DEMONSTRATION_READINESS_2026-11-03.md), [local environment diagnosis](LOCAL_ENVIRONMENT_DIAGNOSIS.md), [repository map](FINAL_SUBMISSION_REPOSITORY_MAP_2026-11-03.md), [viva guide](VIVA_PREPARATION.md), [evaluation protocol](EVALUATION_PROTOCOL.md), [experiment matrix](EXPERIMENT_MATRIX.md), [charter](PROJECT_CHARTER.md), [threat model](THREAT_MODEL.md), [playbook](../ENGINEERING_PLAYBOOK.md), and focused E03/E09/E11 reports under `results/`. The [runner](../scripts/demo/Run-ProfessorDemo.ps1), relevant M3–M5 source and acceptance paths, qualification wrapper comments, and [paper source](overleaf-evaluation1/main.tex) were inspected for consistency. The 3 November repository map is a large historical file inventory, not a current execution guide.

## Findings and corrections

No critical incorrect active command or materially false active technical claim was found. In particular, the active runner and output guide do not instruct a historical database overwrite or fixed-output M6Q rerun.

| Severity | Exact location and finding | Action |
| --- | --- | --- |
| **Major** | [Viva preparation](VIVA_PREPARATION.md) repeatedly says live M6 is unimplemented and frames 216 tests as the current checkpoint. This is accurate for 9 October, but would materially misstate current implementation if used as a live script. | Added a dated status note directing presentation to the current runner, ledger and readiness checklist; retained original Evaluation-1 material. |
| **Major** | [Old readiness audit](PROFESSOR_DEMONSTRATION_READINESS_2026-11-03.md) says `Run-ProfessorDemo.ps1` does not exist and proposes parameters and an application demo module. These are superseded design statements. | Added a dated current-status note; kept the proposal as a historical record. The current script has no parameters and does not rerun live M6. Corrected one non-existent M2 fixture name in its presentation instruction to two names verified in fresh output. |
| **Major** | [Evaluation protocol](EVALUATION_PROTOCOL.md) and [experiment matrix](EXPERIMENT_MATRIX.md) retain older `PLANNED`, `NOT STARTED` and `CONFORMANCE PENDING` status cells, including E03, E06, E08, E09 and E11. They are frozen methodology/planning snapshots, not present-day results. | Added status notes pointing to the ledger and reconciliation; did not edit experiment definitions or old cells. |
| **Minor** | [Environment diagnosis](LOCAL_ENVIRONMENT_DIAGNOSIS.md) records a restricted-sandbox interpreter failure without the later successful normal-account owner run. | Added a dated success pointer while preserving the original account/ACL diagnosis. |
| **Minor** | [Repository map](FINAL_SUBMISSION_REPOSITORY_MAP_2026-11-03.md) contains a pre-runner demonstration readiness verdict and proposed/absent runner material in a dated inventory. | Added a current-status pointer; preserved the large historical inventory. |
| **Historical** | [Completion sprint](COMPLETION_SPRINT_2026-11-02.md), [viva guide](VIVA_PREPARATION.md), [old readiness audit](PROFESSOR_DEMONSTRATION_READINESS_2026-11-03.md), and focused `results/` reports retain as-of statuses and original execution findings. | No results, counts, labels or evidence rewritten. Current-status notes or later addenda identify the governing interpretation. |

The root README and current output guide agree on the active command, existing `.venv`, separate M1–M5 runs, M5's internal M4 run, read-only retained M6Q, external fresh output folder, private synthetic fixture keys, and incomplete E01–E13 study. The README gained a link to the operational checklist; no current output-guide correction was needed. The old readiness audit's `revocation_boundary_01` example did not match current M2 output, so its presentation instruction now names the verified `order-grant-then-revoke` and `order-revoke-then-new-grant` fixtures.

## Current research classification checked

- **E03:** five-call/two-parent pilot and four descriptive detector-evaluable rows; one schema-rejected control. Separate verifiable task-level client objective acknowledgment is missing; the proposed larger cohort is unapproved. Zero fully qualified research cases.
- **E09:** five A3 development cells, three expected-dimension matches and two retained schema-first mismatches. The other six variant contracts/support are absent. Inconclusive, zero research cases.
- **E11:** 14 passing existing lifecycle engineering methods and retained acceptance/restart/duplicate readback. A3T/A4T research support and independent population/oracle remain absent. Zero research cases.
- **Overall:** none of E01–E13 has a fully contract-qualified research result. E08's narrow ten-case reference conformance does not establish a paired comparative workflow study. M6Q's eight retained cases are bounded engineering qualification, not E06/E07 research denominators.

The README, claims register, ledger and output guide use these distinctions consistently. The current runner's `PASSED` result is a bounded engineering status. The manifest checks retained M6Q statuses; it does not independently regenerate or reverify its historical cryptographic evidence.

## Demonstration reliability evidence

The retained owner run `C:\Users\Laptop\AppData\Local\Temp\chainguard-professor-7a5207b6676c45cfb0d952f264dad748` has a readable `run-manifest.json` with nine `PASSED` steps, all Python child exits 0, separate stdout/stderr files, and external artifact paths. M4 standalone inspection reported all six dimensions `PASS`. M5 reported 32 passing synthetic cases, 16 engineering checks, initial `ACCEPTED`, and restarted duplicate `REJECTED/ALREADY_ACCEPTED`. The earlier failed preflight run is preserved separately. Current source SHA-256 matched the 11 source-artifact digests in that M4 configuration and the 15 digests in the retained M6 assessor context; this is a read-only source consistency check, not a new live qualification.

Fresh controlled M1 and M2 executions on 4 November 2026 exited 0 in the normal account; their logs are under `C:\Users\Laptop\AppData\Local\Temp\chainguard-priority5-efdb0112815c48a3b8559ef724b943f9`. M1 retained the intended error/recovery sequence; M2 marked `REPLAY_ONLY_NO_TOOL_EXECUTION` and B2 equivalence passed. The full runner and M3–M5 were not rerun in this audit. Its M4/M5 paths use an internal repository revision lookup, while this task prohibits Git operations. Historical M6Q was only read. These observations support a controlled repeat on the owner's laptop, but do not guarantee a new run will pass under changed environment or source.

## Unresolved and deferred

- The current runner is a suite of separate M1–M5 demonstrations and retained M6Q inspection. It is not a fresh integrated live M6 exercise. A reusable fresh-output M6 qualification would need separate owner authorization, independently pinned inputs and a safe harness; it was not added here.
- The fixed-output historical M6Q wrapper and preserved `live_m6_current` registry must remain untouched. The runner's M6Q step checks expected recorded statuses, not fresh signatures or assessor observations.
- No verified clean-install or public-checkout setup exists. Demonstration reliability currently depends on the owner's existing `.venv`, normal-account access, `$env:TEMP`, local revision metadata and preserved M6Q files.
- The older readiness audit's M2 example fixture name is unsupported by current M2 output; its dated status note redirects readers, while the original audit text remains intact for provenance.

### Priority 6 paper corrections

The [IEEE Evaluation-1 source](overleaf-evaluation1/main.tex) is an earlier checkpoint. Its abstract, scope, limits and lifecycle table still say live M6 is pending/unimplemented, while the repository now has bounded current-source M6Q engineering qualification. Its 216-test and 26-record M4 figures are historical Evaluation-1 figures, not the latest professor-run totals or research-case denominators. A Priority 6 revision should date and source each engineering count, describe the implemented M6 path and M6Q limits, and reconcile E03/E09/E11 and E08 with the current ledger. It must retain the no-fully-qualified-E01–E13 conclusion and must not promote development or engineering outcomes to research results. No paper text was changed here.

## Assessment

The active README and output guide are consistent with the inspected runner and retained owner run. The newly added [operational checklist](FINAL_PROFESSOR_DEMONSTRATION_READINESS.md) is the current presentation entry point. Historical guides now signal their date and redirect to current status. Remaining gaps are research qualification, clean-environment reproducibility, and paper synchronization; they do not turn the observed owner-run result into a complete research demonstration.

Final checks: all 1,491 relative Markdown links found across the 71 current repository Markdown files resolved locally. The runner parsed without errors in the available PowerShell 7.6.5 parser; the preserved owner execution supplies the Windows PowerShell 5.1 runtime evidence. A SHA-256 comparison against the pre-edit inventory of 407 repository `.md`, `.ps1`, `.py`, `.tex`, `.json` and `.sqlite` files found only seven changed Markdown files and these two new Markdown files; no file was removed. No application source, runner, virtual environment, database, research evidence or paper file changed. No Git command was issued.
