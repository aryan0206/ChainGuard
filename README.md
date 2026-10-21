# ChainGuard

ChainGuard is a controlled MCP testbed for studying how retained history affects security decisions and how the evidence supporting those decisions can be verified.

The Model Context Protocol (MCP) connects AI applications to tools. A tool call can look harmless on its own, while its meaning depends on earlier access or permission changes. We compare ways of representing that history without treating the system's own findings as ground truth.

## Objectives

- Compare current-event, unordered-history and ordered-history representations under a fixed policy.
- Keep detector findings and dispatch decisions separate from independent oracle assessment.
- Persist audit records, verify signed evidence and check complete expected-run submissions.

## How it works

A scripted MCP client sends requests through a local stdio proxy to a controlled server. In the audited path, the controller admits a supported call only after its required audit records are durably committed. The result is recorded separately after execution.

**B0** evaluates the current normalized proposal and static policy without history. **B1** also receives counts of prior semantic facts, but not their ordering or active-state transitions. **B2** uses ordered exposure and grant/revoke/use state: B2-R reconstructs the prefix, while B2-S applies incremental transitions. Their agreement checks implementation consistency; independent oracle observations are needed to assess correctness.

M3 provides durable, unsealed records. M4 creates separate SHA-256 chained streams with an ECDSA P-256/SHA-256 signed closure and offline verification. M5 checks the complete independently expected run and records acceptance durably, rejecting an accepted identity again after a process restart. Signatures authenticate commitments, not raw-event truth; acceptance does not certify benign behavior or prevent MCP tool replay.

## Evaluation-1 implementation

M1–M5 and the Phase 2 workflow/oracle foundation are committed in checkpoint **5d00057**. The [results ledger](docs/RESULTS_LEDGER.md) records:

| Milestone | Implemented scope | Recorded passing tests |
| --- | --- | ---: |
| M1 | Real client/proxy/server mediation | 12 |
| M2 | Replay representations and independent fixture oracle | 41 |
| M3 | Durable non-release audit staging | 40 |
| M4 | Signed evidence, offline inspection and persistence-gate repair | 67 |
| M5 | Complete expected-run acceptance and duplicate rejection | 27 |
| Phase 2 | Independent development workflow/observation qualification | 29 |

**187 M1–M5 tests + 29 foundation tests = 216 recorded passing regression/qualification tests across separately executed suites.** This is not 216 independent research experiments or a new 216-test project-wide discovery run. Package campaign cases are reported separately.

## M6.4 bounded engineering status — 21 October 2026

All four M6.4 technical gates PASS within the tested live workflow: (1) an exact canonical evidence contract and fixed signing-byte/digest vector, where structural validity is separate from cryptographic verification; (2) clean-close, trusted count/head snapshot reconciliation and signed export; (3) offline chain, pinned-signature, assessor-context, lifecycle and finding checks with mutation tests; and (4) durable complete-run acceptance. The Gate 4 regression confirms full expectation readback before `M6Host.open_task`, exact intended signer-pin readback after a post-commit lost acknowledgement, and duplicate rejection after registry restart. It does not establish a global runtime preregistration gate.

The [engineering log](docs/SPIKE_LOG.md#m64-four-gate-technical-completion--21-october-2026), [results ledger](docs/RESULTS_LEDGER.md) and [claims register](docs/CLAIMS_REGISTER.md) separate recorded runs and review decisions from the earlier final read-only audit, which ran no tests. A subsequent local M6.4 readiness audit passed 28 focused tests in 58.395s and 466 full-discovery tests in 670.885s; these are engineering tests, not independent research experiments. Gate 3/4 verifier and test files are new in this M6.4 change set. The earlier combined-suite child-startup timeout remains unexplained, and shared test setup remains a test-isolation follow-up.

## Current scope and limitations

The Evaluation-1 M4 demonstration uses public, non-release `echo` and `controlled_failure` calls. M6.3/M6.4 add controlled synthetic live grant/revoke/release and evidence tests; independent final-workflow source/sink qualification is still pending. These engineering checks do not establish general detector superiority or real-world protection. Trust inputs must be supplied by the assessor; signatures authenticate commitments, not observation truth or downstream tool behavior. Registry rollback and directory-entry crash durability remain outside the established claims.

**Final M6 qualification, E01–E13, held-out evaluation, external comparison and final cost/scaling measurements remain pending.** Evidence-label and external-baseline pin conflicts remain documented in the [protocol](docs/EVALUATION_PROTOCOL.md#authority-and-open-ambiguities).

## Run the demonstration

From the repository root in PowerShell, using the existing approved `.venv`:

```powershell
.\.venv\Scripts\python.exe -B -m chainguard.client
.\.venv\Scripts\python.exe -B -m chainguard.m4
```

The first command demonstrates mediation and success/error/success. The second runs the signed-evidence demonstration using an external temporary directory, which it removes after printing the result. Retained-package verification and M5 instructions remain in the [historical engineering record](docs/SPIKE_LOG.md#historical-engineering-readme-at-checkpoint-5d00057).

## Project documentation

- [Architecture lock](docs/ARCHITECTURE_LOCK.md), [threat model](docs/THREAT_MODEL.md) and [engineering playbook](ENGINEERING_PLAYBOOK.md).
- [Evaluation protocol](docs/EVALUATION_PROTOCOL.md), [experiment matrix](docs/EXPERIMENT_MATRIX.md), [results ledger](docs/RESULTS_LEDGER.md) and [claims register](docs/CLAIMS_REGISTER.md).
- [Evaluation-1 report source](docs/overleaf-evaluation1/main.tex) and [figure documentation](docs/overleaf-evaluation1/figures/README.md). The original supplied proposal is historical; this is the current Evaluation-1 report.
- [Viva preparation](docs/VIVA_PREPARATION.md), [adversarial findings](docs/ADVERSARIAL_FINDINGS.md) and [engineering history](docs/SPIKE_LOG.md).
