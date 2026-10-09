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

## Current scope and limitations

The live demonstrations use only public, non-release `echo` and `controlled_failure` calls. Sensitive-release and grant/revoke/use examples are replay qualification. These demonstrations establish bounded mediation, persistence, verification and acceptance behavior; they do not establish general detector superiority or real-world protection.

**M6 live lifecycle, E01–E13, held-out evaluation, external comparison and final cost/scaling measurements remain pending.** Evidence-label and external-baseline pin conflicts remain documented in the [protocol](docs/EVALUATION_PROTOCOL.md#authority-and-open-ambiguities).

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
