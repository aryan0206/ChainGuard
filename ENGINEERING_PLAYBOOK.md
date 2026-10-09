# ChainGuard Engineering Playbook

Version 1.1 — 7 October 2026.

## Authorization snapshot — 7 October 2026

Chronology clarification, 9 October 2026: the original closed implementation/dependency wording records the 7 October architecture-lock stage. Later explicit owner instructions authorized the recorded M1–M5 milestones and Phase 2 foundation; their decisions and evidence are retained in [the engineering history](docs/SPIKE_LOG.md#historical-engineering-readme-at-checkpoint-5d00057). Those later authorizations do not weaken Architecture v1.1 or grant blanket approval for dependencies, M6 or other work. The initial 9 October documentation cleanup excluded commits and pushes; that task-specific restriction does not override later explicit owner authorization.

Research direction and mandatory scope are approved. The owner explicitly declared [ARCHITECTURE LOCKED — ChainGuard Architecture v1.1](docs/ARCHITECTURE_LOCK.md), retaining ECDSA P-256 and SHA-256. This task records lock status only. Application code, dependency installation, experiments, commit, push and publication remain outside the current authorized task.

The pre-existing local environment is not evidence that packages or application behavior have been approved or verified. Do not alter it during this documentation milestone.

## Approval gates

| Gate | State at the 7 October lock stage | What opens it |
| --- | --- | --- |
| Research direction and mandatory scope | Approved | Owner approval already received |
| Final contract synchronization | Completed in version 1.1 | Owner-directed documentation pass |
| Formal architecture lock | Approved — 7 October 2026 | Explicit owner declaration: ARCHITECTURE LOCKED — ChainGuard Architecture v1.1 |
| Application implementation | Closed | Subsequent explicit owner instruction |
| Dependency installation | Closed | Explanation and approval of needed packages, compatible pins and transitives |
| Optional extensions or material architecture changes | Closed | Specific owner approval after impact assessment |
| Milestone commit | Pending student verification | Student verifies the reviewed milestone |
| Push/publication | Not authorized in this task | Owner authorization |

## Implementation sequence after authorization

These are passed milestones, not calendar or mark promises. First obtain explicit implementation authorization and approval of compatible dependency pins. Architecture lock alone does not open either gate.

1. **Prove MCP transport first:** scripted client -> stdio proxy -> controlled tool, modern discovery/per-request metadata, request/result correlation, success/error and documented subset. Do not jump directly into detectors or cryptography.
2. **Context and observation boundaries:** trusted task attachment, FIFO controls/proposals, fixture-controlled oracle observations and downstream-versus-monitor restart containment. Prewrite demonstration contracts.
3. **Policies:** frozen normalization, B0/B1/B2-S, exact H_t and independent B2-R equivalence checks. Shadows cannot control execution or actual consumption.
4. **Persistence/reservation:** typed SQLite appends, trusted incremental count/head, all-mode audit failure handling and atomic reservation. Normal observation MUST NOT bypass authorization; only the committed default-disabled synthetic local-sink override can forward unauthorized synthetic proposals.
5. **Sealing/verification:** canonical byte vectors, exact-snapshot reconciliation, P-256 closure, trusted-key finding reproduction and durable complete-run acceptance.
6. **Evaluation-1 evidence:** satisfy Architecture Lock Section 20 M1–M5. M6 may follow if time permits. Missing M6 is unfinished implementation of core grant/revoke/consumption, not a change to final architecture.
7. **Complete final core and study:** finish M6 and multi-grant/control/restart tests; pass pinned external-subset conformance; evaluate A3T/A4T, grouped held-out workflows, independent oracles, actual raw results, memory/overhead and explanations.

Report incomplete gates candidly. Evaluation 1 demonstrates implementation progress, not publication novelty. It does not require the final external baseline, transcript comparison, held-out corpus or scaling study. Publication feasibility remains unresolved.

## Dependency review

Before installation, check the published MCP specification and a stable Python SDK for compatibility with the locked transport subset. Present the Python version, direct packages, exact pins, relevant transitives, maintenance/security considerations, alternatives and expected environment size. Prefer standard-library SQLite, hashing, JSON and test support where adequate.

The MCP Python SDK and a reviewed cryptography package are dependency candidates, not approved installations. ECDSA P-256 must be implemented through a maintained library. Do not silently substitute an incompatible SDK or change the protocol target; propose a lock amendment if compatibility requires one.

## Verification discipline

- Use contract tests for normalization, context isolation, successful-result state updates, trusted control events and failure handling.
- Compare B0/B1/B2-S on one controller-generated observation history; count USE only once from committed intent. Match serialized B1 inputs. Separate detector-controlled enforcement runs and common reservation refusals; never attribute gate prevention to a detector that allowed the call.
- Label every proposal before its decision using independent controls/commit witnesses/raw proposals/source/sink/task observations, not audit-only reconstruction or detector transitions. Keep contract authorization, dispatch, consumption, disclosure and completion separate; never turn indeterminate into unauthorized.
- Verify B2-R/B2-S equivalence and lifecycle/reference memory. Reference adaptation may enter final results only after pinned-subset differential conformance.
- Test canonicalization, frozen trusted commitments, multi-grant reservation/control ordering, pre-seal mutation, exact-snapshot sealing, key/context substitution, missing-session acceptance, duplicate rejection after verifier restart and audit-write failure in every mode. Verification must never execute tools.
- Measure latency and storage with explicit hardware, versions, session lengths, repetitions and measurement boundaries. Repetitions of one fixture are not independent detection samples.
- Check documentation-only changes with diff/format/link/consistency checks; do not claim application tests were run when no implementation exists.

## Completion and handoff

For each authorized milestone: review against the lock and threat model; run relevant checks; report actual behavior, failures and material limits; explain the component and viva implications; update the existing documents; obtain student verification; then prepare a meaningful milestone commit. A commit is a record of verified work, not a substitute for verification.

The paper must distinguish proposed design from implemented behavior and measured results. Preserve raw experimental evidence and seeds before writing result tables. The existing PDF should be revised from editable source later; this milestone does not edit the supplied paper or syllabus.

## Document responsibilities

README describes status and navigation. PROJECT_CHARTER owns research scope, course mapping and evaluation. ARCHITECTURE_LOCK owns approved system contracts. THREAT_MODEL owns security assumptions and claim limits. AGENTS and this playbook own contributor workflow. Avoid conflicting copies of the architecture.

For any material amendment, record date, owner decision, architecture version and implications in the Architecture Lock. ARCHITECTURE_AMENDMENTS_V1.md is historical/supporting only; its prior normative wording cannot override the authoritative lock. No additional specification or roadmap document is needed for this synchronization.
