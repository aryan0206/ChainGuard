# ChainGuard

ChainGuard investigates explainable security analysis of MCP tool-call sequences and independently verifiable evidence of the monitor's observations and decisions. It is an Information Security course project intended to support a reproducible IEEE-style study.

**Status, 7 October 2026:** research direction and mandatory scope approved; **ARCHITECTURE LOCKED — ChainGuard Architecture v1.1**. Application implementation and dependency installation remain closed. The repository contains control documents, not a working security system or experimental results.

The core is a local Python MCP stdio proxy, task-scoped events, B0/B1/B2, core grant/revoke/one-use consumption, SQLite, trusted running SHA-256 commitments, ECDSA P-256 signatures, offline verification and independent evaluation. The final study includes B2-R/B2-S checks, the pinned sensitivity-policy reference adaptation and signed-transcript comparison. A minimal report separates behavioral findings, oracle labels and evidence status.

Normal observation mode MUST NOT bypass authorization. Unauthorized forwarding is possible ONLY through the explicitly configured synthetic local-sink observation override. Evaluation 1 targets M1–M5; M6 is optional for that evaluation and mandatory for the final project. Missing M6 cannot weaken or redefine core scope.

The research contribution is a controlled study of event ordering and task-bound verifiable findings. Session monitoring, sequence rules, hashing, and signing are established techniques; their inclusion alone is not a novelty claim. Cryptographic verification authenticates committed evidence under the threat model and does not establish that a detector's judgment is correct.

## Project controls

| Document | Responsibility |
| --- | --- |
| [Architecture Lock](docs/ARCHITECTURE_LOCK.md) | Authoritative approved components, contracts, algorithms, scope and acceptance criteria |
| [Project Charter](docs/PROJECT_CHARTER.md) | Research questions, contribution limits, syllabus mapping and experimental methodology |
| [Threat Model](docs/THREAT_MODEL.md) | Assets, adversaries, trust boundaries, assumptions and security limits |
| [Engineering Playbook](ENGINEERING_PLAYBOOK.md) | Approval gates, milestones, verification and student understanding |
| [Agent Instructions](AGENTS.md) | Operating rules for contributors and coding agents |
| [Historical amendment](ARCHITECTURE_AMENDMENTS_V1.md) | Supporting record only; contracts are incorporated into the sole authoritative Architecture Lock |

ML, periodic signed checkpoints, additional transports, real LLM studies, and cryptographic payload storage are extensions. Sensitive payload encryption becomes a requirement if a later approved change retains sensitive payloads; the core stores redacted, policy-sufficient observations.

## Next authorized stage

The owner has explicitly locked ChainGuard Architecture v1.1. Implementation still requires a subsequent explicit owner instruction. Before any package installation, present compatible version pins, dependency purpose, alternatives and transitive requirements for approval. No runtime commands or measured security/performance claims are available yet.

The supplied paper is a proposal/literature baseline and needs alignment with this design before reporting implementation or results. The final marking rubric and evaluation date still need confirmation. The existing LICENSE contains only a placeholder heading; release readiness requires resolving it separately.
