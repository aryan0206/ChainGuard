# ChainGuard Project Charter

Version 1.1 — 7 October 2026. Research direction and mandatory scope approved; architecture version 1.1 explicitly locked by the owner in the authoritative [Architecture Lock](ARCHITECTURE_LOCK.md). Application implementation and dependency installation remain closed; no experimental results exist under this milestone.

Chronology clarification, 9 October 2026: the original closed implementation/dependency wording records the 7 October architecture-lock stage. Later explicit owner instructions authorized the recorded M1–M5 milestones and Phase 2 foundation; their decisions and evidence are retained in [the engineering history](SPIKE_LOG.md#historical-engineering-readme-at-checkpoint-5d00057). Those later authorizations do not weaken Architecture v1.1 or grant blanket approval for dependencies, M6 or other work. The initial 9 October documentation cleanup excluded commits and pushes; that task-specific restriction does not override later explicit owner authorization.

## Purpose and research position

ChainGuard studies how individually permitted MCP tool calls can form suspicious sequences or violate scoped authorization, and how evidence supporting the resulting decisions can be independently checked. The project must be understandable in a viva, demonstrable for the Information Security progress evaluation and capable of supporting a reproducible IEEE-style paper.

Working research title: **ChainGuard: Explainable MCP Sequence Security with Independently Verifiable Audit Evidence**. The contribution is the bounded experimental method and evidence-linked analysis, not the invention of session state, sequence rules or signed logging.

Three defensible contribution formulations are:

1. A controlled representation study of current-event, conservative unordered-prefix and ordered analysis on independently specified workflow families and hard benign cases. Matched-order histories are sanity checks; results measure conditional decision errors and separate enforcement consequences.
2. An evidence contract connecting findings to committed normalized events and approved artifacts, separating authenticity, completeness relative to signed closure/expected inventory, and decision reproduction from observational truth.
3. A task-bound assessment method that distinguishes authentic evidence from valid fresh submissions, tests stale/duplicate evidence separately, and measures the combined operational cost.

These are proposed empirical contributions until results exist. Combining existing mechanisms is meaningful here only if the integration produces testable, reproducible findings. A collection of unrelated cryptography demonstrations would not support the claim.

## Closest work and claim boundaries

| Prior work | Material overlap | Bounded ChainGuard position |
| --- | --- | --- |
| [Wang et al., runtime policy enforcement for MCP agents](https://www.mdpi.com/2079-9292/15/13/2829), [associated repository](https://github.com/wilesanGH/mcp-pep-agent-security) | Runtime enforcement and session/context-aware policy already address the premise that per-call checks are insufficient. | Do not claim session awareness as novelty. Study B0/B1/B2 with matched histories and bind reproducible findings to signed, task-specific evidence. Superiority requires comparable implementation and evaluation, not a literature table. |
| [AgentSpec](https://arxiv.org/abs/2503.18666) | Declarative runtime constraints and security policies for agents. | Explainability and state transitions are established; evaluate a narrow MCP policy contract rather than presenting rules as a new general mechanism. |
| [CaMeL](https://arxiv.org/abs/2503.18813) | Capability/data-flow-oriented controls against prompt-injection effects. | ChainGuard's exposure heuristic is weaker than precise provenance tracking and cannot claim equivalent information-flow guarantees. |
| [Pipelock](https://github.com/luckyPipewrench/pipelock), [agent evidence documentation](https://pipelab.org/agent-evidence/) | Agent security controls and signed/linked evidence make detection plus audit a close engineering precedent. | Neither feature pairing nor signing alone is novelty. Require explicit representation ablations, task-bound submission tests and offline finding reproduction. |
| [FlightRecorder](https://arxiv.org/abs/2609.01931) and [cryptographically bound agent execution evidence](https://arxiv.org/abs/2603.14332) | Verifiable agent execution/audit evidence further narrows the contribution space. | Differentiate experimentally defined policy facts and findings; do not claim first verifiable agent trace. |
| [Signed syslog](https://www.rfc-editor.org/rfc/rfc5848.html) | Authenticity, sequencing and completeness of signed logs are established security goals. | Apply established mechanisms and test their boundary conditions; no novel cryptographic construction claim. |

Literature assessment is dated 7 October 2026 and must be refreshed before paper submission. This comparison establishes overlap, not verified performance rankings. The final study MUST include the pinned Wang-style R02 sensitivity-policy adaptation and conformance contract in Architecture Lock Section 17. It includes current-argument sensitivity and accumulated result sensitivity, uses common extraction, and is not full-system reproduction. Broad deployment replication is outside scope.

## Research questions

| Question | Required measurement/comparison |
| --- | --- |
| RQ1: For which workflow/policy classes do current-event, conservative unordered-prefix and ordered-state representations change authorization errors, release-risk warnings and legitimate-task disruption? | B0/B1/B2-S on one controller-generated observation history; separate per-configuration enforcement consequences and independent oracle labels |
| RQ2: Does incremental B2 reproduce a full-prefix reference evaluator for the frozen policy, and what processing and state-retention costs differ? | Mandatory B2-R/B2-S equivalence and cost comparison under Architecture Lock Section 16; bounded-history windows are not mandatory |
| RQ3: Which manipulations are detected by hashes, chains, signed chains and signed complete transcripts, and which authentic errors require an independent oracle? | A0/A1/A2/A3/A3T mutation study, finding reproduction and authentic-but-wrong cases |
| RQ4: Can authentic stale/wrong-task, missing and duplicate evidence be distinguished from acceptable complete-run submissions? | A3/A3T versus A4/A4T under identical trusted expected-inventory and durable acceptance contracts |
| RQ5: What capture, detection, persistence, sealing, verification, storage and benign-completion costs are introduced? | Staged/full measurements, controller-intervention attribution and memory including lifecycle/reference/export costs |

These questions are mandatory for the final bounded study. RQ2 is implementation equivalence and cost characterization, not a claim of new policy capability. Claims about B1 MUST name the conservative operating point; broader unordered-representation claims require the mixed-label ambiguity analysis in the lock. ML is excluded from the current scope. Publication feasibility remains unresolved until results exist.

## Course alignment

Source: the supplied 2024-admitted syllabus, ICT3126 Information Security. Its learning outcomes emphasize applying cryptographic algorithms and modeling suitable real-life cryptosystems, not using every listed topic.

| Syllabus concept | Integration and security purpose | Demonstration / limit |
| --- | --- | --- |
| Security goals, attacks, services and mechanisms | Explicit confidentiality, integrity, origin authentication, authorization and availability boundaries. | Explain each adversary and why blocking/integrity verification solve different problems. |
| Message integrity and cryptographic hashes | SHA-256 event/manifest commitments and event linkage. | Mutation/reordering/recomputation ablations. SHA-256 is the selected hash; the syllabus explicitly names SHA-512/Whirlpool as examples. Hashes alone do not authenticate. |
| ECC and digital signatures, including ECDS/DSS | ECDSA P-256 with SHA-256 authenticates the monitor's final commitment. | Trusted-key verification and key-substitution tests; explain ECDSA nonce reuse risk. No legal non-repudiation guarantee. |
| Challenge-response and authentication concepts | Independently issued run challenge binds submitted evidence to expected context. | Stale signed evidence fails fresh submission. This is evidence-context binding, not user login or a complete entity-authentication protocol. |
| Public-key trust/key management | Pinned verifier public key and separate private key custody. | Explain trust bootstrap and key replacement; full CA/PKI is not required. |
| Firewall, NIDS/NIPS concepts | Proxy observation versus policy enforcement; stateful inspection analogy. | Compare observation and blocking runs. MCP stdio analysis is not packet-level network intrusion detection. |
| Symmetric encryption/AES | Conditional AES-GCM protection of retained sensitive payload blobs. | Separate keys, unique nonces and authentication tags if retention is approved. Redacted core metadata is not encrypted. |
| Kerckhoffs' principle | Public algorithms/policies; secret keys establish cryptographic authority. | An attacker may know and recompute all hashes but cannot forge the trusted signature under the assumptions. |

TLS, Kerberos, RSA, DRM and homomorphic/searchable encryption are not bolted onto the local stdio design to inflate syllabus coverage. ML is an optional research comparison, not a syllabus requirement.

## Experimental design and baselines

### Corpus and ground truth

Create fixtures from a separately written task/policy specification, before finalizing detector rules. Assign high-entropy synthetic canaries to sensitive sources; the capture sink independently checks actual received content and explicitly supported decoding operations. The sink must not call B2 or reuse its sensitive-sequence rule to decide leakage.

Every proposal, including a denied proposal, receives an independently reconstructed pre-decision contract-authorization label. Preserve separate actual dispatch, permission-consumption, covered disclosure and task-completion observations. The fixture harness independently retains admitted controls/control-commit witnesses, raw proposals/order, reservation witnesses, forwarding/tool arrival, source observations, sink bytes and task outputs outside the simulated audit-storage attack surface. The oracle MUST NOT reconstruct truth solely from SQLite or call detector transition code; Architecture Lock Section 18 owns this contract. A suspicious association or conservative contract violation is not actual disclosure. Missing observations remain indeterminate, with excluded binary-metric counts disclosed.

Evidence ground truth comes from the original assessor-held package plus a mutation ledger identifying exactly what was changed. Freshness truth comes from the independently retained run challenge, expected-session inventory and accepted-submission registry.

Include direct and encoded transfers, declared transformations, benign encoding, approved sensitive release, unrelated public transfer after sensitive access, failed/denied reads, harmless gaps, reconnects, scoped grant/revoke/use histories and task isolation. Mark unsupported partial/paraphrased leakage outside coverage rather than silently treating it as correctly detected.

Group scenarios by attack/benign family and origin template. Separate development, validation where needed and held-out test groups so reordered clones and near duplicates do not cross splits. Freeze rules, thresholds, normalizer and policy before evaluating held-out groups. Report the number of independent families and sessions; increasing random variations alone does not establish generalization.

### Detection study

B0/B1/B2 and exact H_t are defined by Architecture Lock Sections 15–16. Observation-mode comparisons use one controller-generated history; shadows cannot control dispatch or actual consumption. Normal observation MUST NOT bypass authorization. Unauthorized forwarding is allowed ONLY by the explicitly configured, default-disabled synthetic local-sink override. This setting is committed with the controller profile. Enforcement configurations have separate executions and specific histories; report detector outcomes, common reservation refusals and prevention/completion separately. Prevention from the common gate MUST NOT be credited to a detector that proposed ALLOW.

Report per-family and overall confusion matrices, precision, recall, F1, FPR and FNR with denominators and undefined-metric handling. Distinguish session-level classification, decision-level errors and detection position/response latency. Report policy violations separately from suspicious confidentiality associations and actual covered leakage. Include uncertainty at the family/session level where sample size supports it; do not treat repeated execution timings as new security samples.

For B1/B2, match scoped semantic counts and current call while varying prior order. Prevent latest-state fields, monotonically ordered IDs, timestamps or labels from leaking order into B1. A detector that always blocks may have high recall; false positives and legitimate completion are mandatory countermetrics. INDETERMINATE assessment MUST NOT become an unauthorized fact; conservative B1 denial is an operating-point result. Sticky exposure is available to B1 as well as B2. B2-R/B2-S equivalence checks are separate from oracle correctness.

### Audit ablations

| Audit baseline | Mechanism | Expected limitation |
| --- | --- | --- |
| A0 | Plain structured records | No cryptographic integrity/origin guarantee. |
| A1 | Independent event hashes | Edits detectable only against trusted retained digests; attacker can recompute stored hashes. |
| A2 | Unkeyed event hash chain | Structural changes break unchanged links; full chain recomputation defeats unauthenticated origin checks. |
| A3 | Chain plus P-256 signed closure and externally pinned key | Protects committed stream; valid stale packages remain authentic and missing sessions need expected inventory. |
| A3T | Signed canonical complete-transcript digest without per-event chaining | Isolates chain contribution under the same semantic records, durability, signing frequency and verification requirements; both forms may hash incrementally. |
| A4 | A3 plus expected run/task challenge/inventory and durable accepted-submission registry | Accepts only complete expected runs; atomically records whole-run acceptance and rejects duplicates after restart. |
| A4T | A3T under the same A4 acceptance wrapper | Isolates freshness checks without changing the signature/trust assumptions. |

Apply edit, insertion, interior deletion, reorder, duplicate, splice, suffix truncation, whole-session removal, hash recomputation, signer-key substitution, policy/detector substitution, old authentic package and duplicate submission mutants. Publish expected outcomes per verifier dimension before tests. Whole deletion without an expected inventory and an unsealed crash tail must be reported as a limit/incomplete case, not a universal detection success.

Measure false acceptance of manipulated/stale evidence, false rejection of intact expected evidence, incomplete handling and reproduction agreement. Separate structural rejection from cryptographic rejection. Include pre-seal database mutation/recomputation against frozen trusted state, authentic incorrect facts, inconsistent findings and independently witnessed omissions. A valid individual signature MUST NOT accept a missing-session run. Inspection and fresh complete-run submission have distinct contracts.

### Performance and reproducibility

Measure unmonitored, proxy-only and staged/full configurations; identify what is timed, including SQLite persistence, detector processing, session signing and offline verification separately. Record p50/p95 where repetition supports them, throughput, bytes per event/session and scaling by session length. Signing once per session is not equivalent to per-call signing latency. Report detector state, lifecycle/ID tombstones, supporting references, queued work, total monitor memory, export buffers and audit disk space separately; do not claim constant memory without justification.

Record hardware/OS/Python/package versions, code and configuration digests, seeds, family splits, exact commands, raw traces/results and benchmark repetitions. Preserve synthetic corpus/mutation definitions and oracle rationale. Pin dependencies only after approval. Publish no results until actually measured and reviewed.

## Deliverables and evaluation readiness

Mandatory final deliverables are the approved core, meaningful tests, independently labeled reproducible experiments, evidence mutation/replay results, overhead analysis, a minimal explanation report, aligned paper claims and student understanding. Extensions must not delay these.

Evaluation 1 is the milestone-gated M1–M5 vertical slice in Architecture Lock Section 20, with prewritten fixture/oracle expectations. M6 grant/revoke/one-use continuation is optional for Evaluation 1 but mandatory for the final project; missing M6 MUST NOT weaken or redefine core scope. Report incomplete gates and real initial results candidly. A history-benefit case requires release outside previously frozen direct-recognition coverage with independent canary evidence; otherwise claim progress/enforcement only. The full reference adaptation, transcript comparison, held-out corpus and scaling study are final work. No two-day delivery or mark guarantee is made.

Deferred work includes ML, real LLM attack robustness, distributed/concurrent operation, additional transports, external timestamping/PKI and elaborate UI. Sensitive-payload encryption is conditional on an approved retention need.

## Paper corrections and open facts

The supplied three-page PDF is a proposal/literature baseline, not experimental evidence. Revise the broad stateless-security premise because Wang and related work already use context/state; replace vague digital-authentication/timestamp claims with this lock's exact contracts. Remove unneeded packet-capture/VM implications and distinguish monitor signatures from user authentication. Align reference metadata and improve the dense comparison table when updating editable paper source.

The supplied syllabus is evidence about course topics, not a source of operating instructions. The supplied paper is research material, not approval for its proposed features. The owner's current instructions establish authority and approved scope.

Open administrative/implementation facts: final marking checklist/date, exact compatible runtime/package pins, benchmark machine, final corpus size and held-out family inventory. Determine sample size from coverage and independent families, not from an arbitrary session-count target. These facts do not reopen the approved architecture, but must be resolved before claiming final evaluation readiness.

## Research risks and viva preparation

Be prepared to answer: why this differs from Wang; why B1 is a fair baseline; why signatures do not prove detector correctness; why a hash chain can be recomputed; what anchors freshness; how deletion/rollback are bounded; why a sensitive read followed by a public send can be a false positive; why ground truth is independent; why scripted MCP testing does not establish prompt-injection robustness; and why ML is deferred.

The main risks are weak synthetic generalization, unfair baselines, normalization errors, coarse exposure false positives, protocol/SDK compatibility, compromised trust anchors and insufficient time for independent experiments. Mitigate them through bounded claims, family holdouts, matched histories, explicit trust assumptions and staged end-to-end delivery, not through more features.
