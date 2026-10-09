# ChainGuard Evaluation-1 — Viva Preparation

Prepared 9 October 2026 against checkpoint **5d00057**. All outcomes below are **recorded results, not tests or experiments rerun during this documentation task**. This guide does not authorize implementation.

Study A–M first, test yourself with N, and use O–P for navigation and rehearsal. Begin answers in ordinary language, then state the precise boundary. For an unmeasured outcome say: “We have not established that yet.”

Sources: [Architecture Lock](ARCHITECTURE_LOCK.md), especially Sections 6, 8–11 and 15–19; [Threat Model](THREAT_MODEL.md); [Evaluation Protocol](EVALUATION_PROTOCOL.md); [Experiment Matrix](EXPERIMENT_MATRIX.md); [Results Ledger](RESULTS_LEDGER.md); [Claims Register](CLAIMS_REGISTER.md); [AF-001](ADVERSARIAL_FINDINGS.md); [report](overleaf-evaluation1/main.tex); [engineering history](SPIKE_LOG.md#historical-engineering-readme-at-checkpoint-5d00057). Implementation paths are mapped in O.

| Question | Distinction to preserve |
| --- | --- |
| What did ChainGuard recommend? | Detector finding ≠ controller dispatch decision ≠ independent oracle label. |
| Did B2 implementations agree? | Consistency ≠ independently established correctness. |
| Was evidence authentic? | Integrity/origin ≠ truthful capture or absolute completeness. |
| Was the run accepted? | Evidence eligibility ≠ benign behavior. |
| Was a duplicate rejected? | Evidence deduplication ≠ prevention of tool-action replay. |

## A. Opening speech

### 60–90 seconds

“Our project, ChainGuard, studies how the history of tool use affects security decisions in an MCP workflow. MCP is a protocol that connects AI applications to tools. A call can look reasonable by itself, but its authorization can depend on what happened earlier.

“For example, granting permission and then revoking it is different from revoking an old permission and issuing a new grant. Both histories contain a grant and a revocation, but they leave different permission states. We compare a current-call representation, an unordered history representation, and an ordered history representation under a fixed policy.

“We also separate the security decision from the evidence supporting it. A local proxy mediates controlled tool calls, durable audit records precede forwarding, and an offline verifier checks signed evidence and reproduces findings. An independent oracle assesses observations rather than trusting those findings.

“For Evaluation-1, M1 through M5 and the workflow/oracle foundation are implemented. We have 216 recorded passing regression and qualification tests across separately executed suites, together with bounded mediation, repair and acceptance demonstrations. Those tests are not 216 research experiments. Live M6, held-out evaluation and external comparison are still pending. Our final research question is where retaining ordered history improves useful security decisions.”

### 20–30 seconds

“ChainGuard is a controlled MCP testbed studying when tool-use history changes security decisions. We compare current-event, unordered-history and ordered-history representations, then assess outcomes independently and verify signed audit evidence. Evaluation-1 covers M1–M5 and the workflow/oracle foundation, with 216 recorded regression and qualification tests. Live lifecycle, held-out evaluation and external comparison remain pending.”

Pause after the permission example. Do not recite every suite count in the opening. The transition is: the problem needs context; the approach compares retained information; current results establish foundations while useful decision quality remains a research question. These durations are rehearsal targets, not measured delivery.

## B. Explain the idea at three levels

**Layman:** Permission to send a document can be withdrawn. A note saying “one grant, one revocation” does not say which happened last. An ordered history can show whether permission is available. A signed diary can expose later changes to its contents, but does not prove every entry was honest.

**Engineering:** A scripted client calls a controlled MCP server through a stdio proxy. Detectors share the current normalized proposal and policy but receive different historical representations. The controller owns dispatch. Required audit persistence precedes forwarding, and result persistence follows execution. Independent assessment and evidence verification are separate paths.

**Technical:** Before proposal t, H_t is the committed task-local semantic projection: TOOL_OUTCOME, GRANT, REVOKE_SCOPE and projected USE facts. B0 receives c_t and static policy; B1 adds permitted multiset counts; B2 uses eligible ordered history/state. B2-R and B2-S implement the same normalized conservative policy through separate reconstruction/transition paths. An independent assessor derives labels from prewritten contracts and independently supplied observations. M4 authenticates a domain-separated canonical chain closure; M5 checks complete expected-run eligibility and durable acceptance identity.

Example: after the same sensitive read, compare **grant → revoke → proposed send** with **revoke → NEW grant → proposed send** for the same scope and current call. B1 sees equal counts and abstains; B2 sees unavailable versus active permission. This is replay qualification, not a live M6 result.

## C. Problem, motivation and research gap

The problem is not identifying suspicious tool names alone. A send proposal can depend on earlier sensitive acquisition and the current state of scoped permission. MCP provides a controlled boundary for mediating and correlating tool requests/results; it does not itself establish authorization or truthful capture.

The study separates having history from retaining its order. B1 already has history; sticky exposure alone is not an ordering advantage. We ask where ordered state changes useful decisions under specified policies, with what costs and evidence guarantees. Useful decisions include coverage, unnecessary denial, disclosure and legitimate task completion, not one combined security score.

Supported now: recorded operation of the configured mediation path, a bounded replay ordering distinction, repaired persistence admission, offline signed-evidence checks and expected-run acceptance. Hypotheses: general B2 benefit, held-out utility, external superiority, final novelty and cost/scaling.

Prior work: AgentSpec and CaMeL provide runtime enforcement/information-flow context. The Wang work is the planned narrow external comparison, not a completed reproduction. Signed Syslog provides established authenticated-logging precedent. Use the report citations and [baseline notes](BASELINE_NOTES.md). Do not claim first sequence-aware defense or novel cryptography. This guide performed no fresh literature search; exhaustive current novelty is unverified.

## D. Architecture walkthrough

Start with: **“The live Evaluation-1 surface is public and non-release. Sensitive grant/revoke/one-use semantics are replay-qualified and locked for M6, not implemented live.”** M1 is transport only; M3/M4 add audited gating.

| Stage | What/why; input → output | Failure; guarantee and limit |
| --- | --- | --- |
| Scripted client | Issues discovery/listing and sequential calls; JSON-RPC requests → correlated responses. | Malformed/version/correlation errors fail the run. Client metadata cannot create authenticated permission or context. |
| Proxy/normalizer | Mediates local stdio and derives controlled current facts; request/tool metadata → proposal. | Unsupported tools/arguments are not assumed safe. Covers the configured route, not arbitrary host activity. |
| Detector evaluation | Shadows evaluate c_t using permitted prior information; policy/representation → explained findings. | Invalid/incomplete prefix can stop evaluation. Findings are hypothetical recommendations, not dispatch authority or truth. |
| Controller/admission | Validates the supported call and prepares decision/intent; proposal/trusted state → ALLOW/DENY and batch. | Unsupported input denied; audit failure blocks forwarding. LiveAudit authorizes public M1 operations, not sensitive release. |
| Durable writer | Freezes expected rows/state, validates schema, inserts, reads back and confirms COMMIT; batch → trusted advancement/receipt. | Rollback or ambiguity halts. Establishes tested pre-forward materialization under SQLite/runtime assumptions, not post-commit immutability. |
| Downstream tool | Executes the admitted request; forwarding → handler arrival/result. | Can fail after dispatch. Tool effects are outside the database transaction. Live tools are echo/controlled_failure. |
| Outcome recording | Validates known results, persists terminal outcome, then returns response. | Persistence failure cannot undo effects. Unknown outcome halts and prevents false clean closure. |
| M4 seal/export | Reconciles exact snapshot with trusted count/head; records/manifest → signed closure/package. | Mutation, unresolved work or signing failure prevents clean seal. Refusal cannot undo earlier execution. |
| Offline verifier | Uses external expectations, pinned key and approved code; package → six statuses/reproduction counts. | FAIL/INCOMPLETE/NOT_CHECKED remain distinct. Never executes tools or proves raw-event truth. |
| M5 acceptance | Verifies complete expected inventory and atomically stores acceptance; expectations/packages → eligibility decision. | Missing/stale/duplicate evidence refused. Survives restart under trusted registry assumptions; registry rollback excluded. |

Detector findings have behavioral verdicts, authorization assessments, rules and hypothetical recommendations. Controller decisions govern actual forwarding. Oracle assessments label independent observations. Audit evidence records commitments/provenance. M5 decides submission eligibility. Keep these five distinct when explaining any arrow.

## E. B0, B1, B2-R and B2-S — deep explanation

Sources: [semantics.py](../chainguard/semantics.py), [detectors.py](../chainguard/detectors.py), Architecture Sections 6/16, [M2 tests](../tests/test_m2.py).

### Shared setup and output

All detectors share c_t, static policy and normalized current features. The frozen M2 extraction recognizes registered synthetic canaries in raw UTF-8 and one strict base64 layer, applies a 65,536-byte payload limit and static destination restrictions. No recursive/arbitrary decoding or hex recognition is claimed for detector extraction. Independent oracle hex coverage does not change that operating point.

A Finding includes authorization (AUTHORIZED/UNAUTHORIZED/INDETERMINATE), behavior (ALLOW/SUSPICIOUS/POLICY_VIOLATION), hypothetical recommendation (ALLOW/DENY), rule, support, explanation and version/digest identifiers. Static prohibition takes precedence; unsupported input is uncertainty. Supported non-send operations have no release obligation.

### B0 — current event only

Input: current proposal and static policy, with no history argument. Retains current recognition/restrictions; discards previous exposures, controls and permission state. A supported send not statically prohibited has INDETERMINATE authorization because history is unavailable. The frozen operating point can nevertheless give behavioral ALLOW without a current sensitive warning; that is not established authorization. A directly recognized sensitive send under that unknown authority is SUSPICIOUS with hypothetical DENY.

Purpose: meaningful per-call comparison. Strength: current raw/base64 checks and static prohibitions. Limit: historical dependencies. It is not merely a tool-name allowlist.

### B1 — unordered prefix

Input: current proposal and counts of buckets containing category, operation, resource, destination, outcome, sensitivity, transformation and exact release scope. Task partitioning is validated before projection. IDs, ordinals, timestamps, active-state flags and transition features are excluded; references are attached after evaluation and do not feed the counts.

Successful sensitive reads identify exposed resources. Required send resources are exposure union current recognized sensitive resources. For each scope, let G/R/U be grant/revoke/use counts:

- G > U and R = 0: AUTHORIZED.
- G <= U: UNAUTHORIZED under a validated lifecycle.
- G > U and R > 0: INDETERMINATE.

Across required scopes, definite failure dominates, then uncertainty, otherwise authorization. No release obligation is authorized unless statically prohibited. Uncertainty is conservatively denied as SUSPICIOUS, not relabelled definite violation.

Purpose: separate historical information from order. Strength: sticky exposure and definite count predicates. Limit: counts cannot reconstruct remaining active grants after revocation. This is one specified conservative unordered policy, not every possible B1 classifier.

### B2-R — full-prefix reference

Input: c_t, ordered eligible history and task identity. Validates unique facts/grant IDs and reconstructs each grant's availability by examining subsequent facts. Matching scope revocation or USE removes availability; unknown outcomes make the prefix incomplete. For each required scope choose the lexicographically smallest active matching grant. Any missing scope yields UNAUTHORIZED and empty hypothetical selection.

Purpose: a separately written reconstruction path for the same policy. Strength: explicit reference behavior. Limit: intentional repeated scans, not a claimed fast implementation. It shares extraction/policy helpers with B2-S, so common errors remain possible.

### B2-S — incremental state

Input: committed facts through observe, and c_t through evaluate. Retains exposed resources, active grants, issued IDs, seen facts, an incompleteness flag and supporting-reference history. GRANT activates a new ID; REVOKE_SCOPE removes active grants for that exact scope; USE validates/removes its active grant; successful sensitive reads add exposure. Evaluation uses the same complete-scope rule as B2-R.

Purpose: incremental transition implementation. Strength: explicit current permission state. Limits: retained reference history and ID sets grow; no constant-memory claim. In the live M3 shadow callback a streaming object is rebuilt from the prefix per proposal, so live demonstration time does not measure continuously retained B2-S cost. Final retained-state benchmarking is pending.

### Matched-order example

Start both valid histories with the same successful sensitive read; end with the same send for the same task/resource/destination. One has GRANT then REVOKE_SCOPE; the other REVOKE_SCOPE then a NEW unique GRANT. Revocation without active permission is a valid no-op; the new ID is not resurrection/replay.

B1 receives byte-identical serialized current/count inputs: G=1, R=1, U=0. The actual integration check is test_matched_order_pair_is_byte_identical. It returns INDETERMINATE for both. B2-R/B2-S return UNAUTHORIZED for grant→revoke and AUTHORIZED for revoke→new grant. Independently reconstructed M2 oracle labels agree. Phase 2 separately qualifies development group revocation_boundary_01.

This is one bounded information distinction, not completed E02, held-out accuracy or general B2 superiority. B1 abstention is not automatically a classification error. B2-R/B2-S agreement checks consistency between two paths implementing one specification; shared incorrect rules or normalized facts can make both wrong.

## F. Semantic event model and policy state

H_t is committed prior semantic information, not every audit row. Sources: Architecture Section 15.3, semantics.Fact, audit._facts and detector transitions.

| Fact | Meaning and exact transition |
| --- | --- |
| TOOL_OUTCOME | Prior terminal operation/resource/destination/status/sensitivity/transformation. Successful sensitive read adds sticky exposure; failed/denied read does not. Unknown outcome makes context incomplete and halts further security-relevant calls. |
| GRANT | Admitted committed permission for exact (task_id, resource, destination, release), with a fresh unique opaque ID. Activates permission. |
| REVOKE_SCOPE | Removes all currently active grants for one exact scope. Does not affect future NEW grants; no active match is a valid no-op. |
| USE | One projected fact per selected grant in successfully committed dispatch intent; consumes that available grant. Not a separately appended second consumption event. |

Empty selection yields no USE; tool outcomes add no second USE. A dispatched failed call retains its committed consumption. Denied/non-dispatched proposals consume nothing. These release semantics are locked/replay-qualified; live M3/M4 use empty required/selected scopes because release is disabled. Architectural semantic names must not be mistaken for an implemented live M6 persisted-control interface.

Supported sends require permission for exposure union recognized current resources. Static prohibition overrides grants. Public reads, transformations and elapsed time do not clear exposure. An unrelated public transfer can fail this conservative authorization rule without actual canary disclosure. Partial/ambiguous sensitive acquisition is unsupported and halts rather than guessing.

Timestamps give display context, not authoritative order. Hashes describe evidence relationships, not behavior. Findings/controller conclusions would make evaluation circular. IDs/ordinals validate lifecycle or render references, but cannot leak into B1 behavioral features. The current proposal is c_t, not an earlier TOOL_OUTCOME in H_t.

## G. Independent oracle and experimental validity

The oracle evaluates the contract and independently observed effects, not detector claims. [oracle.py](../chainguard/oracle.py) imports no detector/normalizer/projector/B2 state. It receives explicitly synthetic journals: issued/admitted controls, control-commit/reservation witnesses, proposals, forwarding/arrival, source/sink observations and task output/coverage. It reconstructs authorization before proposals and assesses dispatch, consumption, disclosure and completion.

Phase 2 [workflows.py](../chainguard/workflows.py) adds immutable WorkflowContract, CallExpectation, EnvironmentObservations and receipts. Nine authored development contracts cover S1–S6. Expected labels precede detector execution and contain no detector expectation. Actual receipts are separate from the plan: handler/sink effects contradicting intended denial remain observed effects. No environment means missing observations, not fabricated execution.

Actual authorization attribution currently needs independently supplied staged permission history; live adapters/authorization qualification remain future work. Missing sink collector (None) differs from explicitly observed empty capture (()). Unknown commit differs from failed commit. Missing control/source/reservation evidence can preserve unknown permission/consumption. Task closure alone does not prove capture completeness. Detector-relative correctness/coverage/unnecessary-denial metrics remain NOT_CHECKED in this truth-only foundation.

Recorded independence checks: fresh-process import absence, AST import inspection, altered findings, poisoned B2 evaluators, rejected controller/finding annotations, observations contradicting plans, independently supplied consumption and missing-data cases. See [test_workflows.py](../tests/test_workflows.py). These are separation checks, not infallibility or strong OS isolation. Labels remain bounded by fixture correctness, observation coverage and trusted witness assumptions.

## H. Audit and cryptographic evidence

Canonical encoding gives a single agreed spelling; a chain commits sequence; a signature authenticates the final commitment. None proves honest capture. Sources: [canonical.py](../chainguard/canonical.py), [evidence.py](../chainguard/evidence.py), [verifier.py](../chainguard/verifier.py), Architecture Sections 8–10.

### Exact bytes and construction

Let C(x) be canonical.encode(x). Source SHA-256 functions return lowercase hexadecimal presentation. Tags include exactly one final zero byte:

```python
D_MANIFEST   = b"CHAIN GUARD MANIFEST-v1\0"
D_GENESIS    = b"CHAIN GUARD GENESIS-v1\0"
D_EVENT      = b"CHAIN GUARD EVENT-v1\0"
D_COMMITMENT = b"CHAIN GUARD COMMITMENT-v1\0"

manifest_digest = SHA256(D_MANIFEST + C(manifest))
genesis = SHA256(D_GENESIS + bytes.fromhex(manifest_digest))
event_hash = SHA256(D_EVENT + C(event))
signing_input = D_COMMITMENT + C(closure)
expected_inventory_digest = SHA256(C(expected_inventory))
```

Genesis consumes raw 32 digest bytes, not ASCII hex. Event includes identity, sequence and prev_hash but excludes its own hash. First prev_hash is genesis; later prev_hash is preceding event hash. Inventory deliberately has no manifest domain tag.

Exact source signing API:

```python
key.sign(DOMAINS["COMMITMENT"] + encode(closure), ec.ECDSA(hashes.SHA256()))
```

Do not manually prehash and then use this hashing API again. Library handles ECDSA/SHA-256 and signing nonces. Curve: NIST P-256/secp256r1. Suite: ECDSA-P256-SHA256-DER-v1. DER signature bytes are transported in canonical base64. The snippets explain existing code, not proposed changes.

| Component | What it establishes under assumptions | What it cannot establish |
| --- | --- | --- |
| Canonical typed records | Deterministic UTF-8, sorted keys, compact separators, integers bounded to ±(2^53−1), no floats/duplicate keys, preserved Unicode. Event schemas separately validate fields/versions. | Truth, secrecy or RFC 8785 compliance. Encoding alone is not complete schema validation. |
| Manifest/genesis | Initial identity/versions/scope/profile/challenge/inventory/configuration bound into chain. | Honest or complete capture. |
| Domain separation | Different byte tags distinguish manifest/genesis/event/commitment use. | Origin authentication without a trusted signature. |
| Event hash chain | Ordered-record/predecessor commitment relative to trusted authenticated head/count. | Resistance to recomputation on its own; absolute completeness. |
| Signed closure | Authenticates manifest digest, four identities, challenge/inventory digest, count/final sequence/head, CLOSED status and schema/algorithm/signer metadata. | Honest logger, correct detector, trusted time or forward security after key compromise. |
| Pinned key | Origin check against independent approved P-256 key selected by key ID. | Trust merely because the package includes a key or name. |
| Expected binding/inventory | Checks independent contexts/configuration and completeness of known sessions. | Entire unknown runs/sessions omitted before expectation. |
| Finding reproduction | Approved installed code recomputes decisions from committed normalized facts. | Those facts accurately represent raw effects. |

Package fields: format_version, manifest, records, commitment, signature. Record wrappers contain event and event_hash. Verifier freezes input bytes and never runs bundled executable code. Six dimensions: schema_lifecycle, commitment_integrity, trusted_signature, expected_binding, inventory_completeness, finding_reproduction; statuses PASS/FAIL/INCOMPLETE/NOT_CHECKED.

Completeness is relative to authenticated closure and external expected inventory. “Signatures do not prove completeness” means absolute capture completeness; signed count/head still constrain the committed stream. False facts signed at capture time differ from post-capture storage tampering. Authentic wrong facts may reproduce consistently; wrong findings on correct facts should fail reproduction.

**Per-event chain versus batch hash:** chosen design stores a predecessor/hash for every typed event and advances a running head/count across transactional batches, signing one final closure. It supports sequence/link inspection and localization of discontinuities. A canonical whole-transcript digest can also commit order; A3T is planned for comparison. Per-event work/storage have costs; neither approach alone provides truthful capture, origin or external expectations. No universal superiority or final measured tradeoff is established.

## I. M3 persistence and M4 adversarial repair

M3 supplies durable records and process-owned non-cryptographic continuity (last_seq, last_event_id), not a cryptographic complete-transcript commitment. M4 creates new chained streams; it does not reclassify old M3 records as signed evidence.

AF-001 found successful SQL insert/commit acknowledgments could conceal suppressed or altered required records, while trusted state advanced and forwarding occurred. Later sealing rejected disagreement, but the tool had executed. The violated invariant was exact required decision/dispatch-intent persistence before forwarding. This was a persistence admission failure, not an ECDSA forgery.

The repaired shared append_batch sequence is:

1. Freeze canonical records, expected storage tuples, candidate phase/state and receipt.
2. BEGIN IMMEDIATE; validate code-owned tables/indexes/constraints and reject unexpected storage objects.
3. Insert and read back the complete batch inside the transaction. Compare exact metadata/canonical bytes; M4 includes hashes and exact stored manifest bytes/digest.
4. Pre-COMMIT failure: confirm rollback, halt, produce no successful receipt or forwarding.
5. Start COMMIT. Only confirmed return allows trusted phase/history/count/head advancement and receipt.
6. Forward the downstream call; persist the outcome in a separate later transaction.

Ambiguous COMMIT acknowledgment means halt without forwarding, querying/adopting database state, retrying the action or falsely declaring rollback. Actual commit/reservation is unknown. Confirmed commit followed by witness-delivery failure also halts. The database can have advanced without a downstream action; guessing would risk replay.

Limits: readback operates within trusted SQLite/runtime assumptions. It does not continuously protect old rows, prevent arbitrary post-commit mutation, defeat a compromised database engine/filesystem or atomically undo tool effects. Outcome sabotage after a correctly audited execution must prevent false clean completion/subsequent execution; it cannot undo that effect. Recorded repair evidence: 27 targeted regressions and 10/10 independent rechecks BLOCKED, overlapping engineering evidence rather than extra research samples.

## J. M5 expected-run acceptance

An assessor independently registers run_id, a fresh run challenge, complete expected task/session/monitor associations, configuration and pinned keys before submission. Inventory is canonical/sorted; duplicate session/task associations are rejected. Challenge is 32 cryptographically random bytes in lowercase hex, distinct from ECDSA's internal signing nonce.

Displayed ExpectedRun identity is (run_id, run_challenge, expected_inventory_digest). Association/configuration must also match. Packages cannot choose new expectations or shrink the inventory. Registration does not itself accept evidence.

M5 verifies every expected session with PASS in all required dimensions, checks exact coverage, then atomically stores canonical commitments and changes ACTIVE to ACCEPTED in its trusted registry. Exact stored materialization is checked before confirmed commit. The durable registry survives process restart: a later submission for the accepted run returns REJECTED / ALREADY_ACCEPTED. Repeated offline INSPECT is allowed.

Accepted-session digest hashes the existing domain-separated commitment signing input, not signature bytes. ECDSA signatures can differ for identical content, so signature bytes are unsuitable duplicate identities.

Ambiguous registry commit gives NOT_CHECKED/unknown durability and requires explicit reconciliation on retry. This differs from ambiguous execution commit, which must never retry a tool action. Creating a registry is explicit; opening a missing one must not silently erase history. Registry tampering/rollback is outside the claim.

Acceptance means complete eligible expected evidence, not a benign workflow certificate. Correctly reproduced POLICY_VIOLATION findings can legitimately be accepted as evidence of violations. Neither acceptance nor evidence deduplication proves raw-event truth or prevents tool replay.

## K. Results and metrics

| Suite | Recorded passing tests | Interpretation |
| --- | ---: | --- |
| M1 | 12 | Mediation/protocol-subset regression |
| M2 | 41 | Replay representation/oracle qualification |
| M3 | 40 | Durable unsealed audit/non-release regressions |
| M4 | 67 | Chained evidence/verifier/persistence regressions |
| M5 | 27 | Complete-run acceptance/registry/campaign regressions |
| Phase 2 | 29 | Development contract/observation independence qualification |
| Aggregate | **216** | **187 M1–M5 + 29 foundation, across separately executed passing suites** |

Not 216 independent workflows/research experiments or a new project-wide discovery run. Failed/repeated historical attempts do not add samples. Phase 2's initial concurrent M1 discovery timed out; an isolated unchanged rerun passed all 12. Concurrent load is a possible explanation, not a conclusively identified root cause. Durations are observations, not performance benchmarks.

| Recorded demonstration | Result and limit |
| --- | --- |
| M2 | 23 fixtures / 37 valid proposal prefixes; B2 agreement throughout, not held-out accuracy. |
| M4 flow | 26 records / 8 confirmed transactions; success/error/success and 3 proposals. |
| M4 verifier | Six dimensions PASS; 12 reproduced findings (four per proposal); 3 B2-agreeing prefixes. |
| Repair | 10/10 independent recheck cases BLOCKED within declared conditions. |
| M5 campaign | 32/32 package cases and 16/16 consolidated checks; not added to 216. |
| M5 process boundary | Fresh ACCEPTED exit 0; new-process REJECTED / ALREADY_ACCEPTED exit 2, same identity. |
| Foundation | Nine development contracts covering S1–S6, not nine held-out research outcomes. |

Record accounting: start/end give 2 rows; each of 3 calls has proposal + 4 findings + decision + intent + outcome = 8, giving 26. Start/end have one transaction each, each call one admission and one outcome transaction: 2 + 3×2 = 8. This explains the configured non-release flow, not every possible stream.

Tests check engineering obligations. Research units must be actual independent parent workflows with eligible denominators, grouped splits and uncertainty. Prefixes/timing repetitions from one workflow are not independent security samples. No final effect size, held-out result, external superiority or cost estimate exists.

## L. Threat model and trust assumptions

Study scope: supported calls traversing configured mediation, bounded exposure/revocable-authorization policies and evidence manipulation/submission under declared attacker powers.

Trusted: host/controller and running monitor state, approved normalizer/detector/verifier code, controlled registry/tool contracts, private signing key, independently pinned key/configuration, expected inventory/challenge, assessor journals and acceptance registry. SQLite rows/export packages are not live authority. Packages cannot replace these trust inputs.

Workflow attacker can influence supported calls/arguments/destinations/sequences, but cannot issue trusted grants, alter classifications or bypass the route inside the core experiment. Storage attacker can edit/delete/reorder/splice/recompute records and replay packages, but cannot change trusted running state, signing keys, assessor expectations or acceptance history. Separate files/processes are logical boundaries, not demonstrated OS isolation. Unrestricted host compromise is outside the claim.

Sensitive experiments use synthetic data/local capture sinks. Current live tools are public non-release. Normal observation still requires authorization. Only explicitly enabled, default-disabled, committed synthetic local-sink override can forward an otherwise unauthorized supported synthetic release. It cannot apply to real sensitive external destinations, static prohibitions, unsupported input or operational/audit failures. Override selection is empty, with no partial grant consumption. Current live profile disables releases/override.

Private keys remain outside the repository/database; secrecy, library nonce safety and correct provisioning are assumptions. Hashes/signatures do not encrypt metadata. AES-GCM payload retention is conditional design scope, not implemented confidentiality evidence. Clocks do not prove trusted time. SQLite/tool effects are separate; offline verification never executes tools.

## M. Limitations and unresolved issues

- M6 live grant/revoke/one-use lifecycle is unimplemented: optional for Evaluation-1, mandatory for final completion, requiring separate authorization. Its exact schedule/reason beyond recorded phased scope is not established.
- E01–E13, held-out study, external conformance/comparison, signed-transcript comparison and final cost/scaling remain pending.
- Synthetic tests do not establish arbitrary tools, paraphrased/semantic leakage, real LLM injection resilience, universal exfiltration detection or complete information-flow security.
- Signatures authenticate commitments under trusted-key assumptions, not truth or absolute completeness. Accepted evidence can describe violations.
- Conservative exposure can overflag unrelated public transfers. Reproduction can faithfully reproduce decisions on false normalized facts. Oracle/coverage errors remain possible.
- No post-commit immutability, SQLite/tool atomicity, command anti-replay, trusted timestamping, forward-secure key-compromise defense or strong OS isolation claim is established.

**Unresolved evidence labels:** supplied A0 no integrity / A1 hash chain / A2 signed closure conflict with repository A0 structured records / A1 independent hashes / A2 unkeyed chain / A3 signed canonical chain / A3T signed ordered transcript, with A4/A4T acceptance variants. Keep both alternatives; explicit resolution precedes affected experiments.

**Unresolved baseline pin:** supplied `3dd9690b5b6f9c4ef385289714b314d13f6ad1` versus locked `3dd9690b5b6f9c4ef385289714b314d13f6ad9a1`. Supplied string is not a full 40-character SHA. No resolution, baseline checkout or conformance execution occurred here.

Protocol RQ numbering is local: its ordering RQ2 differs from charter/lock RQ2 about B2 reference/incremental equivalence and cost. Use the documented mapping, not silent renumbering.

Unknown/unverified here: classroom projector legibility, actual speech/rehearsal timing, final rubric requirements, live-demo reliability at viva time, final independent workflow count/feasibility, external outcomes and final novelty. The slide notes' 6:45 is planned timing.

## N. Detailed viva question bank

Use the answer as a starting point, then trace the relevant code/contract. Q1–Q100 provide the required six categories; trap questions are explicitly marked.

### N1. Fundamental project questions — 15

**Q1. What is ChainGuard in one sentence?**
A controlled MCP testbed comparing how retained information affects deterministic security decisions, while separately assessing and verifying their evidence. “Controlled” signals bounded tools, policies and trust assumptions.

**Q2. What is MCP?**
The Model Context Protocol connects applications to tools through defined requests/responses. We use a configured local stdio subset, not a claim of full protocol coverage or security supplied by the protocol itself.

**Q3. What problem motivates history?**
A send can depend on prior sensitive acquisition and permission changes. Looking only at its present arguments may miss a historical obligation; this does not mean every call needs ordered history.

**Q4. Why compare three representations?**
To isolate information retained: current event, unordered prior facts, ordered transitions. The comparison is meaningful only with common current observations/static policy and controlled historical feature restrictions.

**Q5. What is the main research question?**
Where ordered retained information changes useful security decisions under the specified policies, with what evidence/cost tradeoffs. General improvement is a hypothesis awaiting final workflow evidence.

**Q6. What has Evaluation-1 completed?**
M1–M5 and development workflow/oracle foundation. Recorded mediation, replay, durable auditing, signed verification, repair and acceptance qualify the platform; the final study is pending.

**Q7. Is the system a production security gateway?**
No production claim is supported. The live surface is two public controlled tools, with a trusted local runtime and configured route; arbitrary hosts/tools need additional evidence.

**Q8. What does explainable mean here?**
Findings name deterministic rules, policy/version digests, supporting events and explanations. This makes a decision traceable to recorded inputs, not necessarily correct or truthful.

**Q9. Why use deterministic rules?**
They let us freeze behavior and reproduce findings while studying representation sufficiency. ML is a separately justified extension, not an implemented contribution.

**Q10. Does history mean order?**
No. B1 retains counts of prior facts, including exposure. B2 additionally retains lifecycle order; claiming that only B2 has history misstates the experiment.

**Q11. What is the concrete ordering example?**
Grant→revoke leaves no active permission; revoke→new grant can leave active permission. Same current call and B1 counts, different ordered state; new grant IDs keep both histories valid.

**Q12. Is detecting a violation the same as preventing it?**
No. A finding is a recommendation; prevention requires actual controller refusal and no relevant effect. A common gate's refusal cannot be credited to a detector that recommended ALLOW.

**Q13. What is the independent oracle for?**
It evaluates contract labels and observed effects without using detector findings as truth. Its own coverage and trusted observations still require qualification.

**Q14. What is the project's cryptographic contribution?**
An application of established SHA-256 and ECDSA P-256 to canonical typed evidence and independent submission checks. No new primitive or first authenticated-logging claim is made.

**Q15. What should the professor remember?**
Current evidence establishes bounded engineering behavior and a research platform. Whether ordered history improves useful security outcomes remains for final evaluation.

### N2. Architecture and workflow questions — 15

**Q16. Trace a supported audited call.**
Client→proxy→normalized proposal/shadow findings→controller batch→validated exact readback/confirmed commit→trusted advancement→tool→separate outcome commit→response. Sealing and verification occur later.

**Q17. Who may grant permission?**
The trusted host/controller under the locked contract, not client metadata or a shadow detector. Live M6 grant admission is still unimplemented; replay controls simulate the specified semantics.

**Q18. Why a proxy?**
It gives the controlled experiment a mediation/correlation boundary. It does not cover unmediated actions or establish arbitrary tool honesty.

**Q19. Are shadow findings controlling live dispatch?**
The current non-release LiveAudit gate validates the M1 registry/arguments and records shadows. Those hypothetical recommendations do not decide forwarding; future enforcement remains governed by the lock.

**Q20. Why are proposal, decision and intent grouped?**
They form the prerequisite evidence for one admission. A confirmed complete batch must precede forwarding so partial recorded decisions cannot authorize an unaudited action.

**Q21. Why record results separately?**
Results exist after execution, so they cannot be included as known pre-dispatch facts. A crash between dispatch and outcome leaves uncertainty rather than a fabricated terminal result.

**Q22. What are run/task/session/monitor identities?**
Run identifies configured execution; task identifies the workflow; session identifies its evidence stream; monitor_instance_id binds the monitor instance. They are trusted context, not client-asserted permission.

**Q23. What do call IDs and admission ordinals do?**
Call IDs correlate phases; ordinals serialize admissions. They support validation/order handling, but must not enter B1 behavioral features and restore discarded order.

**Q24. Can a queued revoke cancel a committed call?**
The lock serializes complete proposal turns. A later control waits; it cannot retroactively cancel an already committed dispatch intent.

**Q25. Can multiple calls run concurrently in one task?**
The locked core requires sequential proposal turns. That keeps pre-decision state and permission reservation well-defined; broader concurrency is not qualified.

**Q26. Does a reconnect reset exposure?**
A downstream reconnect may preserve state only while trusted monitor/controller survive with no unresolved outcome. It is not a permission reset.

**Q27. What happens after monitor restart?**
Unfinished contexts/grants are invalidated, the affected controlled client context terminates, and fresh identities/expectations are required. SQLite reconstruction is not adopted as live authority.

**Q28. Trap: why is the oracle not dispatch authority?**
Using its labels to control the evaluated system would contaminate the comparison. Controller maintains actual permission independently; oracle assesses externally retained observations.

**Q29. What can outcome-write failure change?**
It can halt further execution and prevent false clean closure. It cannot reverse an effect already performed after a correctly audited admission.

**Q30. Where is the live boundary narrower than the design?**
Only echo/controlled_failure with a bounded string token are admitted, normalized public/non-release. Sensitive reads/releases, live grant/revoke/use and collector qualification belong to M6/future evaluation.

### N3. B0/B1/B2, policy and oracle questions — 20

**Q31. What exactly does B0 receive?**
Only the current normalized call/extraction features and static policy. Its function has no historical input; historical permission remains unavailable even when current behavior is allowed at the frozen operating point.

**Q32. Is B0 deliberately weak?**
It checks supported raw/one-layer strict-base64 canaries and destination restrictions. Hex/recursive decoding are outside its frozen coverage, not tuned omissions added after comparison.

**Q33. What exactly does B1 keep?**
Counts of permitted semantic buckets: category, operation, resource/destination, outcome, sensitivity, transformation and release scope. Successful exposure is retained; event/grant IDs and active state are excluded.

**Q34. Could B1 recover order from timestamps or references?**
Those are forbidden input features. Supporting references are attached after evaluation; lifecycle/task validation must not leak order into the counted projection.

**Q35. State B1's permission predicate.**
For a required scope: G>U with R=0 gives AUTHORIZED; G<=U gives UNAUTHORIZED under valid lifecycle; G>U with R>0 gives INDETERMINATE. Across scopes definite absence dominates uncertainty.

**Q36. Trap: is INDETERMINATE AUTHORIZED?**
No; it means the permitted evidence cannot establish authority. Conservative denial may be appropriate, but must not fabricate an UNAUTHORIZED fact or automatically be counted as a classification error.

**Q37. Why does the matched pair have equal B1 input?**
Same current call, exposure and scoped category counts; only eligible control order differs. The test compares actual serialized bytes, not just fixture names or a visual table.

**Q38. Is revoke-before-grant a valid scenario?**
Yes: revoking no active matching grant is a valid no-op. A later NEW unique grant activates permission; replaying a consumed/revoked grant ID would not be valid.

**Q39. How does B2-R reconstruct activity?**
It records each grant's issue position and examines later matching revocations/uses. A grant without such invalidation remains available for its exact scope; malformed uses/replayed IDs are rejected.

**Q40. How does B2-S update activity?**
It inserts new grants, removes all active grants of revoked scope, and validates/removes the selected grant on USE. It separately retains sticky exposure and incompleteness.

**Q41. Trap: does B2-R/B2-S agreement prove correctness?**
It proves only agreement on checked inputs/fields. Shared policy/extraction/helper mistakes can affect both, so independent contracts and observations remain necessary.

**Q42. Why select the lexicographically smallest grant?**
It makes selection deterministic when multiple active grants match. It is a tie-breaker on opaque IDs, not evidence of chronology or extra permission.

**Q43. Why require every resource's scope?**
The policy conservatively requires the union of successful prior acquisition and current recognized resources. Partial selection cannot authorize a complete release; absence yields refusal/empty selection.

**Q44. What exactly is USE?**
A semantic projection per selected grant from committed dispatch intent. It represents once-only permission reservation, not successful leakage and not a second event appended after the result.

**Q45. Why not refund after tool failure?**
Permission was consumed for a committed dispatch attempt. Failure may have uncertain effects; refund/replay could reuse authority and duplicate an action.

**Q46. Can a failed read create exposure?**
A supported failed/denied acquisition does not create successful exposure. Sensitive partial/ambiguous results are outside the supported failure contract and must halt rather than be treated as harmless.

**Q47. Why can public transfer be unauthorized without leakage?**
Sticky exposure can create a release obligation even when current bytes contain unrelated public data. Authorization follows the conservative contract; actual disclosure follows independent sink evidence.

**Q48. What can the oracle recognize that detector extraction cannot?**
The M2 assessor independently covers synthetic raw/base64/hex content, while detector extraction is raw/base64 only. This separation can reveal coverage limits but does not imply arbitrary transformation support.

**Q49. How do missing observations affect truth labels?**
Missing permission/source/reservation evidence preserves unknown authority/consumption. No sink collector differs from observed empty capture; absence cannot be inferred from a task-end marker alone.

**Q50. How is oracle independence tested?**
Import/AST checks, altered findings, poisoned evaluators, forbidden annotation rejection and receipts contradicting plans. These show input/code-path separation within recorded tests, not an infallible external truth service.

### N4. Cryptography, audit, SQLite and persistence questions — 20

**Q51. Trap: does a hash prove an event happened?**
No. It commits bytes; a fabricated record can be hashed. Reality requires trustworthy capture and independently supported observations.

**Q52. Trap: does a signature prove the detector is correct?**
No. It authenticates a commitment under the pinned key. Finding reproduction checks consistency with normalized inputs; independent assessment checks whether those inputs/decisions match the contract/effects.

**Q53. Why canonicalize records?**
Hashing/signing needs deterministic bytes, not exports whose spaces/key order vary. Restricted UTF-8 JSON rejects floats/duplicate keys and preserves Unicode; exact schema checks are a separate step.

**Q54. Trap: why per-event hashes rather than one batch hash?**
Chosen design links every typed event and maintains a running head/count across transactions, allowing event-level link checks. A canonical complete-transcript hash can also commit order; final A3T comparison is pending. No universal superiority is claimed.

**Q55. Why both chain and signature?**
The chain commits record order/content, but a storage attacker can recompute unkeyed hashes. The trusted-key signature authenticates the final head/count and contextual commitment, assuming the private key is uncompromised.

**Q56. What exactly does the signature cover?**
COMMITMENT domain tag plus canonical closure. Closure includes manifest digest, run/task/session/monitor identities, challenge/inventory digest, record count/final sequence/head, CLOSED status and schema/algorithm/key metadata. It indirectly commits the chain, not just a free-floating nonce.

**Q57. What are exact domain tags?**
ASCII “CHAIN GUARD MANIFEST-v1”, “CHAIN GUARD GENESIS-v1”, “CHAIN GUARD EVENT-v1”, “CHAIN GUARD COMMITMENT-v1”, each followed by one zero byte. Do not drop the space in CHAIN GUARD or the separator byte.

**Q58. What does genesis hash?**
GENESIS tag followed by the raw 32-byte manifest digest. Hashing the 64 ASCII hex characters instead would produce a different construction.

**Q59. Where is prev_hash and is event_hash self-referential?**
prev_hash is inside the canonical event; current event_hash is outside in the wrapper/stored hash column. First predecessor is genesis. Excluding the current hash avoids a circular definition.

**Q60. Why pin the key externally?**
Otherwise an attacker could replace records and provide their own key/signature. Key ID chooses an already trusted P-256 key; a package-provided identity is not a trust anchor.

**Q61. Why ECDSA P-256/SHA-256?**
It is the owner-selected locked suite implemented with a maintained cryptographic library. We are not claiming it universally outperforms alternatives or inventing nonce/signature code.

**Q62. Is the run challenge the ECDSA nonce?**
No. Challenge binds independent expected context and is retained by the assessor. Signing nonce belongs to the library's ECDSA operation; unsafe reuse can disclose the private key.

**Q63. Why are signature bytes unsuitable for deduplication?**
Valid ECDSA signatures can differ for identical commitment content. M5 uses expected authenticated identity and commitment digest, so another signature encoding of the same accepted run does not create freshness.

**Q64. Can an attacker recompute all event hashes?**
Yes; algorithms are public. Without the signing key they cannot authenticate an altered sealed head/count under the pinned key; live sealing also compares stored material with process-owned state.

**Q65. Why were SQL success acknowledgments insufficient?**
AF-001 showed manipulated storage behavior could suppress/alter required material while operations appeared successful. A later seal refusal was too late once forwarding occurred.

**Q66. What is exact readback checking?**
Within the same write transaction, actual rows must equal frozen expected tuples, including indexed metadata/canonical bytes and M4 hashes. Manifest bytes/digest must also exactly match; schema is code-owned.

**Q67. Trap: what if COMMIT acknowledgment is ambiguous?**
Halt without forwarding, retry, refund, database-state adoption or false rollback claim. The database may have committed; guessing creates unsafe execution/replay risk.

**Q68. Trap: is SQLite commit atomic with the tool?**
No. Intent commits first, tool runs later, outcome commits last. Failure between stages leaves unknown effects; no ordinary SQLite transaction rolls back an arbitrary external action.

**Q69. Can signatures detect deletion of an entire unknown session?**
Not without independently knowing it was expected. Signed count/head constrain a known stream; external inventory identifies missing known sessions. Absolute capture completeness remains unproven.

**Q70. How do inspection and acceptance differ?**
INSPECT is repeatable read-only verification. Fresh submission additionally needs exact independent complete-run expectations and durable atomic registry acceptance; repeated submission of an accepted identity is rejected.

### N5. Testing, results and experimental validity — 15

**Q71. What are the six suite counts?**
M1 12, M2 41, M3 40, M4 67, M5 27, Phase 2 29. The first five sum to 187; all six sum to 216 across separately executed passing suites.

**Q72. Trap: do 216 tests mean 216 independent samples?**
No. They are regression/qualification cases, including related assertions/fixtures. Independent research units must be actual parent workflows with eligible denominators and grouped splits.

**Q73. Were those tests rerun for this guide?**
No. They are recorded in the ledger and historical engineering records. Documentation validation checks file scope/links/diff, not current application execution status.

**Q74. Was one 216-test discovery run recorded?**
The foundation ledger explicitly reports an aggregate across separately executed suites. Historical 187 discovery is a different checkpoint; do not describe the aggregate as a new discovery run.

**Q75. What do 23 fixtures and 37 prefixes establish?**
M2 replay expectations and B2 equivalence at valid proposal prefixes. Prefixes from one fixture are related observations, not 37 independent held-out workflows.

**Q76. Explain the M4 26/8 counts.**
Two lifecycle rows plus three calls with eight rows each gives 26. Two lifecycle transactions plus three admission/outcome pairs gives eight. These are flow/evidence counts, not security-accuracy metrics.

**Q77. Explain 3 proposals, 12 findings, 3 agreeing prefixes.**
Four detector findings per proposal produce 12; each supported proposal provides a B2 comparison prefix. Reproduction checks those stored findings against approved rules, not 12 independent security incidents.

**Q78. What does six PASS dimensions mean?**
The configured package passed schema/lifecycle, commitment integrity, trusted signature, expected binding, inventory completeness and finding reproduction. It does not certify safe behavior or truthful raw capture.

**Q79. What does 10/10 BLOCKED mean?**
Recorded independent repair rechecks blocked their declared admission manipulations. It does not prove every possible storage attack is blocked or remove SQLite/runtime assumptions.

**Q80. What do 32/32 and 16/16 mean?**
Declared M5 package cases and consolidated checks passed. Their bounded matrix contains genuine/stale/mutated/incomplete/duplicate conditions; they are reported separately from the suite aggregate.

**Q81. Does zero campaign failure imply zero real-world error rate?**
No. It is zero observed failures in a declared engineering matrix, without a population estimate. General FAR/FRR and uncertainty need a qualified independent study.

**Q82. Is the initial M1 timeout hidden by the final total?**
The ledger records initial concurrent setup failure and subsequent isolated 12-test success. We report the final recorded passing suites while preserving failure provenance; root cause remains unproven.

**Q83. What is Phase 2's contribution?**
Nine prewritten development contracts, separate environment receipts, unknown-preserving qualification and independence checks. It is not live M6, a new detector or completed E01–E13.

**Q84. Why grouped held-out splits?**
Variants/prefixes from one parent can share structure and leak information if split independently. Protocol requires parent-level separation before held-out execution; actual final counts/results remain unknown.

**Q85. How will useful security be measured?**
Separate authorization correctness/coverage, unnecessary denial, unauthorized disclosure and legitimate completion, with eligible denominators and attribution. Truth-only foundation does not fabricate detector-relative metrics; final analysis remains pending.

### N6. Threat model, limitations and prior work — 15

**Q86. What is trusted?**
Approved running host/monitor/verifier code, controlled tools/registry, signing key, assessor expectations/observations and durable registry. Storage/export input is not trusted as live authority.

**Q87. What may the evidence attacker do?**
Edit/delete/insert/reorder/splice/recompute stored records, substitute package keys/configuration and replay packages under the simulated boundary. Changing private keys/trusted memory/assessor expectations/registry history is excluded.

**Q88. Does process separation establish strong isolation?**
No. Logical roles/files/processes alone do not constrain an unrestricted same-host attacker. Actual privilege restrictions must be demonstrated before stronger deployment claims.

**Q89. Trap: is a valid accepted package a safe workflow?**
No. It can correctly contain and reproduce violation findings. Acceptance checks evidence eligibility/completeness/authenticity under expectations, not benignness.

**Q90. Trap: does duplicate evidence rejection prevent tool replay?**
No. M5 prevents accepting the same expected evidence identity again. Offline verification never executes tools; preventing replayed real actions requires separate execution controls.

**Q91. Can observation mode bypass authorization?**
Ordinary observation cannot. Only the explicitly enabled, default-disabled synthetic local-sink override may forward an otherwise unauthorized supported synthetic case, with empty selection and no static/operational bypass.

**Q92. Are audit records confidential because they are hashed?**
No. Hashing/signing does not encrypt metadata or low-entropy secrets. Core minimizes/redacts content; conditional AES-GCM retention requires separate approval and key/nonce controls.

**Q93. What if the signer lies or loses its key?**
A dishonest signer can authenticate false capture. Key compromise undermines origin/alteration assurances; this design is not forward secure. Independent observations and key provisioning remain assumptions.

**Q94. Trap: why are workflows replay-based?**
Replay lets us qualify deterministic policy/representation and independent labels with declared synthetic witnesses before adding live lifecycle complexity. Those witnesses are explicitly not durable/live commit proof.

**Q95. Trap: why is M6 pending?**
Recorded scope completes M1–M5 for Evaluation-1 and leaves live grant/revoke/one-use as mandatory final work requiring separate authorization. Do not invent an additional scheduling/technical justification.

**Q96. What remains before final completion?**
Live M6/witness qualification, frozen/held-out E01–E13 work, external conformance/comparison, evidence-variant and cost/scaling evaluation. Current engineering tests cannot substitute for those results.

**Q97. How does this relate to AgentSpec/CaMeL?**
They provide related runtime enforcement/information-flow context in the report. Our controlled retained-information comparison and separate evidence guarantees define our study scope; no exhaustive novelty or superiority conclusion follows.

**Q98. Has the Wang baseline been reproduced?**
No adapter/conformance/comparison is completed. The baseline pin conflict must be explicitly resolved and the locked common-domain comparison qualified before measuring external outcomes.

**Q99. What does Signed Syslog imply for novelty?**
Authenticated logging is established prior work. Applying chained signed evidence here must be positioned as an engineering/design choice and controlled evaluation, not invention of signatures or the first verifiable trace.

**Q100. What is the strongest honest conclusion today?**
The recorded controlled engineering slice operates and provides evidence for specified mediation, replay, persistence, repair, verification and acceptance behavior. Whether ordered history improves useful security decisions broadly remains an empirical question.

## O. Code and implementation map

Paths are relative to repository root; these are inspected files, not invented modules. Read each responsibility before memorizing a function name.

| Module/file | Responsibility | Viva relevance |
| --- | --- | --- |
| [chainguard/client.py](../chainguard/client.py) | Scripted M1 requests/process orchestration and response assertions. | Show real discovery/listing/success-error-success route. |
| [chainguard/proxy.py](../chainguard/proxy.py) | Supported stdio relay, diagnostics and optional audited before/after hooks. | Where mediation, correlation and actual forwarding occur. |
| [chainguard/controlled_server.py](../chainguard/controlled_server.py) | Controlled echo/controlled_failure tools. | Narrow live tool contract; legitimate error versus protocol failure. |
| [chainguard/semantics.py](../chainguard/semantics.py) | Current extraction, Fact/Scope/Finding and B1 projection. | Exact feature allowlist, raw/base64 coverage and semantic history. |
| [chainguard/detectors.py](../chainguard/detectors.py) | b0/b1, B2Reference/B2Streaming, equivalence fields. | Predicates, transition independence, hypothetical decisions. |
| [chainguard/m2.py](../chainguard/m2.py) | Synthetic replay/comparison harness. | Valid-prefix evaluation; not live commit proof. |
| [chainguard/oracle.py](../chainguard/oracle.py) | Independent staged journal assessor. | Permission/effect labels and unknown coverage. |
| [chainguard/workflows.py](../chainguard/workflows.py) | Development contracts, separate receipts, qualification/matched groups. | Prewritten expectations and observed effects remain distinct. |
| [chainguard/canonical.py](../chainguard/canonical.py) | Restricted deterministic JSON encoding/decoding. | Exact cryptographic bytes, no floats/duplicate-key aliases. |
| [chainguard/audit.py](../chainguard/audit.py) | M3 writer/schema/lifecycle, exact batch validation, LiveAudit and semantic projection. | Commit-before-forward and repaired no-adoption rule. |
| [chainguard/m3.py](../chainguard/m3.py) | Real audited non-release harness and shadows. | Unsealed continuity; rebuilt streaming shadow versus benchmark. |
| [chainguard/evidence.py](../chainguard/evidence.py) | M4 domains/manifest/chain/commitment/P-256, ChainedAuditSession. | Exact hash/signing construction and sealing trust. |
| [chainguard/m4.py](../chainguard/m4.py) | Key provisioning and signed non-release demo bootstrap. | Fresh externally retained expectations and controlled fixture key. |
| [chainguard/verifier.py](../chainguard/verifier.py) | Six-dimensional offline inspection and deterministic reproduction. | Repeated INSPECT, approved code, no side effects. |
| [chainguard/acceptance.py](../chainguard/acceptance.py) | Immutable expected-run registration and durable atomic acceptance. | Identity, inventory, duplicate/restart and ambiguity distinctions. |
| [chainguard/m5.py](../chainguard/m5.py) | Registry commands and bounded package campaign. | Fresh/process-boundary acceptance demo; not final E01–E13. |
| [tests/test_m1.py](../tests/test_m1.py) through [test_m5.py](../tests/test_m5.py) | Milestone regressions. | Recorded engineering counts and boundary cases. |
| [tests/test_workflows.py](../tests/test_workflows.py) | 29 foundation qualification tests. | Fresh-process/AST/poisoned-evaluator/contradicted-plan checks. |
| [tests/m2_fixtures.py](../tests/m2_fixtures.py), [m5_fixtures.py](../tests/m5_fixtures.py), [workflow_fixtures.py](../tests/workflow_fixtures.py) | Explicit synthetic replay/package/development contracts. | Prewritten cases, synthetic status and sample-count limits. |

Navigation drill: find LiveAudit.before/after, AuditSession.append_batch/_verify_stored_batch, ChainedAuditSession._verify_stored_batch, sign_commitment, verifier.DIMENSIONS and AcceptanceRegistry.submit. Explain each in one sentence, then name its failure boundary.

## P. Last-minute rehearsal

### Five-minute rapid review

1. **Minute 1:** deliver the brief introduction and distinguish implemented platform from final hypothesis.
2. **Minute 2:** draw client→proxy→gate/database→tool→outcome. Put oracle and verifier outside dispatch authority.
3. **Minute 3:** explain equal-count grant/revoke pair, B1 uncertainty and B2 agreement versus correctness.
4. **Minute 4:** explain canonical bytes→manifest/genesis→chain→signed closure→external expectations→acceptance. Name what authenticity cannot prove.
5. **Minute 5:** recall six suite counts/216, M4 26/8 and 3/12/3, repair 10/10, M5 32/32 and 16/16; end with pending M6/final study.

### Ten-minute self-test

- **Minutes 0–2:** opening without reading; ask your teammate to stop any unsupported novelty claim.
- **Minutes 2–4:** use Q31–Q50 to explain B1 predicates, USE and unknown observations; answer three at random.
- **Minutes 4–6:** use Q51–Q70; reproduce exact tag/closure construction and distinguish ambiguous commit from failure.
- **Minutes 6–8:** reconcile all counts and distinguish campaign cases, prefixes, development contracts and independent parent units.
- **Minutes 8–10:** use Q86–Q100; state attacker powers, observation override and two unresolved protocol alternatives. Mark any uncertain answer and consult the linked source.

Success means explaining why, not memorizing a label. Keep answers bounded: “in our controlled slice,” “recorded engineering evidence,” and “pending final qualification” are useful when they accurately state scope.

### Ten difficult follow-up questions

1. **Both B2 implementations agree on a wrong fact: what detects it?** Independent source/sink/contracts can expose the capture/normalization error; reproduction alone cannot. Missing observations mean uncertainty.
2. **A public transfer follows sensitive read without a grant: is it exfiltration?** It can be unauthorized under conservative exposure policy without actual leakage. Inspect sink bytes before claiming disclosure.
3. **A complete package contains violations: why accept it?** Eligible evidence of violations is legitimate; acceptance is not a safe-behavior decision.
4. **Readback passes, storage changes later: what holds?** Tested pre-forward admission under assumptions, plus later sealing/verification detection where commitments/expectations apply; no perpetual immutability.
5. **COMMIT may have succeeded, why not just inspect SQLite and proceed?** Execution must not adopt attacker-writable storage as authority or risk replay; halt. Registry reconciliation is a separate non-tool operation.
6. **A session disappears entirely, how do you detect it?** Exact independently retained inventory; without knowing it was expected, absence alone proves nothing.
7. **What if another valid ECDSA signature is generated?** Same authenticated commitment/run identity remains duplicate; signature bytes are not identity.
8. **Why can't the matched pair establish general accuracy?** One specified policy/development distinction supplies no independent held-out population estimate; abstention and task utility need separate metrics.
9. **Does incremental B2 mean constant memory or measured faster execution?** No: state/reference/ID retention grows, live shadows rebuild, and final retained-state timing remains pending.
10. **What exact unresolved choices must be frozen before final work?** Evidence-ablation labels and external baseline pin require explicit resolution; retain protocol-local versus charter RQ mapping without guessing.

### Common overclaims to avoid

| Avoid | Say instead |
| --- | --- |
| “B2 is always better.” | “One replay ordering distinction is demonstrated; final useful-outcome evaluation is pending.” |
| “B1 has no history.” | “B1 retains unordered historical counts.” |
| “INDETERMINATE is authorized/wrong.” | “The permitted information does not establish authority; abstention is evaluated separately.” |
| “216 experiments passed.” | “216 recorded regression/qualification tests across separately executed suites.” |
| “Hashes/signatures prove truth or full capture.” | “They authenticate committed bytes under key/expectation assumptions.” |
| “Acceptance means safe; duplicate rejection prevents tool replay.” | “Acceptance checks evidence eligibility and prior accepted identity.” |
| “SQLite makes tool effects atomic.” | “Intent and outcome persist on either side of a non-atomic tool boundary.” |
| “Universal leakage detection/first sequence-aware defense.” | “Bounded controlled policies, with related prior work and unresolved final novelty.” |
| “Final evaluation completed.” | “M6, E01–E13, held-out/external comparison and final costs remain pending.” |

### Before entering the viva

- Know the exact supported live tool names and tell apart M1 transport from M4 evidence.
- Use the actual existing README commands in the approved environment; do not install dependencies or invent recovery steps at the desk.
- If demonstrating tools, follow the previously reviewed demo; do not silently treat a failed run as success.
- Have the reviewed PPT/PDF accessible and be ready to zoom slides 7–8 terminal evidence.
- Agree who introduces, who traces code and who answers cryptography/experiment questions.
- Explain the matched-order pair without looking at the slide.
- Know all count meanings; avoid adding campaign/repeated runs into 216.
- Distinguish uncertainty, legitimate controlled error and security violation.
- State trust assumptions and pending work calmly.
- For an unverifiable follow-up: identify the relevant source or say it remains unmeasured; do not guess.

## Documentation preparation checks

This guide is a study aid grounded in existing source/contracts/recorded evidence. Preparing it did not rerun tests, provision keys, execute demonstrations, implement M6, resolve protocol conflicts or change the report/PPT. Actual demo reliability, rehearsal and owner review remain separate checks.
