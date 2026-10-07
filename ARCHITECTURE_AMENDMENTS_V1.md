# ChainGuard Architecture Amendments V1 — Historical Record

Date of proposal and synchronization: 7 October 2026.

Status: HISTORICAL / SUPPORTING ONLY. The reviewed contracts have been incorporated into [docs/ARCHITECTURE_LOCK.md](docs/ARCHITECTURE_LOCK.md), version 1.1, Sections 15–20. That file is the SINGLE authoritative architecture document; the owner explicitly declared version 1.1 locked on 7 October 2026. This record does not authorize implementation or dependencies.

The proposal body below is preserved for review provenance. Its MUST/MUST NOT/SHOULD/MAY wording records the earlier proposal and has NO independent normative authority. Subsequent owner clarifications restrict unauthorized observation forwarding to an explicitly configured synthetic local-sink override and retain M6 as mandatory final-project core. Consult the authoritative lock, not this historical snapshot, for current contracts.

Historical sections 1–6 correspond to authoritative sections 15–20. This file MUST NOT be maintained as a competing specification.

## 1. Execution authority and historical input

### 1.1 Common authorization and ordering boundary

The existing trusted host/controller MUST maintain actual execution permissions independently of detector outputs. Its execution ledger MUST receive admitted controls and committed normalized tool outcomes through the execution path, not detector state. It MUST NOT call B2 to manufacture shared history or read any shadow verdict as an input. Sharing the written permission specification is permitted. This controller is execution authority, NOT the evaluation oracle.

Each task MUST have one FIFO admission queue for host controls and tool proposals. The controller MUST assign an increasing admission ordinal on receipt and the fixture harness MUST independently retain admitted input order. Local timestamps MUST NOT decide order. One proposal turn MUST cover pre-decision state, all detector evaluations, dispatch reservation, forwarding, and terminal result processing. Later grants/revocations MUST wait until that turn completes. A queued revocation MUST NOT cancel an already committed dispatch intent. Calls MUST NOT run concurrently within one task.

Each control turn MUST durably append its control event before activating its grant/revocation transition. Failed control persistence MUST leave the transition unapplied and halt the task; ambiguous commit MUST leave authority unknown and halt. The harness MUST independently retain control-commit witnesses as well as issued/admitted controls. Queued or issued approval alone MUST NOT become usable permission.

For a supported outbound proposal, the stipulated conservative contract requires exact release permission for every resource in the union of successful prior sensitive acquisitions and directly recognized current sensitive-resource facts. Non-release operations have no release obligation. Static prohibitions override grants. An unresolved sensitivity-to-resource mapping MUST be treated as operationally unsupported, not guessed. Actual public payloads can consequently fail this conservative contract; that is not proof of disclosure.

An atomic scope is (task_id, resource_id, destination_id, release). Grant IDs MUST be unique opaque values, used for lifecycle correlation but not B1 features. Each grant permits one committed dispatch intent. Scope revocation MUST invalidate all currently active grants for that exact scope; a later NEW grant ID MAY restore permission. Revocation with no active grant is a valid no-op. Grants MUST NOT outlive the task or survive monitor restart. Dynamic wildcards and wall-clock expiry are excluded.

For each required scope, selection MUST choose the lexicographically smallest active matching grant ID. One transaction MUST persist the proposal decision records and one dispatch-intent record containing the complete selection. Consuming all selected grants, appending intent, allocating audit sequence numbers and advancing trusted commitment/state MUST constitute one logical all-or-nothing reservation. This is not an atomic transaction with tool execution: trusted memory advances after confirmed database commit under the task gate. No forwarding is permitted until successful durable commit is confirmed and trusted running state is advanced. A failed reservation MUST consume no subset. An ambiguous commit result MUST halt the task without forwarding or retrying; the reservation outcome is unknown, not falsely reported rolled back.

### 1.2 Observation mode

The controller MUST forward supported, statically admissible proposals irrespective of B0/B1/B2 shadow outcomes, subject to operational readiness and successful audit persistence. Static safety prohibitions and unsupported operations MUST still prevent dispatch.

If the controller can reserve the entire required grant set, it MUST consume that set with dispatch intent. If permission is unavailable, observation mode MAY forward only within the approved synthetic local-sink experiment using the run's explicit authorization override. It MUST record an empty selection and MUST NOT partially consume available grants. These override executions remain unauthorized under the stipulated contract.

Shadow detectors MUST NOT issue controls, alter execution, consume grants, select actual grants, or mutate the shared execution ledger. Each detector MAY update its own representation using the same committed semantic observations. Current controller authorization/override status MUST NOT be passed to a shadow detector as an extra feature.

Thus observation comparisons measure decisions conditional on ONE controller-generated execution history, not counterfactual detector-controlled trajectories.

### 1.3 Exact H_t

Immediately before proposal t is evaluated, H_t MUST contain only committed prior semantic facts from that task:

1. TOOL_OUTCOME: one terminal outcome per prior call, including operation, resource/destination, status, sensitivity and declared transformation facts.
2. GRANT: one admitted grant and its exact scope.
3. REVOKE_SCOPE: one admitted scope revocation.
4. USE: one fact per selected grant in a successfully committed dispatch-intent record.

USE is a projection of dispatch intent, NOT a second independently appended consumption event. The dispatch_intent body MUST contain call_id, required_scopes, selected_grants and reservation_status. Each selected_grants entry MUST contain grant_id and its resource/destination/release scope; task identity comes from the envelope. reservation_status MUST be AUTHORIZED, OBSERVATION_OVERRIDE or NO_RELEASE_OBLIGATION. Selection and required-scope arrays MUST be canonically sorted; AUTHORIZED MUST cover the full nonempty requirement set; the other statuses MUST have an empty selection. OBSERVATION_OVERRIDE requires observation mode and a nonempty requirement set; NO_RELEASE_OBLIGATION requires an empty requirement set. Auxiliary copies of these facts MUST NOT create more USE facts or feed controller conclusions to detectors. Existing envelope names seq and prev_hash remain unchanged; no alias fields are introduced.

Duplicate selected IDs and duplicated intent/call phase records MUST be rejected. A dispatch with an empty selection generates no USE. Tool outcomes MUST NOT generate additional consumption facts.

Prior proposals, findings, shadow decisions, explanation text, controller authorization conclusions, timestamps, audit hashes and lifecycle bookkeeping MUST NOT become behavioral history features. Lifecycle records remain available for validation and task partitioning. The current persisted proposal is c_t, not a prior fact in H_t.

Failed/denied acquisition MUST NOT create successful exposure. Controlled acquisition failures MUST return no sensitive partial payload; partial/ambiguous result forms are unsupported and MUST halt the task. A dispatched failed call retains its committed consumption. A denied/non-dispatched proposal consumes nothing. Unknown outcomes MUST be recorded where possible, halt further security-relevant calls and make the stream incomplete; consumed permissions MUST NOT be refunded or tool calls automatically replayed.

### 1.4 Enforcement mode

Each detector/configuration MUST receive a separate execution with fresh task/session identities and equivalent fixture inputs. Its findings control allow/deny under its frozen operating point. A denial MUST NOT consume grants. An allowed call needing permissions MUST pass the same atomic reservation procedure; an authoritative reservation refusal MUST be reported separately from the detector's proposed decision. Observation overrides MUST NOT apply.

Future outcomes and history are specific to that execution. Enforcement trajectories MUST NOT be described as identical-input representation comparisons. Detector error rates, controller refusals and actual task consequences MUST be reported separately. Prevention caused by the common mandatory reservation gate MUST NOT be credited to a detector that proposed ALLOW; comparisons measure the explicitly composed detector-plus-controller configuration.

## 2. Baseline contracts and state-sufficiency question

B0 MUST receive only c_t, trusted static policy and current extraction features. It MUST NOT receive historical exposure or active-grant conclusions. Its direct sensitive-payload checks MUST be frozen and meaningful. A static prohibition is a definite violation; inability to validate a required historical permission is INDETERMINATE, not proof of unauthorized behavior. An outbound proposal lacking current warning features MAY be allowed under B0's stated operating point while its full task-contract authorization remains INDETERMINATE. That combination MUST NOT be presented as established authorization.

B1 MUST receive c_t and counts of H_t facts projected to event category, operation, resource, destination, outcome, sensitivity, transformation category and exact grant/use/revocation scope. IDs, ordinals, timestamps, predecessor links, current active-state flags, transition features, other findings and scenario labels MUST be removed. Its projection MUST preserve each scope's successful exposure count and G_s, R_s, U_s. Matching-order sanity pairs MUST have byte-identical serialized B1 inputs.

B1 is one conservative unordered policy. For a required scope:

- G_s > U_s and R_s = 0: AUTHORIZED under the normalized contract.
- G_s <= U_s: UNAUTHORIZED under the normalized contract, assuming a validated lifecycle.
- G_s > U_s and R_s > 0: INDETERMINATE; historical counts cannot establish current permission.

Static prohibitions are UNAUTHORIZED. Across required scopes, a definite failure yields UNAUTHORIZED; otherwise any uncertainty yields INDETERMINATE; otherwise authorization is established. A proposal with no release obligations is authorized unless statically prohibited. Conservative B1 MUST deny INDETERMINATE required release permissions, recording SUSPICIOUS rather than inventing a definite policy violation. Extraction accuracy remains a separate oracle question.

B2 MUST evaluate the same normalized contract using ordered grant/revoke/use transitions and successful acquisition facts. Missing permission solely due to coarse prior exposure MAY yield SUSPICIOUS behavior even when conservative contract authorization is UNAUTHORIZED; this distinction MUST be explicit. Authorization assessment MUST NOT be conflated with actual sensitive-byte release.

All general claims MUST name conservative B1. Claims about unordered representations generally require a mandatory ambiguity analysis: group identical allowed inputs with opposite independent authorization labels and report mixed-label groups and their minimum binary error count, sum(min(authorized_count, unauthorized_count)). This is a bound for those observed groups, not a population theorem. A second B1 operating point is optional.

RQ2 SHALL be: "Does incremental B2 reproduce a full-prefix reference evaluator for the frozen policy, and what processing and state-retention costs differ?" Bounded-history windows are NOT mandatory.

The mandatory correctness comparison MUST use B2-R, a reference evaluator reconstructing policy state from the complete eligible prefix for each proposal, and B2-S, the incremental B2 implementation. B0/B1/B2-S remain the representation comparison. B2-R and B2-S MUST independently implement transition evaluation; they MAY share schemas, extraction and canonical explanation formatting. On the same valid prefix they MUST agree on authorization assessment, behavioral verdict, rule IDs and deterministic supporting references. Dispatch selection MUST agree when evaluated against identical actual state. This is implementation equivalence, not oracle correctness or novel detection.

Memory reporting MUST include exposure state, active grants, ID uniqueness/tombstones, correlation/lifecycle validation, supporting references and queued work. Detector-only retained state, total monitor memory, sealing/export buffers and audit disk space MUST be distinguished. Constant-memory claims are prohibited unless measured and justified for a bounded universe.

## 3. Frozen Wang-style conformance subset

Reference repository: https://github.com/wilesanGH/mcp-pep-agent-security

Pinned revision: 3dd9690b5b6f9c4ef385289714b314d13f6ad9a1.

Reference basis: prototype/pep/enforcer.py, prototype/pep/label_tracker.py, prototype/pep/rules.py and prototype/datatypes.py at that revision. The retained decision rule is R02 plus its default-allow behavior on the declared common surface. Other reference rules are excluded from this subset; ChainGuard's common static safety envelope remains separately reported.

At each proposal the adaptation MUST merge current-argument sensitivity with accumulated trace sensitivity; SENSITIVE wins. Accumulated sensitivity MUST initialize NORMAL and become sticky after successfully returned result sensitivity. Current-argument sensitivity affects that decision; it MUST NOT alone mutate accumulated state when no result occurs. Denied/failed-without-result calls MUST NOT create successful acquisition. Unknown results terminate covered evaluation rather than establish NORMAL.

Map controlled acquisition tools to filesystem.read_file, declared transformations to neutral non-R02 tools, and every configured capture-sink destination to http_post.post. A local sink is an experimental stand-in for outbound release, NOT the reference's internal notify/send_message category. Destination identity MUST NOT add an exception to R02. A grant MUST NOT bypass R02. On the common valid surface, token/tool admission is enabled and call limits are nonbinding.

Exclude R01/R03/R04/R05, source-integrity propagation, intent-taint, confirmation UX, rate limits, capability exhaustion, source path-normalization experiments, original logging and LLM behavior. This is a sensitivity-policy subset adaptation, NOT reproduction of the full reference system. Published reference baseline labels MUST NOT be renamed B0/B1/B2; disabling its source-integrity propagation does not remove its accumulated sensitivity.

The comparison MUST use common frozen sensitivity facts injected into both the adapter and a reference-subset driver. This compares policy semantics, not the original regex extraction pipeline. Source behavior outside the defined input domain MUST NOT be silently treated as reproduced.

Before final-study use, differential tests MUST agree on decision, matched R02 rule, effective sensitivity and post-outcome accumulated sensitivity for: no-history sensitive outbound arguments; benign outbound with no history; successful sensitive result then benign-looking outbound; public results/transformations after sensitive exposure; denied/failed acquisition; sensitive current arguments without a subsequent result; all mapped destinations; grant presence; and no reset on permitted reconnect. Failed conformance MUST block baseline inclusion and claims. No adaptation is implemented by this amendment.

## 4. Independent oracle observations and labels

Every fixture MUST specify contracts and expected side effects before its evaluated results are presented, including Evaluation-1 fixtures.

The existing fixture harness MUST independently retain issued and admitted host controls, control-commit witnesses, raw proposals before decisions, controller admission order, reservation-commit witnesses, forwarding attempts, source handler observations, sink receipts/bytes and task outputs. This assessor-held journal MUST be outside the simulated audit-storage attack surface. It MUST NOT be reconstructed solely from ChainGuard's SQLite, normalized events or detector findings. Commit witnesses MUST originate at observed transaction-completion boundaries, not by copying a later normalized audit record. These observations assume the trusted runtime/fault-injection boundary and are not cryptographic proof against a dishonest monitor.

The authorization oracle MUST independently implement the written contract using raw fixture observations and its own state reconstruction. It MUST NOT call B2 or import its transition state. Before each proposal decision it MUST snapshot the permission state and label that proposal AUTHORIZED, UNAUTHORIZED or INDETERMINATE. Denied proposals MUST receive the same label procedure despite having no dispatch. If observations are insufficient, the label is INDETERMINATE and excluded from binary authorization metrics with its count disclosed.

The oracle MUST preserve five separate dimensions:

| Dimension | Independent evidence and boundary |
| --- | --- |
| Contract authorization | Ordered controls with successful commit witnesses, successful source observations, raw proposal and independently evaluated contract features immediately BEFORE its reservation/decision |
| Actual dispatch | Proxy-forward attempt observation AND controlled tool-handler arrival; distinguish attempted forwarding from confirmed tool receipt |
| Permission consumption | Independently retained successful reservation-commit witness listing the entire grant set; reconstruct and check its correctness without detector state |
| Actual disclosure | Destination-tagged sink receipt and bytes tested against fixture-held canaries and declared decoding coverage |
| Task completion | Fixture-specific outputs, files, receipts and side effects |

Consumption witnesses MUST identify the call, scope set and grant IDs without using a detector verdict as the label. If a crash makes the commit witness unavailable, consumption MUST be UNKNOWN, not assumed absent. A later audit deletion MUST NOT erase an independently retained witness.

Actual unauthorized disclosure MUST be assessed for the resources really delivered against the preserved pre-reservation permission snapshot, not the already-consumed state. A public transfer can violate the conservative exposure contract without disclosing sensitive bytes. Unsupported leakage forms MUST remain outside coverage.

Authentic-but-wrong tests MUST separately cover incorrect facts with consistent findings, correct facts with incorrect findings, and an omitted action witnessed independently by source/sink or forwarding observations. Missing independent observations MUST be reported as an unevaluable completeness case.

## 5. Restart, sealing and complete-run acceptance

### 5.1 Restart containment

Each monitor process start MUST create a fresh monitor_instance_id. Unexpected monitor termination makes its unfinished sessions incomplete and invalidates all unconsumed grants and task attachments. The harness MUST terminate the affected scripted client context and discard its saved payload variables, buffers and conversation state. Automatic client reconnect or request replay after MONITOR restart is prohibited.

A new monitor MUST NOT accept an old context or reconstruct trusted exposure/grants from SQLite. A new task/session requires a fresh fixture client/context, fresh identities and a new independently issued expected-run challenge. A failed expected run MUST remain failed/incomplete; replacement MUST NOT hide it by shrinking its inventory. If surviving context cannot be cleared under the controlled harness contract, execution MUST stop. This is bounded harness containment, not arbitrary host recovery.

DOWNSTREAM tool reconnect while controller/monitor stay alive MAY retain the existing task state, provided no call outcome is unresolved. Unknown outcome MUST halt the task. Closure state and outstanding work MUST be checked before sealing.

### 5.2 Sealing

The trusted monitor MUST maintain incremental count/head and task state independently of SQLite. On closure it MUST stop admissions, drain already admitted work to known terminal states, append the closing event, and freeze manifest digest, count, head and closure status. No record may be added to that session afterward.

The exporter MUST obtain a fixed snapshot, validate its schema/lifecycle/sequence, recompute its commitment and compare against frozen trusted values. Recomputed attacker values MUST NOT replace the trusted count/head. Divergence MUST prevent clean sealing. An unknown outcome, ambiguous commit, missing close, failed reconciliation or failed signature/export MUST yield INCOMPLETE/unsealed, never clean acceptance.

Signing and output MUST use the exact validated snapshot, without rereading mutable storage to substitute records. The final package MUST pass self-verification before export success is reported. Later byte mutation makes the altered package invalid; export success is not a promise of continuous storage integrity.

A3T MUST commit the ordered canonical object {manifest, records}, where records retain semantic envelopes and sequence but omit previous/current hash fields. Its SHA-256 input MUST be domain-separated with ASCII "CHAIN GUARD TRANSCRIPT-v1" followed by one zero byte. Its signed closure binds transcript digest, count, manifest digest and the same identities/status/suite as A3. Both forms MAY hash incrementally. Fair comparison MUST hold semantic records, durability, signature frequency and verification requirements equal; A3T MUST NOT also compute the unused event chain. Structural and cryptographic rejection MUST be reported separately. Exact schema/byte vectors MUST pass before signed-format implementation acceptance.

### 5.3 Fresh complete-run submission

Before execution the assessor MUST retain an immutable expected run/challenge, exact required task/session inventory, pinned signer keys and configuration digests. The manifest MUST bind the controller execution profile and this inventory's canonical SHA-256 digest. Session entries MUST identify expected task/session/monitor associations; monitor identity MUST be registered independently at launch before task execution. The package MUST NOT define or shrink its own acceptance expectations.

Inspection MAY be repeated and MUST NOT consume expectations. Fresh submission MUST present every required session exactly once, no unexplained additional sessions, matching run/task/session/challenge/configuration, a complete valid closure for each, and PASS for schema/lifecycle, commitment integrity, trusted signature, expected binding, inventory completeness and finding reproduction. INCOMPLETE or NOT_CHECKED in a required dimension MUST prevent acceptance. A run containing recorded security violations MAY be accepted as evidence; acceptance does not mean benign behavior.

The verifier MUST freeze/validate the submitted package snapshot. In one durable transaction it MUST recheck that the expected run is ACTIVE and unaccepted, record all authenticated session commitment digests and the whole-run acceptance identity, and transition the expectation to ACCEPTED. It MUST report acceptance only after confirmed commit. Failed/incomplete submissions MUST NOT consume expectations. Ambiguous registry commit MUST return an error and be reconciled on retry, never guessed successful.

Duplicate identity is authenticated (run_id, challenge) plus its expected inventory, NOT signature bytes. ACCEPTED expectations MUST reject subsequent submission including after verifier restart. CANCELLED/FAILED expectations and context mismatches MUST reject stale/wrong-run submissions. Registry rollback remains excluded. A valid individual signature MUST NOT accept a run missing another required session. Whole missing runs can only be identified against independent expected inventory.

## 6. Evaluation-1 and final-study boundaries

Evaluation-1 completion MUST be gate-based; no two-day completion or mark guarantee is made.

| Gate | Required evidence |
| --- | --- |
| M1 | Real supported MCP client -> proxy -> controlled tool; correlated success/error; modern stdio discovery/per-request metadata; no legacy handshake assumption |
| M2 | Frozen normalized facts, B0/B1/B2 shadow findings, identical shared execution history; benign and sensitive cases with prewritten oracle expectations |
| M3 | Typed SQLite events, trusted incremental count/head and operational failure handling; dispatch-intent selections remain empty if M6 is not implemented, and grant-bearing once-only consumption is tested at M6 |
| M4 | SHA-256 chain, ECDSA P-256 closure, pinned-key offline checks and deterministic finding reproduction |
| M5 | Intact acceptance; tampered record rejection; recomputed-chain rejection against original signature; pre-seal mutation refusing clean seal; duplicate rejection after verifier restart; wrong-task/old-run rejection; audit-write failure preventing forwarding |
| M6 | If time permits: one-use grant, scope revoke, NEW grant, first release consuming permission and second release denied without a new grant |

M1-M5 define the intended minimum slice. Missing gates MUST be reported as incomplete progress. A one-session demonstration run MAY use the same complete-run acceptance contract with a singleton inventory. If M6 is unfinished, authorization transitions remain mandatory final-project work and MUST NOT be claimed implemented by the progress demonstration.

A history-benefit demonstration MUST use an independently covered synthetic release outside the previously frozen direct detector's recognition coverage, with a credible declared sensitive source; detector coverage MUST NOT be weakened after selecting the case. Otherwise the demonstration MUST claim enforcement/progress only, not history superiority. Hard benign unrelated-public-transfer and failed-read controls MUST accompany interpretation.

Evaluation-1 MUST NOT require the external adaptation, A3T/A4T, full held-out corpus, scaling study or publication novelty. The external baseline, transcript comparison, held-out study and scaling measurements remain final-study work. Publication-level novelty is not a prerequisite for course-project completion; publication feasibility is unresolved. Dependency approval, explicit implementation authorization, student verification before milestone commit, and separate push/publication authorization remain required.
