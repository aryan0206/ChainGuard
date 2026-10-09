# ChainGuard Architecture Lock

**Version:** 1.1

**Synchronization date:** 7 October 2026

**Lock date:** 7 October 2026

**Owner decision:** research direction and mandatory scope approved; ECDSA P-256 retained. Following synchronization of the reviewed amendment and the owner's two scope clarifications, the owner explicitly locked the unchanged architecture as ChainGuard Architecture v1.1 on 7 October 2026.

**State:** **ARCHITECTURE LOCKED — ChainGuard Architecture v1.1**. Application implementation and dependency installation remain prohibited.

Chronology clarification, 9 October 2026: the original closed implementation/dependency wording records the 7 October architecture-lock stage. Later explicit owner instructions authorized the recorded M1–M5 milestones and Phase 2 foundation; their decisions and evidence are retained in [the engineering history](SPIKE_LOG.md#historical-engineering-readme-at-checkpoint-5d00057). Those later authorizations do not weaken Architecture v1.1 or grant blanket approval for dependencies, M6 or other work. The initial 9 October documentation cleanup excluded commits and pushes; that task-specific restriction does not override later explicit owner authorization.

This document is the single authoritative source of system architecture contracts. The [charter](PROJECT_CHARTER.md) defines research methodology; the [threat model](THREAT_MODEL.md) defines security assumptions and claim limits. Sections 15–20 incorporate the reviewed amendment's precise contracts. [ARCHITECTURE_AMENDMENTS_V1.md](../ARCHITECTURE_AMENDMENTS_V1.md) is historical supporting material only and has no independent normative authority. MUST, MUST NOT, SHOULD and MAY express normative requirements. This document records a design, not an implemented or tested system.

## 1. Direction and mandatory scope

ChainGuard is an explainable MCP sequence-security monitor with independently verifiable audit evidence. Its core study compares event representations and tests whether task-bound evidence can preserve and reproduce findings under storage manipulation and stale/duplicate submission.

Mandatory scope comprises local MCP stdio interception, application-level task tracking, B0/B1/B2 deterministic detectors, core grant/revoke/consumption capabilities, structured persistence, signed hash-chained evidence, offline verification, independent ground truth, controlled experiments and a minimal report/timeline. The final study also requires B2-R/B2-S correctness/cost comparison, the pinned Wang-style sensitivity-policy adaptation, and A3T/A4T transcript comparison under Sections 16–19. The core uses scripted MCP clients and controlled local tools; real LLM behavior is not required.

Grant, scope revocation and one-use consumption are CORE architecture capabilities and MUST be delivered for the final project. M1–M5 are the minimum Evaluation-1 vertical slice. M6 is optional for Evaluation 1 and mandatory for the final project; its absence in Evaluation 1 MUST NOT weaken, remove or redefine the final architecture.

Sequence detection and evidence verification are connected by the exact normalized observations, policy and detector versions that produced each finding. Signing a generic log alongside an unrelated detector would not satisfy this design.

No claim of first session-level MCP security, a novel cryptographic primitive, universal exfiltration prevention or guaranteed publication is authorized.

## 2. Layers and responsibilities

| Layer/component | Sole primary responsibility | Mandatory output |
| --- | --- | --- |
| Trusted host context | Create identities; serialize controls/proposals; own actual execution permissions independently of shadow detectors | Task context, grant/revoke state, atomic dispatch reservation and run challenge |
| MCP stdio proxy | Observe the supported request/result path and apply recorded dispatch decisions | Correlated call phases and outcomes |
| Event normalizer | Produce stable, redacted policy facts from the controlled tool contract | Versioned normalized records |
| Session tracker | Keep task-local state and ordered event prefixes across reconnects | Isolated task state and lifecycle |
| B0/B1/B2 detectors | Evaluate permitted representations under fixed policy | Behavioral verdict, rule and supporting event IDs |
| Audit writer | Append observations/findings transactionally and seal closed sessions | SQLite records, chain and signed commitment |
| Offline verifier | Check evidence structure/origin/context and reproduce deterministic findings | Separate verification dimensions and diagnostics |
| Evaluation harness | Execute independent fixtures and collect oracle outcomes | Ground truth, baseline results and mutation ledger |
| Minimal report | Explain timelines and evidence-linked findings | Behavioral and evidence status displayed separately |

Flow: trusted context -> proxy -> normalized observation -> detector -> persisted decision -> dispatch if allowed -> persisted result -> updated task state. Session closure produces a signed evidence package; the verifier consumes that package without contacting or executing tools.

Observation mode records B0/B1/B2 shadow decisions against one controller-generated history; shadow outcomes MUST NOT control forwarding or consume grants. Normal observation mode MUST NOT bypass authorization. An unauthorized proposal MAY be forwarded ONLY through an explicitly configured synthetic local-sink observation override, as defined in Section 15.2. Enforcement uses a separate execution for each detector/configuration, with detector decisions and the common reservation gate controlling actual dispatch. Mode and controller execution profile, including the default-disabled override setting, MUST be committed in the manifest.

## 3. Technology and protocol boundary

- Runtime: Python; persistence: SQLite; proxy transport: MCP stdio only.
- Protocol target: published MCP specification 2026-07-28, with an explicitly documented supported subset. A stable compatible SDK version must be checked and approved before installation.
- Handle modern discovery/version selection, required per-request metadata, supported tool discovery/calls, correlated responses and errors. The 2026-07-28 subset MUST NOT assume a legacy initialize handshake. Legacy compatibility is deferred. Document unsupported features; do not advertise full MCP compliance without testing it.
- This protocol target is stateless at the protocol level. ChainGuard's security task/session context is application-managed, not supplied by a transport process or an untrusted client metadata field.
- Initially process security-relevant calls sequentially within a task. Cross-task interleaving must preserve isolation; concurrent calls within one task and distributed ordering are outside core coverage.
- Scripted client and controlled tool server run locally. No HTTP gateway, cloud service, VM, container, packet capture, complex frontend or real LLM dependency is mandatory.
- Candidate external dependencies are a compatible MCP Python SDK and a maintained cryptographic library. Exact versions, transitives and installation are not yet approved.

## 4. Controlled tool and policy contract

The registry defines supported public reads, sensitive reads, declared transformations/encodings and a local capture sink representing an outbound destination. Labels and resource/destination identities come from trusted fixture/registry contracts, not from tool-provided prose. Synthetic canaries replace real secrets.

Two bounded policy families are mandatory:

1. **Sensitive-release sequences:** successful sensitive access followed by a proposed transfer to a destination lacking applicable authorization is suspicious. Declared transformations and harmless intervening calls do not erase exposure. This is an explainable overapproximation, not proof that the outgoing payload derives from that read.
2. **Scoped authorization ordering:** host grants and revocations determine whether a release permission is active at the transfer point. Unauthorized release under this contract is a policy violation, distinct from a suspicious association.

Host grants use exact atomic (task, resource, destination, release) scopes and opaque unique IDs. Scope revocation invalidates currently active grants; a later authentic NEW grant ID may restore permission. One grant permits one committed dispatch intent. Multi-grant selection, consumption and intent MUST be all-or-nothing under Section 15.1; consumption persists after failed/unknown dispatched outcomes. Denial consumes nothing. Dynamic wildcards, wall-clock expiry and interactive consent interfaces are deferred.

Static destination/resource policy applies to all detectors. Sensitive reads update exposure only on successful results; failed or denied reads do not. Public reads, transformations and elapsed time do not clear prior exposure. Policy may deliberately overflag a subsequent unrelated public transfer; such cases belong in hard benign evaluation rather than being relabeled malicious.

Behavioral findings use ALLOW, SUSPICIOUS or POLICY_VIOLATION. Dispatch uses a separate ALLOW/DENY decision. In enforcement mode both SUSPICIOUS and POLICY_VIOLATION are denied under the core conservative policy. Every finding carries its rule, explanation, policy digest and supporting event IDs.

## 5. Task and session lifecycle

- A run identifies an experiment/execution configuration; a task identifies the authorized workflow; a session identifies one evidence stream for that task.
- The trusted host creates these identifiers and associates every supported call with exactly one active context. Client identity strings and MCP metadata do not authenticate the host or establish context.
- A downstream reconnect MAY continue the same task state only while trusted monitor/controller state survives and no outcome is unresolved. Monitor restart MUST invalidate unfinished context and grants, terminate the affected controlled client context, and require a fresh client/task/session/expected run under Section 19.1. Unknown/missing context MUST NOT be silently treated as clean.
- Core lifecycle is CREATED -> ACTIVE -> CLOSED. Failures leave an incomplete stream rather than a fabricated clean closure. Closed task contexts cannot be reopened; new tasks receive new identities and isolated memory.
- Reset requires trusted closure and task-state separation. Cross-task memory/data sharing is outside the core model and cannot be used as a benign reset loophole.
- Sequence numbers start at 1 and are contiguous per evidence stream, assigned by the audit writer. Event IDs are unique within the stream; each call attempt has a distinct call ID. Correlated call IDs connect request, decision, dispatch and outcome records. Reject duplicates or invalid phase relationships during verification.
- A session-start and session-end record allow even a zero-call session to be represented. Missing end/commitment means incomplete evidence.

## 6. Detector contracts

All detectors receive identical current normalized observations, static policy and controlled tool semantics. Their permitted historical representations differ. Decisions are evaluated against the prefix available at the decision point; no future result is visible.

H_t is exactly the committed semantic projection in Section 15.3: prior tool outcomes, grants, scope revocations and once-only USE facts from dispatch intent. Findings, controller authorization conclusions, other detectors' decisions and audit bookkeeping MUST NOT become features. Operational fail-closed decisions and common reservation refusals MUST NOT be credited as detector successes.

| Baseline | Permitted information | Excluded information |
| --- | --- | --- |
| B0: stateless | Current call and current normalized payload features; static policy | Previous calls/control events or derived historical state |
| B1: unordered prefix | B0 plus a multiset/count representation of prior semantic facts by scope | Prior-event ordering, sequence/timestamps, latest-grant state, transition features |
| B2: ordered deterministic | B0 plus ordered prefix/state transitions and evidence references | Future events, unobserved payload provenance or oracle labels |

B0 must be a credible per-call policy: include direct sensitive-pattern checks on the current outgoing payload for the explicitly supported raw/encoded forms and destination restrictions. It is not a deliberately weak tool-name allowlist.

B1 retains successful exposure and exact scoped G/R/U counts; its behavioral projection excludes IDs, ordering, timestamps and derived active-state flags. Under Section 16, G > U and R = 0 establishes permission; G <= U establishes absence under a validated lifecycle; G > U and R > 0 is INDETERMINATE. Conservative denial of uncertainty MUST NOT fabricate an unauthorized fact. Lifecycle validation and evidence-reference mapping MUST NOT leak discarded order into the behavioral projection. Claims MUST name this conservative B1 policy.

B2-S maintains ordered incremental exposure and grant/revoke/use state. B2-R independently reconstructs state from the complete eligible prefix for equivalence/cost checks under Section 16; it is not another detector policy. Rule tables, deterministic references, transitions and extraction versions MUST be frozen before held-out evaluation. Sticky exposure alone is representable by B1 and MUST NOT be claimed to require order.

Read-then-send versus send-then-read is useful to test context, but is insufficient to isolate B1/B2 ordering: B1 already knows the prefix preceded the current call. Mandatory matched-order cases use equal scoped prior semantic counts with changed ordering, for example:

- Successful sensitive read -> grant -> revoke -> proposed send: revoked permission.
- Successful sensitive read -> revoke -> new grant -> proposed send: active permission, provided the new grant matches scope and has not been consumed.

Use distinct valid grant IDs and matched semantic categories/scopes; do not manufacture a grant replay. Include authorized release, unrelated public transfers, failed reads, encoding and reconnect cases. Report the ordering advantage for the policy families actually studied, not as a universal security result.

## 7. Event and finding schema

Every persisted record is a versioned typed event. Required common fields are:

| Field group | Required meaning |
| --- | --- |
| Identity | schema_version, run_id, task_id, session_id, monitor_instance_id, event_id |
| Ordering | seq, prev_hash; observed_at_utc for display only |
| Type/correlation | event_type, call_id where applicable; request/decision/dispatch/result/control/start/end distinguished |
| Observation | server/tool identity, normalized resource/destination, sensitivity, supported payload/transform features |
| Outcome | proposed, allowed, denied, dispatched, succeeded, failed or unknown as applicable to the event type |
| Trusted control | grant/revoke scope, opaque grant ID and host origin classification where applicable |
| Finding | detector_id/version/artifact digest, policy_digest, behavioral verdict, AUTHORIZED/UNAUTHORIZED/INDETERMINATE assessment, dispatch decision, rule_id, supporting_event_ids, explanation |

Fields are type-specific rather than nullable placeholders everywhere. Dispatch intent MUST contain call_id, required_scopes, selected_grants and reservation_status, with once-only USE projection under Section 15.3. Reference only existing events within the available prefix. Preserve raw protocol request IDs safely for correlation if needed; they do not establish uniqueness across tasks.

Redact raw arguments, secret payloads and irrelevant responses before persistence. Keep the policy-sufficient normalized facts needed to reproduce B0/B1/B2. Do not store plaintext hashes of low-entropy secrets and call that confidentiality. Stable resource/destination identifiers must be documented so normalization does not erase scope relationships.

The verifier can reproduce decisions from committed normalized facts; it cannot independently prove that the monitor classified raw content correctly when raw content is not retained. The separate evaluation oracle tests normalization/detection correctness against fixtures.

## 8. Canonicalization and chain

Use a documented restricted JSON schema, UTF-8, sorted object keys, fixed compact separators, explicit strings/booleans/null and bounded integers. Reject duplicate object keys, non-finite values, floating-point numbers, invalid types, unknown schema versions and out-of-range integers. Integers are limited to the exact interoperability range through 2^53-1 in magnitude; larger values must use schema-defined decimal strings. Unicode strings are preserved without implicit normalization. This is a project canonical format, not a claim of RFC 8785 compliance.

Finalize type-specific field schemas and canonical test vectors before implementation acceptance. Cryptographic inputs are canonical bytes, never pretty-printed database exports.

- Manifest digest = SHA-256(domain MANIFEST-v1 || canonical manifest).
- Genesis value = SHA-256(domain GENESIS-v1 || manifest digest).
- Event hash = SHA-256(domain EVENT-v1 || canonical event), with prev_hash, identity and sequence inside the canonical event; exclude the event's own hash field.
- The first record links to the genesis value; each later record links to the preceding event hash.

Domain tag bytes are ASCII CHAIN GUARD MANIFEST-v1, CHAIN GUARD GENESIS-v1, CHAIN GUARD EVENT-v1 and CHAIN GUARD COMMITMENT-v1 respectively, followed by one zero byte. Hash input uses the relevant tag followed by canonical bytes, except genesis which uses the tag followed by the raw 32-byte manifest digest. Signing input uses the commitment tag followed by canonical commitment bytes. Store digest presentation as lowercase hexadecimal and validate lengths/encoding.

The trusted running monitor supplies authoritative next sequence, count and head; SQLite transactions append complete events/hashes atomically. Trusted memory advances after confirmed commit under the task gate. Ambiguous commit halts the task without forwarding or adopting database state. Existing records are append-only through the application, which does not prevent direct storage mutation. Recomputed unkeyed hashes MUST NOT replace trusted running commitments; Sections 15.1 and 19.2 govern reservation and sealing.

## 9. Manifest and signed closure

The manifest binds schema/canonicalization/protocol versions, observation scope, run/task/session identity, execution mode, controller execution profile including synthetic_local_sink_override (default false), assessor-provided run challenge, expected-inventory digest, monitor instance, policy/tool-registry/normalizer/detector digests, and code revision plus artifact digests. Version labels alone are insufficient. Do not sign local secrets or environment values.

On clean closure, freeze trusted running state and validate the exact export snapshot before signing under Section 19.2. The commitment contains manifest digest, stream identity, final chain hash (A3) or complete-transcript digest (A3T), total record count, closure status, algorithm identifier and signer key ID. Post-validation storage MUST NOT substitute records into the signed package.

**Selected signature suite: ECDSA over NIST P-256 (secp256r1), hashing the canonical domain-separated commitment with SHA-256.** Use a maintained library's ECDSA-with-SHA-256 API; do not accidentally hash twice or generate ECDSA signing nonces manually. The signature is DER encoded and transported in base64; the suite and encoding are explicit in the schema. Verify using the externally trusted P-256 public key selected by key ID.

The suite identifier is ECDSA-P256-SHA256-DER-v1. Reject unknown suites, mismatched curves and algorithm downgrade attempts; the bundle cannot select a weaker verification algorithm. The assessor issues a fresh 32-byte cryptographically random run challenge, represented as lowercase hexadecimal, and retains its association with the expected run independently of the package.

Private signing keys stay outside the audit database and repository. The verifier pins an assessor-approved public key independently of the evidence bundle. Accepting any public key provided by a bundle would defeat origin authentication. Key provisioning and replacement are explicit administrative actions; no certificate authority is required by the core.

ECDSA signing nonce security is delegated to the library; nonce reuse can disclose the private key. This nonce is distinct from a run challenge and from an encryption nonce. Signature byte strings are not replay identifiers: ECDSA signatures may vary for the same content. Deduplicate by authenticated run/task/session/challenge identity.

Per-event signing is not mandatory. The final commitment detects changes to the committed stream, including truncation relative to its authenticated count/head. Before closure the tail is unsealed; the design is not forward secure after signing-key compromise.

## 10. Evidence package and offline verifier

An export contains the manifest, complete ordered records and hashes, signed closure and required policy/registry/detector references or artifacts. The verifier checks those against trusted expected configuration/digests; bundled executable code is never run merely because the bundle asks for it. Reproduction uses the approved verifier's detector implementation and version.

Verification must independently report:

1. Schema/canonical structure and sequence/link validity.
2. Signature and trusted-key origin.
3. Expected run/task/session/challenge and configuration binding.
4. Completeness relative to the signed closure and trusted expected-session inventory.
5. Deterministic finding reproduction and any mismatch.

Report PASS/FAIL/INCOMPLETE/NOT_CHECKED per dimension with reasons; do not collapse an authentic but stale package into a valid fresh submission or an incomplete run into a clean behavioral result. A valid signature does not make a wrong decision correct.

Two modes are distinct:

- **Inspect:** repeatable offline integrity/origin/reproduction checks; inspecting the same authentic package again is permitted.
- **Fresh submission:** require the entire independently expected run/session inventory and PASS in every required verification dimension; atomically accept the whole run in durable verifier state under Section 19.3. A single valid session signature MUST NOT accept an incomplete multi-session run. Stale contexts and duplicates are rejected, including after verifier restart.

The expected-run inventory and acceptance registry must be outside the attacker's audit-storage write authority. Persistence must survive verifier restarts. Registry rollback is outside the claimed defense unless an independently retained latest state is available. Merely placing a nonce or timestamp inside a signed bundle does not prove freshness.

Whole-session deletion is detectable only when the verifier independently knows that session was expected. A valid committed prefix presented as a complete later run requires a trusted expected final commitment/inventory to reject rollback. Local timestamps provide ordering context, not an external trusted timestamp service.

These checks defend evidence submission, not replay of actual MCP commands. Verification never replays side effects.

## 11. Failure and recovery behavior

- In ALL modes, do not dispatch if the required request/decision/dispatch audit append cannot complete. An observation override MUST NOT bypass operational persistence controls. Report audit failure separately from a threat finding.
- Persist the decision and dispatch intent before forwarding the call. Persist the result after completion. Database commits and external tool effects are not one atomic transaction.
- A crash between dispatch intent, forwarding and result recording leaves an unknown outcome, halts the task and prevents clean sealing. Do not automatically replay the call or refund consumed permission; monitor restart follows Section 19.1.
- Signing/export failure leaves incomplete or unsealed evidence and a clear error; it cannot roll back actions already executed.
- A denied/failed call is recorded and correlated, but a failed sensitive read does not become successful exposure.
- Storage manipulation is detected when evidence is checked under the verifier's trusted inputs, not necessarily at the moment an attacker edits a file.

## 12. Confidentiality and extensions

The mandatory core minimizes retained data: redacted normalized facts and synthetic evaluation data. Hashing and signatures do not encrypt these records or hide metadata.

If sensitive payload retention is later approved, encrypt payload blobs with AES-GCM using a separate encryption key outside the database. Use a documented nonce allocator guaranteeing uniqueness per key, including after restart; rotate the key if uniqueness cannot be guaranteed. Bind stable run/task/session/event identities as associated data and commit the ciphertext digest in the event chain. Avoid circular associated-data/hash definitions. Authentication tag checks are mandatory. This protects blobs, not the entire SQLite database or a compromised running monitor.

| Extension | Reason deferred / condition for approval |
| --- | --- |
| B3 ML | Require enough independently labeled data and grouped holdouts; compare counts-only versus ordered-transition features. Start with a lightweight logistic model in observation mode if justified. |
| Periodic signed checkpoints | Useful for live evidence; requires trusted latest-checkpoint retention to address rollback, not just more signatures. |
| Real LLM/prompt-injection study | Adds stochastic behavior and a separate robustness question; scripted mechanisms cannot establish LLM robustness. |
| Other transports/concurrent calls | Requires new ordering, identity and compatibility contracts. |
| Encryption of sensitive blobs | Conditional on approved retention; not a reason to retain unnecessary secrets. |
| PKI, trusted timestamping, distributed ledger, richer UI | Not needed for the bounded core claim. |

B3 would use only available-prefix features, no labels/rule verdicts/scenario IDs or future events. It remains outside mandatory implementation and core publication claims. An LLM detector is not approved.

## 13. Mandatory acceptance criteria

The completed core must demonstrate all of the following with reproducible evidence:

- Real supported MCP stdio interception and correlated request/decision/result events, with task isolation and reconnect continuity.
- Meaningful conditional B0/B1/B2 comparisons, B2-R/B2-S equivalence/cost checks, the pinned reference adaptation and hard benign/held-out workflows under frozen contracts.
- Successful/failed/denied read correctness, core grant/revoke/one-use consumption, atomic multi-grant reservation, deterministic control ordering and separately attributed enforcement behavior.
- Trusted incremental commitments, transactional records, exact-snapshot P-256 sealing, A3/A3T and A4/A4T comparisons, and independently pinned verifier configuration.
- Tamper tests including edit, deletion, reordering, insertion, splicing, hash recomputation, key/configuration substitution and committed suffix truncation.
- Fresh-context and duplicate-submission tests with durable verifier state, plus an explicit incomplete/missing-session limitation demonstration.
- Offline reproduction of findings from committed normalized facts, with evidence references displayed in a minimal report.
- Independent proposal-level authorization, source/sink/consumption/task observations, held-out evaluation, raw results and overhead measurements as specified in the charter.
- Documented failure boundaries and student explanation of each major component.

These are FINAL-project criteria. Evaluation 1 uses M1–M5 and optional M6 under Section 20; incomplete M6 MUST NOT alter final core scope. No numerical accuracy target, novelty claim, protocol-support claim or mark guarantee is inferred. Partial progress MUST be labeled partial.

## 14. Change control and reference basis

For material changes, propose current/proposed design, reason, benefit, complexity, module/test/paper/timeline impact and obtain owner approval. Then amend this document's version, date and decision record and synchronize the controls. Exact implementation schemas, test vectors and approved dependency pins may refine these contracts; changes to their security semantics require approval.

Decision record: version 1.0 recorded the earlier design and ECDSA P-256 selection. Version 1.1 synchronizes the six reviewed contract blockers and the owner's explicit observation-override/Evaluation-1 clarifications on 7 October 2026. On the same date, the owner explicitly declared ARCHITECTURE LOCKED — ChainGuard Architecture v1.1 without changing the architecture. The lock declaration authorizes no application implementation, dependency installation, experiments, commit, push or publication.

Design references: [MCP basic protocol](https://modelcontextprotocol.io/specification/2026-07-28/basic), [stdio transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports), [Python SDK](https://github.com/modelcontextprotocol/python-sdk), [NIST digital signature standard](https://csrc.nist.gov/pubs/fips/186-5/final), [AES-GCM guidance](https://csrc.nist.gov/pubs/sp/800/38/d/final), and [signed syslog precedent](https://www.rfc-editor.org/rfc/rfc5848.html). These are design references, not dependency installation approvals or claims of standards certification.

## 15. Execution authority and historical input

### 15.1 Common authorization and ordering boundary

The existing trusted host/controller MUST maintain actual execution permissions independently of detector outputs. Its execution ledger MUST receive admitted controls and committed normalized tool outcomes through the execution path, not detector state. It MUST NOT call B2 to manufacture shared history or read any shadow verdict as an input. Sharing the written permission specification is permitted. This controller is execution authority, NOT the evaluation oracle.

Each task MUST have one FIFO admission queue for host controls and tool proposals. The controller MUST assign an increasing admission ordinal on receipt and the fixture harness MUST independently retain admitted input order. Local timestamps MUST NOT decide order. One proposal turn MUST cover pre-decision state, all detector evaluations, dispatch reservation, forwarding, and terminal result processing. Later grants/revocations MUST wait until that turn completes. A queued revocation MUST NOT cancel an already committed dispatch intent. Calls MUST NOT run concurrently within one task.

Each control turn MUST durably append its control event before activating its grant/revocation transition. Failed control persistence MUST leave the transition unapplied and halt the task; ambiguous commit MUST leave authority unknown and halt. The harness MUST independently retain control-commit witnesses as well as issued/admitted controls. Queued or issued approval alone MUST NOT become usable permission.

For a supported outbound proposal, the stipulated conservative contract requires exact release permission for every resource in the union of successful prior sensitive acquisitions and directly recognized current sensitive-resource facts. Non-release operations have no release obligation. Static prohibitions override grants. An unresolved sensitivity-to-resource mapping MUST be treated as operationally unsupported, not guessed. Actual public payloads can consequently fail this conservative contract; that is not proof of disclosure.

An atomic scope is (task_id, resource_id, destination_id, release). Grant IDs MUST be unique opaque values, used for lifecycle correlation but not B1 features. Each grant permits one committed dispatch intent. Scope revocation MUST invalidate all currently active grants for that exact scope; a later NEW grant ID MAY restore permission. Revocation with no active grant is a valid no-op. Grants MUST NOT outlive the task or survive monitor restart. Dynamic wildcards and wall-clock expiry are excluded.

For each required scope, selection MUST choose the lexicographically smallest active matching grant ID. One transaction MUST persist the proposal decision records and one dispatch-intent record containing the complete selection. Consuming all selected grants, appending intent, allocating audit sequence numbers and advancing trusted commitment/state MUST constitute one logical all-or-nothing reservation. This is not an atomic transaction with tool execution: trusted memory advances after confirmed database commit under the task gate. No forwarding is permitted until successful durable commit is confirmed and trusted running state is advanced. A failed reservation MUST consume no subset. An ambiguous commit result MUST halt the task without forwarding or retrying; the reservation outcome is unknown, not falsely reported rolled back.

### 15.2 Observation mode

The controller MUST forward supported, statically admissible, AUTHORIZED proposals irrespective of B0/B1/B2 shadow outcomes, subject to operational readiness and confirmed audit persistence. Normal observation mode MUST NOT bypass authorization: unauthorized proposals MUST NOT be forwarded unless the explicitly configured synthetic local-sink observation override applies. Static safety prohibitions and unsupported operations MUST still prevent dispatch.

If the controller can reserve the entire required grant set, it MUST consume that set with dispatch intent. If permission is unavailable, forwarding is permitted ONLY when synthetic_local_sink_override is explicitly true in the committed controller execution profile AND the proposed destination is the configured synthetic local capture sink AND the payload/workflow is within the approved synthetic experiment. The setting MUST default to false; mode = observation alone MUST NOT enable it. No external destination, real sensitive payload, static prohibition or operational failure can use this override. An override dispatch MUST record an empty selection and MUST NOT partially consume available grants. It remains unauthorized under the stipulated contract.

Shadow detectors MUST NOT issue controls, alter execution, consume grants, select actual grants, or mutate the shared execution ledger. Each detector MAY update its own representation using the same committed semantic observations. Current controller authorization/override status MUST NOT be passed to a shadow detector as an extra feature.

Thus observation comparisons measure decisions conditional on ONE controller-generated execution history, not counterfactual detector-controlled trajectories.

### 15.3 Exact H_t

Immediately before proposal t is evaluated, H_t MUST contain only committed prior semantic facts from that task:

1. TOOL_OUTCOME: one terminal outcome per prior call, including operation, resource/destination, status, sensitivity and declared transformation facts.
2. GRANT: one admitted grant and its exact scope.
3. REVOKE_SCOPE: one admitted scope revocation.
4. USE: one fact per selected grant in a successfully committed dispatch-intent record.

USE is a projection of dispatch intent, NOT a second independently appended consumption event. The dispatch_intent body MUST contain call_id, required_scopes, selected_grants and reservation_status. Each selected_grants entry MUST contain grant_id and its resource/destination/release scope; task identity comes from the envelope. reservation_status MUST be AUTHORIZED, OBSERVATION_OVERRIDE or NO_RELEASE_OBLIGATION. Selection and required-scope arrays MUST be canonically sorted; AUTHORIZED MUST cover the full nonempty requirement set; the other statuses MUST have an empty selection. OBSERVATION_OVERRIDE requires observation mode and a nonempty requirement set; NO_RELEASE_OBLIGATION requires an empty requirement set. Auxiliary copies of these facts MUST NOT create more USE facts or feed controller conclusions to detectors. Existing envelope names seq and prev_hash remain unchanged; no alias fields are introduced.

Duplicate selected IDs and duplicated intent/call phase records MUST be rejected. A dispatch with an empty selection generates no USE. Tool outcomes MUST NOT generate additional consumption facts.

Prior proposals, findings, shadow decisions, explanation text, controller authorization conclusions, timestamps, audit hashes and lifecycle bookkeeping MUST NOT become behavioral history features. Lifecycle records remain available for validation and task partitioning. The current persisted proposal is c_t, not a prior fact in H_t.

Failed/denied acquisition MUST NOT create successful exposure. Controlled acquisition failures MUST return no sensitive partial payload; partial/ambiguous result forms are unsupported and MUST halt the task. A dispatched failed call retains its committed consumption. A denied/non-dispatched proposal consumes nothing. Unknown outcomes MUST be recorded where possible, halt further security-relevant calls and make the stream incomplete; consumed permissions MUST NOT be refunded or tool calls automatically replayed.

### 15.4 Enforcement mode

Each detector/configuration MUST receive a separate execution with fresh task/session identities and equivalent fixture inputs. Its findings control allow/deny under its frozen operating point. A denial MUST NOT consume grants. An allowed call needing permissions MUST pass the same atomic reservation procedure; an authoritative reservation refusal MUST be reported separately from the detector's proposed decision. Observation overrides MUST NOT apply.

Future outcomes and history are specific to that execution. Enforcement trajectories MUST NOT be described as identical-input representation comparisons. Detector error rates, controller refusals and actual task consequences MUST be reported separately. Prevention caused by the common mandatory reservation gate MUST NOT be credited to a detector that proposed ALLOW; comparisons measure the explicitly composed detector-plus-controller configuration.

## 16. Baseline contracts and state-sufficiency question

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

## 17. Frozen Wang-style conformance subset

Reference repository: https://github.com/wilesanGH/mcp-pep-agent-security

Pinned revision: 3dd9690b5b6f9c4ef385289714b314d13f6ad9a1.

Reference basis: prototype/pep/enforcer.py, prototype/pep/label_tracker.py, prototype/pep/rules.py and prototype/datatypes.py at that revision. The retained decision rule is R02 plus its default-allow behavior on the declared common surface. Other reference rules are excluded from this subset; ChainGuard's common static safety envelope remains separately reported.

At each proposal the adaptation MUST merge current-argument sensitivity with accumulated trace sensitivity; SENSITIVE wins. Accumulated sensitivity MUST initialize NORMAL and become sticky after successfully returned result sensitivity. Current-argument sensitivity affects that decision; it MUST NOT alone mutate accumulated state when no result occurs. Denied/failed-without-result calls MUST NOT create successful acquisition. Unknown results terminate covered evaluation rather than establish NORMAL.

Map controlled acquisition tools to filesystem.read_file, declared transformations to neutral non-R02 tools, and every configured capture-sink destination to http_post.post. A local sink is an experimental stand-in for outbound release, NOT the reference's internal notify/send_message category. Destination identity MUST NOT add an exception to R02. A grant MUST NOT bypass R02. On the common valid surface, token/tool admission is enabled and call limits are nonbinding.

Exclude R01/R03/R04/R05, source-integrity propagation, intent-taint, confirmation UX, rate limits, capability exhaustion, source path-normalization experiments, original logging and LLM behavior. This is a sensitivity-policy subset adaptation, NOT reproduction of the full reference system. Published reference baseline labels MUST NOT be renamed B0/B1/B2; disabling its source-integrity propagation does not remove its accumulated sensitivity.

The comparison MUST use common frozen sensitivity facts injected into both the adapter and a reference-subset driver. This compares policy semantics, not the original regex extraction pipeline. Source behavior outside the defined input domain MUST NOT be silently treated as reproduced.

Before final-study use, differential tests MUST agree on decision, matched R02 rule, effective sensitivity and post-outcome accumulated sensitivity for: no-history sensitive outbound arguments; benign outbound with no history; successful sensitive result then benign-looking outbound; public results/transformations after sensitive exposure; denied/failed acquisition; sensitive current arguments without a subsequent result; all mapped destinations; grant presence; and no reset on permitted reconnect. Failed conformance MUST block baseline inclusion and claims. The adaptation remains unimplemented at this documentation stage.

## 18. Independent oracle observations and labels

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

## 19. Restart, sealing and complete-run acceptance

### 19.1 Restart containment

Each monitor process start MUST create a fresh monitor_instance_id. Unexpected monitor termination makes its unfinished sessions incomplete and invalidates all unconsumed grants and task attachments. The harness MUST terminate the affected scripted client context and discard its saved payload variables, buffers and conversation state. Automatic client reconnect or request replay after MONITOR restart is prohibited.

A new monitor MUST NOT accept an old context or reconstruct trusted exposure/grants from SQLite. A new task/session requires a fresh fixture client/context, fresh identities and a new independently issued expected-run challenge. A failed expected run MUST remain failed/incomplete; replacement MUST NOT hide it by shrinking its inventory. If surviving context cannot be cleared under the controlled harness contract, execution MUST stop. This is bounded harness containment, not arbitrary host recovery.

DOWNSTREAM tool reconnect while controller/monitor stay alive MAY retain the existing task state, provided no call outcome is unresolved. Unknown outcome MUST halt the task. Closure state and outstanding work MUST be checked before sealing.

### 19.2 Sealing

The trusted monitor MUST maintain incremental count/head and task state independently of SQLite. On closure it MUST stop admissions, drain already admitted work to known terminal states, append the closing event, and freeze manifest digest, count, head and closure status. No record may be added to that session afterward.

The exporter MUST obtain a fixed snapshot, validate its schema/lifecycle/sequence, recompute its commitment and compare against frozen trusted values. Recomputed attacker values MUST NOT replace the trusted count/head. Divergence MUST prevent clean sealing. An unknown outcome, ambiguous commit, missing close, failed reconciliation or failed signature/export MUST yield INCOMPLETE/unsealed, never clean acceptance.

Signing and output MUST use the exact validated snapshot, without rereading mutable storage to substitute records. The final package MUST pass self-verification before export success is reported. Later byte mutation makes the altered package invalid; export success is not a promise of continuous storage integrity.

A3T MUST commit the ordered canonical object {manifest, records}, where records retain semantic envelopes and sequence but omit previous/current hash fields. Its SHA-256 input MUST be domain-separated with ASCII "CHAIN GUARD TRANSCRIPT-v1" followed by one zero byte. Its signed closure binds transcript digest, count, manifest digest and the same identities/status/suite as A3. Both forms MAY hash incrementally. Fair comparison MUST hold semantic records, durability, signature frequency and verification requirements equal; A3T MUST NOT also compute the unused event chain. Structural and cryptographic rejection MUST be reported separately. Exact schema/byte vectors MUST pass before signed-format implementation acceptance.

### 19.3 Fresh complete-run submission

Before execution the assessor MUST retain an immutable expected run/challenge, exact required task/session inventory, pinned signer keys and configuration digests. The manifest MUST bind the controller execution profile and this inventory's canonical SHA-256 digest. Session entries MUST identify expected task/session/monitor associations; monitor identity MUST be registered independently at launch before task execution. The package MUST NOT define or shrink its own acceptance expectations.

Inspection MAY be repeated and MUST NOT consume expectations. Fresh submission MUST present every required session exactly once, no unexplained additional sessions, matching run/task/session/challenge/configuration, a complete valid closure for each, and PASS for schema/lifecycle, commitment integrity, trusted signature, expected binding, inventory completeness and finding reproduction. INCOMPLETE or NOT_CHECKED in a required dimension MUST prevent acceptance. A run containing recorded security violations MAY be accepted as evidence; acceptance does not mean benign behavior.

The verifier MUST freeze/validate the submitted package snapshot. In one durable transaction it MUST recheck that the expected run is ACTIVE and unaccepted, record all authenticated session commitment digests and the whole-run acceptance identity, and transition the expectation to ACCEPTED. It MUST report acceptance only after confirmed commit. Failed/incomplete submissions MUST NOT consume expectations. Ambiguous registry commit MUST return an error and be reconciled on retry, never guessed successful.

Duplicate identity is authenticated (run_id, challenge) plus its expected inventory, NOT signature bytes. ACCEPTED expectations MUST reject subsequent submission including after verifier restart. CANCELLED/FAILED expectations and context mismatches MUST reject stale/wrong-run submissions. Registry rollback remains excluded. A valid individual signature MUST NOT accept a run missing another required session. Whole missing runs can only be identified against independent expected inventory.

## 20. Evaluation-1 and final-study boundaries

Grant, scope revocation and one-use consumption are CORE architecture capabilities. M6 is optional ONLY for Evaluation 1 and mandatory for the final project. Its absence from an Evaluation-1 slice MUST NOT weaken, remove or redefine these final capabilities or their contracts.

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
