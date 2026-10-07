# ChainGuard Threat Model

Version 1.1 — 7 October 2026. Applies to the owner-locked [ChainGuard Architecture v1.1](ARCHITECTURE_LOCK.md). These are design assumptions and intended guarantees, not tested results.

## Protected assets and goals

Assets are synthetic sensitive source data during experiments; scoped release permissions; task-local detector state; normalized observations and findings; signed commitments; signing/encryption keys; and the verifier's expected-run inventory, trusted configuration and accepted-submission registry.

Goals are to identify bounded suspicious sequences and authorization violations, optionally deny them under enforcement, preserve verifiable origin/integrity of committed findings, reproduce deterministic decisions and reject stale/duplicate evidence submissions. Minimize stored content. Availability and confidentiality guarantees are limited by the trusted local runtime.

## Actors and trust boundaries

| Actor/boundary | Trusted responsibility | Untrusted input / restriction |
| --- | --- | --- |
| Host/task controller | Create context; serialize controls/proposals; own actual permissions and atomic reservation independently of shadow detectors | Tool/client metadata cannot create permissions or reset tasks. Normal observation cannot bypass authorization. |
| Proxy, normalizer and detector | Correct observation, extraction and ordered state under committed versions | Arbitrary call arguments/results must be validated; no raw-data truth guarantee follows from signing extracted facts. |
| Controlled tool registry/server | Declared resource sensitivity, tool effects and capture semantics | This bounded study does not assume arbitrary third-party tools honestly describe their effects. |
| Audit storage | No trust as authority for running history | SQLite/export mutation cannot change trusted in-memory count/head, grant state or signing keys. |
| Signing authority | Exclusive private-key use by the trusted monitor | Key ID/name alone is not proof; verifier uses an independently pinned key. |
| Offline verifier/assessor | Correct trusted code/configuration, expected inventory/challenge and durable registry | Evidence bundles cannot replace keys, policy or executable verifier code. |
| Evaluation oracle | Independent proposal-level labels and assessor-held controls/commit witnesses/source/sink/task observations | Neither detector state nor audit-database-only reconstruction may define ground truth. |

These are logical privilege boundaries. Separate files/processes on one machine do not establish strong OS isolation by themselves. Experiments must state how the simulated attacker is restricted. Unauthorized observation forwarding exists ONLY through the explicitly configured, default-disabled synthetic local-sink override, committed in the run profile. It cannot apply to real sensitive payloads, external destinations, static prohibitions or operational failures; normal observation and enforcement retain authorization controls. An attacker with the same unrestricted host privileges as the monitor/verifier is outside the claimed boundary unless appropriate isolation is separately demonstrated.

## Adversaries

### A. Workflow attacker

Can influence agent/tool-facing text, submit valid supported tool calls, choose arguments/destinations, arrange sequences, apply declared transformations, retry and reconnect. Can exploit individually permitted calls within the controlled surface and may know all rules.

Cannot issue trusted host control events, forge grants, clear task state, falsify trusted registry classifications, bypass the configured proxy path or execute arbitrary unmediated shell/network actions within the core experiment. Prompt injection is a possible cause of malicious calls, but real LLM injection resilience is not evaluated by scripted calls.

### B. Evidence-storage attacker

Can read/modify/delete/insert/reorder/splice audit records or exported packages, including simulated storage modification before sealing while the trusted monitor remains alive; recompute event hashes/chains; substitute supplied keys/configuration; replay authentic packages and resubmit accepted evidence. Knows schema, algorithms and rules.

Cannot access signing keys or trusted running state, change assessor keys/configuration, issue expected challenges, alter immutable expected inventory/independent oracle journals, or roll back/change durable acceptance state. Full deletion is discoverable only where the assessor independently knows evidence was expected.

### C. Storage-disclosure attacker, conditional

Can obtain stored ciphertext blobs if sensitive retention is later approved. Cannot obtain the separate AES-GCM key or running plaintext. Encryption does not protect metadata, compromised runtime memory, screenshots, exported decrypted content or an attacker who also holds the key.

## Assumptions

- Trusted monitor/host/normalizer/verifier execute their approved code correctly; the signing key remains secret and ECDSA library signing nonces are safe.
- The SHA-256 and ECDSA P-256 primitives retain their standard security properties; libraries and key provisioning are not compromised.
- The supported calls traverse the configured proxy, and controlled tools implement their documented contracts. Observations outside this path are not covered.
- Downstream reconnect preserves task state only while the trusted monitor/controller survive without unresolved outcomes. Monitor restart invalidates unfinished contexts/grants; the controlled harness terminates the affected client context and requires fresh identities and expected run. No hidden cross-task memory survives that boundary.
- Verifier keys and exact complete-run expectations are independent of evidence. Required sessions/dimensions pass before atomic durable whole-run acceptance; persistence survives verifier restart. Registry rollback is excluded.
- Oracle commit witnesses come from observed transaction-completion boundaries under the trusted runtime/fault-injection assumptions, not copied normalized rows. Missing witnesses produce unknown labels; these are not proofs against a dishonest monitor.
- Local clocks are not trusted authorities. Timestamps can be wrong without making signatures invalid; core freshness relies on expected context, not clock accuracy.
- Synthetic leakage ground truth covers only explicitly tested raw/decoded forms; arbitrary semantic/paraphrased leakage is outside coverage.

## Attack-to-control mapping

| Attack / failure | Intended control | Security boundary / required test |
| --- | --- | --- |
| Sensitive read, transform, unapproved send | B2 exposure and scoped policy; B0 current-payload checks; B1 comparison | Temporal association may overflag unrelated payload; independently test actual sink leakage. |
| Revoke then transfer; consumed permission reuse | Ordered trusted grant/revoke/use state | Compare matched-count histories and test scope/task binding. |
| Reconnect/context confusion | Surviving trusted-state continuity for downstream reconnect; containment for monitor restart | Old client context cannot reconnect into fresh clean state; no automatic tool replay. |
| Failed read incorrectly treated as exposure | Successful-result state updates | Denied/failed/unknown cases tested separately. |
| Edit/insert/delete/reorder/splice committed records | Sequence/hash validation plus P-256 signed final count/head | An unkeyed chain alone is recomputable. |
| Truncate committed suffix | Trusted signed closure/count/head | No seal or unknown expected final state limits rollback claims. |
| Delete entire session | Independently retained expected-session inventory | Without inventory, absence cannot establish deletion. |
| Substitute key/policy/detector | Externally pinned key and expected configuration digests | Do not trust self-described bundle identity or run bundled code. |
| Replay old authentic package in new run/task | Independent expected challenge/context binding | Signature validity alone is insufficient. |
| Submit same accepted package again | Atomic durable acceptance registry | Repeated offline inspect is allowed; registry rollback is excluded. |
| Audit append failure before dispatch | Fail closed in every mode, including override | Test no forwarding and no partial reservation after failed persistence. |
| Partial reservation / ambiguous commit | All-or-nothing multi-grant intent; halt on ambiguity | Failed reservation consumes no subset; unknown commit is not falsely reported rolled back. |
| Revocation during an active call | FIFO admission and complete proposal turns | Queued controls cannot retroactively cancel committed dispatch intent. |
| Pre-seal storage mutation/recomputation | Frozen trusted count/head and exact-snapshot reconciliation | Refuse clean seal; never adopt attacker-recomputed storage as authority. |
| Missing session in a validly signed run | Independent exact inventory and whole-run acceptance | One valid signature cannot accept an incomplete expected run. |
| Crash around tool side effect | Pending/unknown outcome; no automatic replay | SQLite and tool action are not an atomic transaction. |
| Signing failure after executed calls | Incomplete/unsealed evidence status | No retroactive rollback or false clean-session claim. |
| Conditional ciphertext disclosure/tampering | AES-GCM, distinct key, unique nonce, bound associated data | Does not encrypt all SQLite metadata or defeat runtime compromise. |

## Intended guarantees and nonclaims

With uncompromised signing/verifier trust anchors, modifications to a sealed committed stream should fail verification, including attacker recomputation of all hashes. The signature authenticates the holder of the trusted monitor key and the commitment's contents. It does not prove an honest monitor, complete capture before signing, human identity, detector correctness, legal non-repudiation or an externally trusted time.

The verifier reproduces findings from committed normalized observations and approved rules. This establishes consistency with those inputs; independent oracle evaluation tests facts against actual effects/contracts. Authentically signed incorrect facts may reproduce consistently, while incorrect findings on correct facts should fail reproduction. Independently witnessed omissions expose capture errors; missing oracle observations do not establish completeness.

Fresh submission rejects a package whose authenticated identity/challenge does not match the assessor's expectation or has already been accepted. This is not MCP request anti-replay, a command nonce protocol or a guarantee against replayed tool side effects.

The monitor cannot prove detection of events deliberately omitted by a dishonest logger before sealing. Unsigned tails, whole unknown sessions and rollback without independently retained expected state remain limits. There is no forward-secure protection after signing-key compromise.

Behavioral coverage is limited to supported normalized tools and policy families. The exposure rule is an overapproximation and does not implement general taint tracking, arbitrary information-flow control, cross-agent security, protection against malicious server implementations or universal prompt-injection defense.

## Residual risks and validation

Residual risks include oracle/classifier mistakes, false positives from coarse exposure, unsupported transformations, legitimate workflow interruption, key theft, misconfigured routing, disk exhaustion/denial of service, cryptographic API misuse and weak synthetic generalization. Resource limits and diagnostics can aid engineering but do not justify a comprehensive availability claim.

Use the charter's detection corpus and A0/A1/A2/A3/A3T/A4/A4T mutation/submission matrix to validate controls. Include genuine expected packages, authentic stale packages, missing/incomplete evidence and attacker hash recomputation. A test must state which verifier dimension is expected to pass or fail and why; do not equate every failure with detected malice.

Any later expansion of attacker power, tool scope, retention, transport or key trust is a material architecture/threat-model change and requires owner approval before implementation.
