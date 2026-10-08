# Adversarial findings registry

Snapshot: 8 October 2026. Observed engineering findings and planned attack cases are separate. Expected protection below is a contract, not a recorded successful test. Sources and trust limits: [README](../README.md), [Architecture Lock](ARCHITECTURE_LOCK.md) Sections 15-19 and [Threat Model](THREAT_MODEL.md). No attacks were executed in Phase 1.

## AF-001: discovered persistence-gate flaw

| Field | Record |
| --- | --- |
| ID | AF-001 |
| Attack | Suppress/delete inserted evidence, rewrite persisted bytes/hashes/metadata or substitute storage schema while SQL operations appear successful |
| Target | Shared M3/M4 transaction-before-forwarding gate |
| Precondition | Simulated audit-storage attacker can manipulate SQLite within the declared boundary; trusted process/key/assessor journals remain outside attacker authority |
| Expected protection | Persist the exact complete batch before confirmed commit, trusted state update and forwarding; audit failure blocks dispatch |
| Observed result | Adversarial review of M4 `d631e61bfd0621fadf225a8bede03b87820da15a` found successful SQL acknowledgments could conceal missing/altered evidence while actual forwarding occurred. Later sealing refused the stream but did not prevent the earlier execution |
| Impact | Violated the durable persistence prerequisite for forwarding; closure rejection alone was insufficient |
| Status | REPAIRED; engineering regressions recorded; no final research fault study claim |
| Evidence | README Durability-gate correction validation, 8 October 2026; repair `49aa07b31edc2d77f275ec15e7ae42af02d37065`; 27 targeted tests passed, 10 independent recheck cases BLOCKED; current M3/M4 suites 40/67 |
| Repair | Transaction-local validation of code-owned tables/indexes/constraints; reject unexpected schema/temp objects. After inserts, compare the exact whole persisted batch and manifest to frozen expected tuples/bytes/hashes **before COMMIT**. Mismatch rolls back/halts, without successful receipt, trusted advancement or forwarding |
| Remaining limitation | Local SQLite locking/durability and trusted runtime assumptions; no continuous old-row protection, raw filesystem/database-engine compromise defense or atomicity with external tool effects. Outcome sabotage after a correctly audited execution cannot undo that effect; it halts without false committed outcome or subsequent execution |

README records admission attacks caused no handler execution after repair; initialization sabotage created no usable context; outcome sabotage halted after one correctly audited execution. These bounded observations do not establish universal tamper resistance.

## Final adversarial set: unexecuted placeholders

| ID | Attack | Target | Precondition | Expected protection | Observed result | Impact | Status | Evidence | Remaining limitation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| AF-002 | Controller credit theft | E04 detector attribution | Detector recommends ALLOW but common gate blocks | Report controller refusal separately; no detector prevention credit | Not measured | Inflated detector benefit | NOT STARTED | Required: recommendation/refusal/handler trace | Composed enforcement can hide unsafe advice |
| AF-003 | B1 indistinguishability | E02 representation sufficiency | Identical permitted B1 inputs, opposite independent labels | Preserve valid matched groups; separate abstention from error | Not measured in final study | Misleading claims about unordered policy | NOT STARTED | Required: exact projection bytes and independent labels | Observed group bound is not a population theorem |
| AF-004 | Revocation placebo | E06 lifecycle | Only consumed grants are revoked | Revoke an unconsumed active grant and demonstrate subsequent denial | Not measured | Revocation untested despite a passing example | NOT STARTED | Required: independent pre-revoke activity and consumption witnesses | Consumed-grant revocation is insufficient |
| AF-005 | Dispatch-intent boundary | E07 persistence/execution | Failure between intent, commit, forwarding and outcome | Confirm commit before dispatch; ambiguous outcome halts without replay/refund | Not measured in final study | Unaudited effects or duplicate execution | NOT STARTED | Required: fault timing, commit and handler observations | Database/tool effect not one atomic transaction |
| AF-006 | Permission resurrection | E06/E07 restart/regrant | Consumed/revoked grants or old context reused | NEW unique grant only; monitor restart invalidates unfinished context | Not measured | Reuse of unavailable permission | NOT STARTED | Required: controls, restart identities and independent permission journal | Bounded client/context clearing assumptions |
| AF-007 | Partial multi-resource release | E06/E07 atomic reservation | One required scope lacks a usable grant | No subset consumption or forwarding; override selection empty | Not measured | Partial consumption or unauthorized release | NOT STARTED | Required: full selected set and sink/handler witnesses | Partial/ambiguous tool payloads unsupported |
| AF-008 | Oracle starvation | E07/E10 oracle completeness | Missing source/sink/commit observation | Unknown/indeterminate label and disclosed exclusion | Not measured | Fabricated ground truth | NOT STARTED | Required: missing-witness fixture and reported denominator | Missing observations cannot establish absence |
| AF-009 | Authentic lie | E10 evidence truth | Legitimate signer commits wrong facts or findings | Separate signature, reproduction and independent oracle disagreement | Not measured in final study | Authentic evidence mistaken for truth | NOT STARTED | Required: signed fixture and external truth journal | Signature authenticates commitment, not honesty |
| AF-010 | Expectation laundering | E11 acceptance | Package attempts to define/shrink expected inventory | Independently retained immutable expectation; whole-run acceptance | Not measured in final study | Missing/stale run accepted as complete | NOT STARTED | Required: independent inventory, package and registry outcomes | Unknown entire runs need external expectations; registry rollback excluded |
| AF-011 | Trust-boundary escape | E08-E11 trust assumptions | Package substitutes key/configuration/code or attacker crosses declared boundary | External pins; trusted code only; document attack authority | Not measured in final study | Invalid authentication or overbroad guarantee | NOT STARTED | Required: substitutions, pins and explicit privilege boundaries | Logical files/processes alone are not OS isolation |

Some related engineering checks already exist; see the [ledger](RESULTS_LEDGER.md). Placeholders do not imply those checks were absent, nor that this final attack set passed. For each execution append actual precondition, expected dimension outcome, raw artifact reference, observed result, limitation and affected [claim](CLAIMS_REGISTER.md).
