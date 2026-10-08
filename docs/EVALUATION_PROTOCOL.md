# Evaluation protocol

Documentation snapshot: 8 October 2026. Approved Astra protocol supplied in the Phase 1 owner request, reconciled only by explicit authority notes below. This is the methodology control for E01-E13, subject to the [Architecture Lock](ARCHITECTURE_LOCK.md), [charter](PROJECT_CHARTER.md), [threat model](THREAT_MODEL.md), [playbook](../ENGINEERING_PLAYBOOK.md) and [AGENTS](../AGENTS.md). It authorizes no implementation, dependency, experiment, commit or publication.

## Authority and open ambiguities

Architecture v1.1 remains authoritative and unchanged. README corroborates M1-M5 engineering progress; older control documents describe an earlier closed implementation gate. Record completion separately from student review/commit approval. No final E01-E13 study is established by those milestones.

| Issue | Supplied protocol | Repository contract / treatment |
| --- | --- | --- |
| Evidence labels | A0 no integrity; A1 hash chain; A2 signed closure | Charter: A0 structured records, A1 independent hashes, A2 unkeyed chain, A3 signed canonical chain, A3T signed ordered transcript. Lock Sections 13/19 preserve A3/A3T and A4/A4T. Use repository labels below; retain supplied alternatives here pending explicit resolution before ablation execution. No A2 signed-closure experiment is silently substituted. |
| Baseline revision | `3dd9690b5b6f9c4ef385289714b314d13f6ad1` | Lock Section 17: `3dd9690b5b6f9c4ef385289714b314d13f6ad9a1`. These strings differ; supplied string is not a full 40-character SHA. Locked pin remains authoritative; owner resolution required before baseline work. |
| RQ numbering | Eight study questions, with ordering as RQ2 | Lock Section 16 explicitly fixes RQ2 as B2-R/B2-S equivalence and cost; charter has five questions. The eight IDs below are **protocol-local**, not replacement architecture/charter IDs. Locked RQ2 remains mandatory through protocol RQ1/RQ8 and H5/H10. |

## Research questions and hypotheses

| Protocol ID | Question |
| --- | --- |
| RQ1 | What changes between current-event, unordered-history, and ordered-state representations? |
| RQ2 | Where does event ordering materially change security decisions? |
| RQ3 | Does ordered history improve useful authorization decisions on held-out workflows? |
| RQ4 | Can detector, controller, and independent oracle outcomes be separated? |
| RQ5 | Can evidence be independently verified, reproduced, and accepted without treating evidence authenticity as truth? |
| RQ6 | Do guarantees survive execution and persistence failures? |
| RQ7 | How does ChainGuard compare fairly with an external policy baseline? |
| RQ8 | What cost does stronger representation/evidence impose? |

Charter RQ1 maps to protocol RQ1-RQ4/RQ7; charter RQ2 to protocol RQ1/RQ8 and H5; charter RQ3/RQ4 to protocol RQ5/RQ6; charter RQ5 to protocol RQ8. This mapping retains every locked requirement.

| ID | Hypothesis to test; not a finding |
| --- | --- |
| H1 | Order-insensitive workflows should not require B2. |
| H2 | Some valid histories have identical B1 inputs but different authorization labels. |
| H3 | B2 should improve useful decisions on held-out order-sensitive workflows. |
| H4 | B2 improvement should not simply trade into unsafe recommendations or excessive task disruption. |
| H5 | B2-R and B2-S should agree. |
| H6 | M6 lifecycle semantics should hold. |
| H7 | Signed evidence can be authentic but wrong; acceptance does not prove truth. |
| H8 | A3/A3T and A4/A4T provide different assurance/cost tradeoffs. |
| H9 | External baseline adaptation must conform before comparison. |
| H10 | Stronger representations/evidence have measurable cost. |

## Workflow population and freeze

| Stratum | Workflow class | Target development / validation / held-out parent templates |
| --- | --- | --- |
| S1 | Public/current-event | 3 / 2 / 5 |
| S2 | Monotone exposure | 3 / 2 / 5 |
| S3 | Authorized sensitive release | 3 / 2 / 5 |
| S4 | Revocation/regrant | 3 / 2 / 5 |
| S5 | Consumption/failure/retry | 3 / 2 / 5 |
| S6 | Multiple resources/interleaved scopes | 3 / 2 / 5 |

Target: 10 parent templates per stratum, 60 total (18 development, 12 validation, 30 held-out). This is a coverage target, not a power calculation or an achieved sample size. Report the actual number of independent workflows if fewer are feasible. Reordered clones, variants and near duplicates stay in one parent split. Freeze fixture contracts, oracle, extraction/decoding coverage, rule tables, thresholds/operating points, policy/tool mapping and code/configuration digests before held-out execution. Preserve seeds and split inventory. No tuning on held-out outcomes.

## Representations and execution attribution

B0 uses current-event features and meaningful frozen direct-content/static checks. B1 is the conservative unordered historical projection retaining only locked non-order features: successful exposure and exact scoped G/R/U counts. Remove ordering, timestamps, IDs, ordinals, predecessor links, active-state flags, transitions, detector findings and scenario labels. Lifecycle validation/reference mapping cannot leak order into behavioral inputs. B2 uses ordered deterministic transitions; B2-R reconstructs each eligible prefix, and B2-S retains state. Compare authorization assessment, behavioral verdict, rule IDs and deterministic references at every valid prefix; identical actual-state dispatch selection must agree. Agreement is a consistency check, not an oracle.

E02 preserves current call, scoped non-order semantics and serialized B1 input while varying valid order. Include revoke/use, use/revoke, grant/use/revoke, grant/revoke/NEW grant/use, multiple grants and interleaved scopes. A use after revoke needs a separately valid NEW grant, another available grant or the explicit synthetic override; do not manufacture a valid authorized USE. Equal counts alone are insufficient if lifecycle/category/scope or outcomes differ. Mixed-label groups must have independent labels. Report observed minimum binary error count as `sum(min(authorized_count, unauthorized_count))` within identical-input groups; it is a bound for those groups. Do not call B1 wrong merely for abstaining: separate authorization error, coverage/abstention, unnecessary denial and enforcement consequence. Sticky exposure alone does not require ordering.

Shadows see one controller-generated committed history and cannot control forwarding or consume grants. Normal observation retains authorization; unauthorized forwarding requires the committed, default-disabled synthetic local-sink override. Static prohibitions, unsupported operations and persistence failures still block. Enforcement uses fresh separate executions per configuration under the same static envelope/controller; trajectories may diverge. Attribute detector recommendation, controller refusal, dispatch, consumption, disclosure and completion separately. Prevention by a common gate is not detector credit.

## Independent oracle and outcome axes

Prewrite fixture contracts and expected effects. Independently retain issued/admitted controls and order, successful control/reservation commit witnesses, raw pre-decision proposals, source observations, forwarding attempts, handler arrivals, destination sink contents/canaries, task outputs and audit persistence/closure observations outside the simulated audit attack surface. Labels cannot come from ChainGuard findings, B2 transitions or audit-only reconstruction. The controller is execution authority, not the oracle.

Before every proposal, including denied ones, independently reconstruct AUTHORIZED / UNAUTHORIZED / INDETERMINATE. Preserve the pre-reservation permission snapshot for disclosure assessment. Missing observations remain unknown; disclose exclusions from binary denominators. Consumption without an available commit witness is UNKNOWN. The primary reporting axes are authorization correctness, decision coverage/abstention, unnecessary denial, unauthorized disclosure and legitimate task completion. The underlying oracle dimensions additionally retain actual dispatch and permission consumption (Lock Section 18); these are not merged into detector labels. Audit/closure witnesses remain separate. Replay fixtures assume commit success; they cannot qualify live durability.

## Experiments and current status

PLANNED means protocol specified but not executed as a final research experiment. NOT STARTED identifies missing prerequisite implementations/conformance. COMPLETED applies only to recorded executed work in the [ledger](RESULTS_LEDGER.md); none of E01-E13 is currently COMPLETED. Related engineering checks do not automatically complete an experiment.

| ID | Experiment | Status / prerequisite |
| --- | --- | --- |
| E01 | Order-insensitive controls | PLANNED; qualified fixtures/oracle |
| E02 | Matched order-sensitive groups | PLANNED; identical B1-input checks and valid independent labels |
| E03 | Historical recognition | PLANNED; freeze direct-recognition coverage; independent canary outside that coverage plus hard benign/failed-read controls |
| E04 | Detector/controller attribution | PLANNED; separate shadows and enforcement trajectories |
| E05 | Held-out workflows | PLANNED; frozen grouped split and completed prerequisites |
| E06 | Live M6 lifecycle | NOT STARTED; M6 implementation/authorization and live oracle qualification |
| E07 | Execution/failure boundaries | PLANNED; existing engineering checks retained; full M6 failure study pending |
| E08 | External baseline | NOT STARTED / CONFORMANCE PENDING; pin ambiguity and adapter |
| E09 | Evidence integrity | PLANNED; mutation expectations and missing evidence variants |
| E10 | Authentic-but-wrong facts/findings | PLANNED; independently observed truth and legitimate test signer |
| E11 | Acceptance | PLANNED; M5 engineering package campaign is supporting evidence only |
| E12 | Cost/scaling | NOT STARTED; actual retained-state B2-S measurement and staged instrumentation |
| E13 | Invariance/explanation | PLANNED; irrelevant gaps/renaming within contracts, deterministic references and versioned explanations |

Detailed controls and retained artifacts: [experiment matrix](EXPERIMENT_MATRIX.md).

## M6, evidence and acceptance contracts

M6 must independently test grant/use/reuse, active revoke, regrant, multiple scopes, failed dispatched call without refund, denial consuming nothing and ambiguous outcomes halting without replay. Include independent source/sink/consumption observations and at least one revocation of an **unconsumed active grant**; revoking only an already-consumed grant is insufficient. Locked shorthand: first release consumes NEW grant; following release is denied WITHOUT another grant. Multi-resource selection is all-or-nothing. Proposal -> decision -> dispatch intent -> confirmed SQLite COMMIT -> trusted state update -> forwarding remains the critical boundary. SQLite and tool effects are not atomic together.

Repository evidence labels pending the authority-note resolution:

| Variant | Mechanism |
| --- | --- |
| A0 | Structured records without evidence integrity |
| A1 | Independent event hashes |
| A2 | Unkeyed hash chain |
| A3 | Signed canonical chain |
| A3T | Signed ordered canonical transcript, without unused event-chain computation |
| A4 | A3 with independent expected context/inventory and durable whole-run acceptance |
| A4T | A3T under the same acceptance wrapper |

Hold semantic content, durability, signature frequency, ECDSA P-256/SHA-256 trust anchors and verification requirements equal for A3/A3T and A4/A4T. Mutations: edit, insert, delete, duplicate, reorder, splice, truncate, whole-session removal, recompute, pre-seal/post-seal mutation, wrong key/context/identity and policy/detector substitution. Predeclare expected outcomes per verifier dimension. Preserve original assessor package and exact mutation ledger. Separate structural, commitment, signature, binding, completeness and reproduction outcomes; missing/unsealed evidence is not automatically malicious.

E10 uses a legitimate test signer to sign intentionally incorrect observations with consistent findings: authenticity may pass and reproduction may succeed while the independent oracle disagrees. Correct observations with unsupported incorrect findings should fail deterministic reproduction. Include independently witnessed omitted actions; absent oracle observations yield unevaluable completeness. Signatures do not prevent lies. E11 separates repeatable inspection from fresh whole-run acceptance, including missing/extra inventory, wrong/stale context, duplicates, restart, concurrency and failed/ambiguous registry commit. Acceptance requires confirmed durable registry commit and does not certify benign behavior.

## Execution order

1. Freeze protocol/documentation and resolve authority notes.
2. Qualify oracle and fixture contracts.
3. E01/E02/E03/E04/E13.
4. External baseline conformance; E08 comparison only after it passes.
5. Separately authorize, implement/validate M6, then E06/E07.
6. Evidence variants E09/E10.
7. M5 acceptance evaluation E11.
8. Held-out study E05.
9. Cost/scaling E12.
10. Final adversarial sweep.
11. Final analysis.
12. [Claims register](CLAIMS_REGISTER.md) -> paper/PPT/viva after evidence review.

## Metrics, statistical treatment and reproducibility

Report per workflow/parent template, with per-prefix diagnostics retained but never treated as independent samples. Repetitions estimate reliability/timing, not new detection samples. Report each stratum and aggregate with actual eligible denominators, unknown counts and undefined metrics explicitly.

| Outcome | Reporting rule |
| --- | --- |
| Authorization correctness | Workflow summary of definite recommendation/assessment errors against independent labels; disclose label and assessment uncertainty separately |
| Coverage/abstention | Eligible independently labeled proposals receiving definite assessment; aggregate within workflow and report indeterminate/unsupported counts |
| Unnecessary denial / task disruption | Predefined legitimate workflow obligations blocked/delayed; include controller versus detector attribution and completion |
| Unauthorized disclosure | Independently observed covered sink disclosure against pre-reservation permission; conservative exposure violations reported separately |
| Legitimate completion | Fixture-defined task completion, with failures/unknowns and hard benign controls |
| Unsafe recommendations | ALLOW recommendations against independently UNAUTHORIZED proposals, including those prevented by controller |
| B1 ambiguity / B2 disagreement | Identical-input mixed-label groups and bound; B2-R/B2-S mismatches across valid prefixes with workflow-level aggregation |
| Mutation detection / reproduction / acceptance | Dimension-specific expected-versus-observed results, false acceptance/rejection, incomplete handling, case inventory and eligible denominators |
| Latency / storage / memory | Capture, detection, SQLite, sealing, verification and acceptance boundaries separately; bytes per event/session and total memory/state/export/disk accounting |

Freeze exact denominators, aggregation/weighting, binary treatment and analysis scripts before held-out outcomes. Use paired workflow differences and workflow-level uncertainty methods (e.g. paired bootstrap over independent parent templates, retaining all related variants together); disclose small-sample limitations. For skewed timings prefer median/IQR; add p95 only with sufficient repetitions. Do not infer statistical power from the target corpus or generalize from repeated prefixes. Zero failures in a mutation campaign describe only that bounded campaign, not a cryptographic failure probability.

No B2 performance/scaling claim until an actual retained-state B2-S implementation is measured. Current live shadow replay is not incremental-state performance evidence. Compare unmonitored, proxy-only and staged/full paths under common measurement boundaries. Record hardware/OS/runtime/package versions, revisions/configuration digests, actual parent count/splits, commands, seeds, raw journals, measurement repetitions and artifact locations. Published README test durations are engineering run observations, not benchmarks.

## Validity threats and claim limits

Prevent circular oracle/detector imports, controller credit theft, order/label leakage into B1, held-out clone leakage, post-selection weakening of B0, unequal baseline facts, survivor selection and denominator changes. Synthetic controlled tools, bounded decoding, coarse exposure false positives, logical host isolation and trusted runtime witnesses limit external validity. Missing oracle data cannot establish correctness/completeness. Full host/key compromise, registry rollback, arbitrary MCP bypass, real LLM robustness and unsupported transformations remain outside claimed coverage.

Prohibited wording: first sequence-aware MCP defense; universal protection; signatures prove truth; acceptance proves benign behavior; B2 is always better; general zero FAR/FRR; MCP execution replay prevention; universal tamper resistance; trusted timestamping; constant-memory/constant-time; full Wang reproduction; final novelty before literature review and final study. Use [claim controls](CLAIMS_REGISTER.md), not engineering test totals, to determine permitted conclusions.
