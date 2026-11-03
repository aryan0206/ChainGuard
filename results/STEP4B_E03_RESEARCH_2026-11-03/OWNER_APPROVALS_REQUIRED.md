# E03 prospective cohort: decisions and execution gates

**No approval is inferred from this design. No experiment may begin until every mandatory gate below passes and the owner explicitly authorizes execution.** The historical pilot remains unchanged. Read [design](COHORT_DESIGN.md), [exact sample](SAMPLE_PLAN.md), [oracle/acknowledgment](ORACLE_AND_ACKNOWLEDGMENT_CONTRACT.md), [collector gaps](COLLECTION_GAP_ASSESSMENT.md), and [summary](STEP4B_SUMMARY.md).

## Existing requirements versus new decisions

The locked [architecture](../../docs/ARCHITECTURE_LOCK.md), [evaluation protocol](../../docs/EVALUATION_PROTOCOL.md) and [experiment matrix](../../docs/EXPERIMENT_MATRIX.md) already require independent predecision labels, frozen direct-recognition coverage, source/sink/task outcome observations, hard unrelated-public and failed-read controls, signed evidence, clear denominator/exclusion reporting, and no common-gate detector credit. They do **not** approve the proposed 12-parent/48-call E03 cohort or a task-acknowledgment implementation. The protocol's 3/2/5 parent-template targets are not this cohort's sample prescription. The owner-approved A1/A2 labels, E08 reference pin and earlier M6 engineering changes do not decide Step 4B.

**Owner decisions required:**

1. Approve or revise the **six-block, 12-parent, 48-call (24 planned A, 18 planned U, six excluded controls)** bounded descriptive cohort, its S2/S3 coverage, fixed two-resource/three-public-objective variation, clustering, exact case IDs and no inferential/generalizability claim.
2. Approve the exact frozen public texts/objective outputs, source/canary bytes, hex decoder and direct-coverage operating point/digest, case ordering, grant scopes, expected effects and parent split. Any change to the application security policy, extraction, controlled tool registry or architecture requires a separate material-change review; this design proposes none.
3. Approve the independent assessor/label procedure, disagreement retention, pre-reservation permission snapshot and unknown/exclusion rules. Approve access to the assessor-held witness location and the task/client observer trust boundary.
4. Approve the separate task-level objective acknowledgment schema, identity/challenge binding, integrity mechanism/key custody, failure handling and fresh-process verifier behavior described in [the contract](ORACLE_AND_ACKNOWLEDGMENT_CONTRACT.md). Authorize **implementation of only the smallest collector/validator change** after review; this document itself gives no implementation permission. New dependencies, if any are proposed later, need separate approval.
5. After implementation and focused qualification, approve the frozen run inventory, analysis plan and **explicit final permission to execute**. Do not treat an engineering test pass as research execution permission or qualification.

## Objective pre-execution gates

| Gate | PASS criterion | FAIL criterion now |
| --- | --- | --- |
| G1 design approval | Owner records explicit approval of sample, scope, claim limit and controls | Proposed only |
| G2 parent/case freeze | Immutable inventory contains all 12 parent IDs, 48 ordered case IDs, six grant controls, objective bytes, planned labels/effects, split, version/digest/seed or deterministic rule; hash retained before run | Not frozen |
| G3 independent oracle freeze | Assessor-held labels/rules and planned witness mapping pre-registered; blinded adjudication and INDETERMINATE/exclusion process qualified | Not frozen or qualified |
| G4 task acknowledgment capture | Separate writer and verifier produce one signed/bound task-level record per parent, validate objective/output/identity/order, and fail closed on missing, duplicate or wrong record | **No executable writer/verifier** |
| G5 collector qualification | Focused engineering checks pass for source success/failure, controls/commit, child/host/sink closure, exact bytes/digests, denial, retry, timeout, and no-arrival; every failed check retained | New-cohort collector not qualified |
| G6 export/offline verification | A fresh process verifies signed export and separate acknowledgment against assessor-held expected inventory/configuration/key pins; missing/altered evidence fails; no tool re-execution | E03 end-to-end path not qualified |
| G7 attempt/exclusion retention | No-overwrite output plan; every attempt/failure/retry and invalid case retained with parent/case linkage and denominator policy | Future ledger absent |
| G8 permission to execute | G1–G7 documented PASS, source/coverage pin rechecked, and owner explicitly authorizes the frozen prospective run | **Not granted** |

**Current gate verdict: FAIL / BLOCKED.** Next authorized stage would be owner review of this design and the task-level acknowledgment contract, then separately authorized collector implementation and qualification. Do not run the cohort, patch the pilot, change protocols or write IEEE results from this design.
