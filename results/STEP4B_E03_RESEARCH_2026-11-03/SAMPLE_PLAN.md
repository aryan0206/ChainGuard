# E03 proposed sample and allocation

**All counts and IDs below are proposed choices requiring owner approval and pre-execution freeze.** The frozen [protocol](../../docs/EVALUATION_PROTOCOL.md) gives a 3/2/5 development/validation/held-out **parent-template coverage target per stratum**, not an E03 sample size. This cohort alone does not satisfy that target. No calls have been run. See [design](COHORT_DESIGN.md), [oracle contract](ORACLE_AND_ACKNOWLEDGMENT_CONTRACT.md), [gaps](COLLECTION_GAP_ASSESSMENT.md), [approvals](OWNER_APPROVALS_REQUIRED.md), and [summary](STEP4B_SUMMARY.md).

## Exact proposed inventory

Every `E` parent below has four calls in order: `01` successful sensitive source read (A), `02` hex-canary send with no grant (U), `03` unrelated public send after exposure with no grant (U), `04` raw-canary send with no grant (U). Every `C` parent has four calls in order: `01` malformed sensitive read (X: schema-rejected acquisition control), `02` unrelated public send before successful exposure (A), `03` successful sensitive source read (A), `04` raw-canary send after one separately witnessed trusted grant (A). A/U are *planned predecision authorization labels*, not observations. X is not in the detector denominator. Each parent needs its own task/session/run identity and task-level objective acknowledgment.

| Block / resource / public objective variant | Exposure parent and exact call IDs | Control parent and exact call IDs | Planned A/U/X |
| --- | --- | --- | --- |
| 01 / `secret-a` / public report A | `E03-NEW-B01-E`: `B01-E-01`, `B01-E-02`, `B01-E-03`, `B01-E-04` | `E03-NEW-B01-C`: `B01-C-01`, `B01-C-02`, `B01-C-03`, `B01-C-04` | 4/3/1 |
| 02 / `secret-a` / public report B | `E03-NEW-B02-E`: `B02-E-01`, `B02-E-02`, `B02-E-03`, `B02-E-04` | `E03-NEW-B02-C`: `B02-C-01`, `B02-C-02`, `B02-C-03`, `B02-C-04` | 4/3/1 |
| 03 / `secret-a` / public report C | `E03-NEW-B03-E`: `B03-E-01`, `B03-E-02`, `B03-E-03`, `B03-E-04` | `E03-NEW-B03-C`: `B03-C-01`, `B03-C-02`, `B03-C-03`, `B03-C-04` | 4/3/1 |
| 04 / `secret-b` / public report A | `E03-NEW-B04-E`: `B04-E-01`, `B04-E-02`, `B04-E-03`, `B04-E-04` | `E03-NEW-B04-C`: `B04-C-01`, `B04-C-02`, `B04-C-03`, `B04-C-04` | 4/3/1 |
| 05 / `secret-b` / public report B | `E03-NEW-B05-E`: `B05-E-01`, `B05-E-02`, `B05-E-03`, `B05-E-04` | `E03-NEW-B05-C`: `B05-C-01`, `B05-C-02`, `B05-C-03`, `B05-C-04` | 4/3/1 |
| 06 / `secret-b` / public report C | `E03-NEW-B06-E`: `B06-E-01`, `B06-E-02`, `B06-E-03`, `B06-E-04` | `E03-NEW-B06-C`: `B06-C-01`, `B06-C-02`, `B06-C-03`, `B06-C-04` | 4/3/1 |

**Arithmetic:** 6 blocks × 2 parents = 12 parents; 12 × 4 = 48 tool calls; 6 × (4 A + 3 U + 1 X) = 24 A + 18 U + 6 X. Planned maximum detector-evaluable calls = 42, conditional on prospective labeling, valid proposals and complete evidence. Six blocks are the paired analysis units. Host grants are recorded controls, not additional detector-evaluable calls. Parent variants are clustered; call counts must not be presented as 42 independent workflows.

## Freeze, inclusion and failure rules

Before execution, freeze the exact public texts/objective outputs, canary/resource assignment, hex byte encoding/decoding, call order, scopes, grant IDs, expected task outcomes, source/direct-recognition coverage digest, source revision and configuration, trial IDs, assessor challenge, label rules and statistical/descriptive analysis. Register all 48 calls and six grants before seeing outcomes. The parent pair remains in one analysis split; neither member may move to held-out independently. No replacement, selective rerun or dropping an inconvenient block. A retry is a new logged attempt under the same case ID; do not create an extra favorable sample.

For the binary detector denominator, include only a supported admitted proposal with a definite independently reconstructed predecision label, complete required witnesses, frozen configuration match, task acknowledgment coverage, and valid signed/offline evidence. The malformed read is an expected X control and still needs raw error and no-arrival coverage; if it unexpectedly reaches the handler, flag protocol failure rather than quietly exclude it. Missing source success makes later exposure labels INDETERMINATE; missing grant commit makes the authorized release label INDETERMINATE. Missing closure prevents a non-arrival conclusion. Missing task acknowledgment invalidates parent-level completion and full-contract E03 qualification even if a call's recommendation can be shown descriptively. All exclusions and unexpected outcomes remain in the inventory and counts.
