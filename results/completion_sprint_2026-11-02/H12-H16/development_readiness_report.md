# H12–H16 E01/E02/E13 development readiness

Prepared 2 November 2026. The only execution was the development-only capture command in `capture.run.json`; no live M6 case or protocol-qualified E01/E02/E13 experiment was run. Source and test files were not edited. The existing authored fixtures are staged synthetic contracts, not observed tool effects or durable COMMIT witnesses.

## E02: revocation_boundary_01

Fixture: `tests/workflow_fixtures.py`, `MATCHED_GROUPS` and the `matched-grant-revoke` / `matched-revoke-grant` contracts, call `release`. Assertion: `tests/test_workflows.py#test_actual_b1_input_equality_on_separate_representation_path`. The fresh capture used the same `ReplayLedger.accept`, `extract_current`, `project_b1`, and `b1_input_bytes` path, plus `validate_group` and `validate_contract`.

| Case | Order before `release` | Authored staged label | Retained B1 bytes | SHA-256 |
| --- | --- | --- | ---: | --- |
| CG-DEV-004 | successful sensitive read, grant `opaque-grant`, revoke same scope, proposal | UNAUTHORIZED | 724 | `04f3855f76dfef35d7b20948939ebf5cb849c10c29f63bb4a001df413f7435c1` |
| CG-DEV-005 | successful sensitive read, revoke scope, NEW grant `opaque-grant`, proposal | AUTHORIZED | 724 | `04f3855f76dfef35d7b20948939ebf5cb849c10c29f63bb4a001df413f7435c1` |

`CG-DEV-004.b1.bin` and `CG-DEV-005.b1.bin` are the **exact raw serialized UTF-8 bytes**. The capture script reread both files and asserted byte equality, not parsed-object equality; independent PowerShell SHA-256 checks agreed. The common B1 input contains one successful sensitive read, one GRANT, one REVOKE_SCOPE, no USE, and the same current sensitive `send` to `sink`; it excludes their order and opaque grant identity. The first order leaves no active grant; the second ends with a newly active grant. The authored labels are in `CallExpectation` objects in `tests/workflow_fixtures.py`; unchanged staged M2 assessor validation checks them without using detector findings. They are **development-authored, not independently observed live labels**.

The retained development replay records B1 `INDETERMINATE`/`UNORDERED_REVOKE_AMBIGUITY` on both, while B2-R and B2-S give UNAUTHORIZED/PERMISSION_ABSENT for CG-DEV-004 and AUTHORIZED/PERMISSION_PRESENT for CG-DEV-005. This does not count B1 abstention as a definite error. The staged identical-input mixed-label group has `min(1,1)=1` as a **development-group diagnostic bound**, not a research sample estimate.

**E02 eligibility:** this pair meets the development structural requirements for common current call, policy/resources/task/objective, valid staged grant/revoke order, equal non-order semantic inventory, byte-identical B1 input, and opposite prewritten staged labels. It does **not** satisfy final E02 execution: independently retained actual control/COMMIT/source/sink/task observations are absent, raw B1 bytes were retained only now, and the required wider valid S4–S6 matched-group inventory/denominators remain unfrozen. Source journals, labels, findings and staged oracle outputs are in `e02_development_pair.json` and per-case journal files.

## E01: order-insensitive controls

Protocol requires S1/S2 **paired benign reorderings** with identical current-call features, policy and scoped non-order facts; independent authorization labels; raw before/after input projections and B1 bytes; source/sink/task effects; and B2-R/S valid-prefix agreement. A public/current-event control and a monotone-exposure hard benign control must not be mistaken for a paired reordering merely because both are benign fixture families.

| Candidate from `tests/workflow_fixtures.py` | Authored release expectation | Why it is not an eligible paired E01 control |
| --- | --- | --- |
| CG-DEV-001 `public-current` | AUTHORIZED; task output `deliver-required-output` in the staged plan | No frozen valid benign-reordering partner with equal current and non-order facts. |
| CG-DEV-002 `monotone-public-transfer` | UNAUTHORIZED under conservative exposure; no actual sensitive disclosure in the staged plan; task expected INCOMPLETE | Contains a `harmless-gap` echo, but has no no-gap/reordered partner with the required equality, independent sink capture, or final task observation. |

The `tests/test_m2.py#test_counts_permutation_and_evidence_id_invariance` unit check reverses a fact tuple to test B1 projection invariance; that reversal is not a qualified valid lifecycle workflow. **No E01 case was run** in H12–H16. Authored expected outputs are not observed ground truth.

## E13: metamorphic preparation and one development check

Protocol transformations: harmless gaps, opaque-ID renaming, and valid scope interleaving. Harmless gaps must preserve relevant pre-decision semantics; renamed IDs require a bijective reference mapping; interleaving is invariant only if it leaves relevant permission/exposure facts and the pre-decision contract unchanged. A reordering that changes permission is an E02 order-sensitive case, not an E13 invariant.

| Transformation | Existing implementation | H12–H16 status |
| --- | --- | --- |
| Opaque event/grant ID renaming | `tests/test_workflows.py#test_identifier_renaming_preserves_contract_and_signature`; H12 capture reconstructs the same transform | **Development checked**; original CG-DEV-005, transformed CG-DEV-005-RENAME-01. |
| Harmless gap addition/removal | One `harmless-gap` event exists in CG-DEV-002; no paired transformed case or independent invariant contract | **Missing qualified pair**. |
| Valid scope interleaving | S6 fixture contains interleaved controls; no before/after metamorphic pair | **Missing qualified pair**. |

For the available renaming, original and transformed raw contract JSON and replay outputs are retained. Changed properties: every event ID gains `renamed-`, the opaque grant ID becomes `renamed-grant`, and selected/consumed grant references follow the same mapping. Expected invariant basis: the authored contract's task, resources, current proposals, scope, control outcome and objective are unchanged; IDs are opaque to B1 and independent contract authorization. Expected changing properties: raw IDs and deterministic supporting references, mapped bijectively. Fresh development checks found equal unordered signatures, equal B1 input bytes for both proposals, equal staged oracle authorization, equal detector authorization/behavior/rule tuples, and supporting references equal after the declared `renamed-` mapping. See `e13_development_check.json`, `e13_postrun_analysis.json`, and before/after input/output files. These are two staged proposals in **one development parent**, not independent samples or population-level robustness.

## Execution and status

Exact command: `.\.venv\Scripts\python.exe -B results/completion_sprint_2026-11-02/H12-H16/capture_development.py`. Start 2026-11-02 19:13:28.7472026 +05:30; end 19:13:30.7271442 +05:30; 1.9663615 wall seconds; exit 0. Stdout/stderr and metadata are retained. No retry. This is a development capture/check, not an E01/E02/E13 population experiment.

- **E01 research execution:** NOT STARTED; readiness remains PARTIALLY PREPARED, with no eligible paired control.
- **E02 research execution:** NOT STARTED; development matched-input verification strengthened by retained bytes/digests, final independent observations missing.
- **E13 research execution:** NOT STARTED; one renaming development check, other transformations and independent observation basis missing.

## Artifact index

- E02 exact bytes: `CG-DEV-004.b1.bin`, `CG-DEV-005.b1.bin`; raw staged contracts: `CG-DEV-004.journal.json`, `CG-DEV-005.journal.json`; labels/replay: `e02_development_pair.json`.
- E13 original/transformed inputs and outputs: `e13_original_input.json`, `e13_renamed_input.json`, `e13_original_output.json`, `e13_renamed_output.json`; checks: `e13_development_check.json`, `e13_postrun_analysis.json`.
- Execution provenance: `capture_development.py`, `run_capture.ps1`, `capture.run.json`, `capture.stdout.log`, `capture.stderr.log`.
- Authority decisions: `authority_decision_sheet.md`. No A1/A2 or E08 decision was made here.
