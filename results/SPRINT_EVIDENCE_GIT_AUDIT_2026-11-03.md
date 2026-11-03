# ChainGuard sprint evidence Git inclusion audit

**Audit date:** 3 November 2026 (Asia/Calcutta). **Scope:** `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/` and `results/STEP4A_EXECUTION_READINESS_2026-11-03.md`. This is a read-only assessment of the evidence; the only write was this audit report. No Git operation, stage, commit, push, regeneration, source change or evidence change was performed.

## Decision and material caveat

Preserve the scripts, run metadata, stdout/stderr (including failures and empty streams), synthetic inputs, raw requests/responses, assessor and witness records, signed packages, verifier outputs, reference source with its MIT license, results, documentation, and both manifest versions. **Exclude `live_m6_current/acceptance_registry.sqlite` from Git and any public package.** The existing manifests describe the *full local package*, including that SQLite file. Consequently, staging the recommended subset makes whole-manifest verification report one missing file. Neither existing manifest may be described as a complete manifest of the Git handoff. Retain them as historical/full-local provenance with this limitation; a separately scoped distributable manifest would be needed in a later authorized preparation step. Do not regenerate either historical manifest during this audit.

The exact file-by-file classification is below. `INCLUDE` means recommended for the engineering/evidence handoff, not that an E01–E13 research result is qualified. `REVIEW` is unused: the approved E08 pin, MIT-licensed source and synthetic evidence do not require an additional owner choice for this inclusion decision. Publication still needs normal owner review of repo visibility and disclosures; this audit is not a guarantee that arbitrary hidden content is absent.

## Integrity and dependency checks

- The package contains **283 files**. `file_manifest.json` declares **283 entries**: the other **282 package files** plus `docs/COMPLETION_SPRINT_2026-11-02.md`. The manifest intentionally cannot hash itself. All 283 declared paths exist, and every declared byte count and SHA-256 matches the current local file. The current manifest's own SHA-256 is `9f5e6966417a229b06cde85a86afa4d6e1c5ed2d04f7fdca19e71e27617b1301`.
- `file_manifest_step1_verified_2026-11-03.json` is present, SHA-256 `bac6ef071b4fe60db8eee6a5d2e4d917e2d6de31a0a9fe526f85ddc385686e6f`. It retains **282** entries from the Step 1 verified point. Compared with the current manifest, only this preserved snapshot was added; four documentation/status hashes changed: `experiment_inventory.json`, `report_evidence_map.md`, `sprint_results.md`, and `docs/COMPLETION_SPRINT_2026-11-02.md`. Thus its historical hash set must not be presented as matching the present tree: **278/282** entries match now, **4/282** differ, and none is missing.
- The refreshed manifest correctly describes the current local package and the one external sprint document. It includes the SQLite registry and the preserved Step 1 snapshot. It does **not** include the Step 4A readiness report, which is a later separate file, nor this audit. The package contains no other unlisted file besides the self-referential current manifest.
- All 67 expected per-case raw files for the eight M6Q calls, five E03 calls, both five-mutant E09 sets and four E10 packages exist. All 21 checked high-value result/witness paths across E03, M6Q, E08, E09, E10 and E12 exist. All 40 stdout/stderr paths recorded in the execution log exist. Both E03 parent witness triplets and both M6Q witness triplets are present; the signed packages and offline-verification records are present. These are file-presence and hash checks, not renewed experimental or oracle validation.
- The SQLite exclusion removes the retained registry's raw state from a public reviewer. The independent fresh-process reinspection, submission/readback records, signed package, assessor records, witness streams, and case results remain, so the documented bounded engineering observations can still be inspected. Exact whole-manifest replay and independent inspection of the original registry bytes cannot be claimed from the Git subset. No other proposed exclusion removes a referenced raw input or output.
- The package has three **public** PEM keys and no filename suggesting a private key. A text scan of all non-SQLite files found no PEM private-key header, AWS access key pattern, credential assignment pattern or email address. The payloads inspected were synthetic canaries/local-sink data. Two failure logs contain an absolute `C:\Users\Laptop\...` workspace path; they are retained because they document failed attempts. This scan is bounded and is not a substitute for the owner's publication review. Do not publish the SQLite database; no `audit.sqlite` is in this package, and none should be staged anywhere.
- E08's retained reference files are tied to approved revision `3dd9690b5b6f9c4ef385289714b314d13f6ad9a1`; the included `LICENSE` is MIT and must accompany those source files. The reference conformance is ten narrow cases and 19 supplied-fact steps, not a full comparative study. E03 remains **PARTIALLY EXECUTED — CONTRACT INCOMPLETE**; no E01–E13 result is fully contract-qualified.

## Recommended user-controlled staging strategy

1. Stage the exact `INCLUDE` files below, including `results/STEP4A_EXECUTION_READINESS_2026-11-03.md` and this audit report, using an explicit path list or reviewed path selection. Do not stage the directory wholesale.
2. Leave `live_m6_current/acceptance_registry.sqlite` unstaged. Also leave any `audit.sqlite`, temporary database, key, secret or credential elsewhere in the repository unstaged. This audit does not classify paths outside its stated scope.
3. Preserve both manifests verbatim, and describe the current manifest as a full-local inventory whose SQLite entry is intentionally absent from the Git subset. If a distributable package is required to pass a single all-files hash check, create a new subset manifest in a later separately authorized step; keep the Step 1 snapshot and current manifest unchanged.
4. Before any public push, the owner should check repository visibility, the two logs with local paths, and that the reference MIT license remains paired with the reference files. No staging or publishing action is authorized or performed here.

## Exact file classifications

Every path below is repository-relative and individually listed. The original classification rows were recovered without missing or duplicate paths, then checked against the current file inventory.

### INCLUDE — 283 files

| Classification | Repository-relative path |
| --- | --- |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/analysis_0.stderr.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/analysis_0.stdout.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/analysis_1.stderr.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/analysis_1.stdout.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/analysis_2.stderr.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/analysis_2.stdout.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/analysis_checks.run.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/analyze_e03.py` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/benchmark_development.py` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/build_execution_log.ps1` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/build_metamorphic_development.py` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/current_fresh_submission.stderr.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/current_fresh_submission.stdout.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/current_m6q.stderr.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/current_m6q.stdout.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/current_qualification.run.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/current_reinspect.stderr.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/current_reinspect.stdout.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/current_source_and_owner_pin.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/development_metric_input.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/development_metric_result.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E01_benign_reordering-A.input_revision.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E01_benign_reordering-A.input.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E01_benign_reordering-A.output_revision.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E01_benign_reordering-A.output.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E01_benign_reordering-A.release.b1_revision.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E01_benign_reordering-A.release.b1.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E01_benign_reordering-B.input_revision.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E01_benign_reordering-B.input.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E01_benign_reordering-B.output_revision.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E01_benign_reordering-B.output.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E01_benign_reordering-B.release.b1_revision.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E01_benign_reordering-B.release.b1.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_analysis.run.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_analysis.stderr.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_analysis.stdout.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_frozen_pilot_plan.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_metric_input.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot_escalated.run.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot_escalated.stderr.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot_escalated.stdout.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot_metrics.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot.run.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot.stderr.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot.stdout.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/assessor_public_key.pem` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/case_results.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-CONTROL-01/assessor_context.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-CONTROL-01/assessor_inventory.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-CONTROL-01/client_responses.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-CONTROL-01/E03-P2-DENIED-READ.oracle.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-CONTROL-01/E03-P2-DENIED-READ.witness.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-CONTROL-01/E03-P2-DENIED-READ/call.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-CONTROL-01/E03-P2-DENIED-READ/request.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-CONTROL-01/E03-P2-DENIED-READ/response.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-CONTROL-01/E03-P2-PUBLIC.oracle.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-CONTROL-01/E03-P2-PUBLIC.witness.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-CONTROL-01/E03-P2-PUBLIC/call.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-CONTROL-01/E03-P2-PUBLIC/request.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-CONTROL-01/E03-P2-PUBLIC/response.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-CONTROL-01/offline_verification.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-CONTROL-01/signed_package.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-CONTROL-01/witness/child.jsonl` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-CONTROL-01/witness/host.jsonl` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-CONTROL-01/witness/sink.jsonl` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/assessor_context.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/assessor_inventory.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/client_responses.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/E03-P1-HEX.oracle.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/E03-P1-HEX.witness.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/E03-P1-HEX/call.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/E03-P1-HEX/request.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/E03-P1-HEX/response.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/E03-P1-PUBLIC.oracle.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/E03-P1-PUBLIC.witness.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/E03-P1-PUBLIC/call.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/E03-P1-PUBLIC/request.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/E03-P1-PUBLIC/response.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/E03-P1-SOURCE.oracle.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/E03-P1-SOURCE.witness.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/E03-P1-SOURCE/call.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/E03-P1-SOURCE/request.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/E03-P1-SOURCE/response.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/offline_verification.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/signed_package.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/witness/child.jsonl` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/witness/host.jsonl` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/E03-PILOT-EXPOSURE-01/witness/sink.jsonl` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/frozen_plan.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e08_conformance_cases.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e08_conformance_results.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e08_conformance.py` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e08_conformance.run.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e08_conformance.stderr.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e08_conformance.stdout.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e08_reference_provenance.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e08_reference_verify.run.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e08_reference_verify.stderr.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e08_reference_verify.stdout.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e08_reference/LICENSE` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e08_reference/prototype/datatypes.py` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e08_reference/prototype/pep/enforcer.py` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e08_reference/prototype/pep/label_tracker.py` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e08_reference/prototype/pep/rules.py` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_a3_mutation_development.py` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_a3_mutations_pinned.run.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_a3_mutations_pinned.stderr.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_a3_mutations_pinned.stdout.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_a3_mutations_retry.run.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_a3_mutations_retry.stderr.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_a3_mutations_retry.stdout.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_a3_mutations.run.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_a3_mutations.stderr.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_a3_mutations.stdout.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants_revision/E09-DEV-A3-00.package.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants_revision/E09-DEV-A3-00.verifier.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants_revision/E09-DEV-A3-01.package.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants_revision/E09-DEV-A3-01.verifier.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants_revision/E09-DEV-A3-02.package.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants_revision/E09-DEV-A3-02.verifier.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants_revision/E09-DEV-A3-03.package.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants_revision/E09-DEV-A3-03.verifier.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants_revision/E09-DEV-A3-04.expected_config.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants_revision/E09-DEV-A3-04.package.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants_revision/E09-DEV-A3-04.verifier.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants_revision/mutation_results.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants/E09-DEV-A3-00.package.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants/E09-DEV-A3-00.verifier.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants/E09-DEV-A3-01.package.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants/E09-DEV-A3-01.verifier.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants/E09-DEV-A3-02.package.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants/E09-DEV-A3-02.verifier.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants/E09-DEV-A3-03.package.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants/E09-DEV-A3-03.verifier.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants/E09-DEV-A3-04.expected_config.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants/E09-DEV-A3-04.package.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants/E09-DEV-A3-04.verifier.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants/mutation_results.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_variant_and_mutation_plan.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e10_development_plan.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e10_signed_wrong_development.py` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e10_signed_wrong_development/assessor_truth.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e10_signed_wrong_development/case_results.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e10_signed_wrong_development/E10-DEV-00.signed_package.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e10_signed_wrong_development/E10-DEV-00.verifier.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e10_signed_wrong_development/E10-DEV-01.signed_package.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e10_signed_wrong_development/E10-DEV-01.verifier.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e10_signed_wrong_development/E10-DEV-02.signed_package.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e10_signed_wrong_development/E10-DEV-02.verifier.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e10_signed_wrong_development/E10-DEV-03.signed_package.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e10_signed_wrong_development/E10-DEV-03.verifier.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e10_signed_wrong_development/test_signer_public_key.pem` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e10_signed_wrong.run.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e10_signed_wrong.stderr.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e10_signed_wrong.stdout.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development_inputs_revision/ambiguous-reservation.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development_inputs_revision/failed-use-retry.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development_inputs_revision/grant-use-revoke.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development_inputs_revision/matched-grant-revoke.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development_inputs_revision/matched-revoke-grant.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development_inputs_revision/monotone-public-transfer.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development_inputs_revision/multiple-grants-interleaved-scopes.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development_inputs_revision/public-current.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development_inputs_revision/regrant-new-identity.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development_inputs/ambiguous-reservation.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development_inputs/failed-use-retry.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development_inputs/grant-use-revoke.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development_inputs/matched-grant-revoke.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development_inputs/matched-revoke-grant.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development_inputs/monotone-public-transfer.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development_inputs/multiple-grants-interleaved-scopes.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development_inputs/public-current.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development_inputs/regrant-new-identity.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development_instrumentation_revision.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development_instrumentation.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development.run.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development.stderr.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_development.stdout.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_revision.run.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_revision.stderr.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e12_revision.stdout.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_harmless_gap-A.input_revision.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_harmless_gap-A.input.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_harmless_gap-A.output_revision.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_harmless_gap-A.output.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_harmless_gap-A.release.b1_revision.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_harmless_gap-A.release.b1.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_harmless_gap-B.input_revision.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_harmless_gap-B.input.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_harmless_gap-B.output_revision.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_harmless_gap-B.output.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_harmless_gap-B.release.b1_revision.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_harmless_gap-B.release.b1.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_valid_scope_interleaving-A.input_revision.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_valid_scope_interleaving-A.input.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_valid_scope_interleaving-A.output_revision.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_valid_scope_interleaving-A.output.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_valid_scope_interleaving-A.release.b1_revision.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_valid_scope_interleaving-A.release.b1.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_valid_scope_interleaving-B.input_revision.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_valid_scope_interleaving-B.input.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_valid_scope_interleaving-B.output_revision.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_valid_scope_interleaving-B.output.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_valid_scope_interleaving-B.release.b1_revision.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/E13_valid_scope_interleaving-B.release.b1.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/execution_log.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/experiment_inventory.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/file_manifest_step1_verified_2026-11-03.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/file_manifest.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/assessor_context.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/assessor_inventory.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/assessor_public_key.pem` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/case_results.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/controls.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/fault_inventory.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/fresh_process_reinspection.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/fresh_submission_readback.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/fresh_submission.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/frozen_plan.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-01/call.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-01/request.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-01/response.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-02/call.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-02/request.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-02/response.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-03/call.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-03/request.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-03/response.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-04/call.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-04/request.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-04/response.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-05/call.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-05/request.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-05/response.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-06/call.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-06/request.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-06/response.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-07/call.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-07/request.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-07/response.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-08/call.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-08/request.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/M6Q-08/response.bin` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/offline_verification.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/pre_execution_registration.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/signed_package.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/witness_fault/child.jsonl` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/witness_fault/host.jsonl` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/witness_fault/sink.jsonl` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/witness_primary/child.jsonl` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/witness_primary/host.jsonl` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/witness_primary/sink.jsonl` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/metamorphic_development_pairs_revision.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/metamorphic_development_pairs.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/metamorphic_development.run.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/metamorphic_development.stderr.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/metamorphic_development.stdout.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/metamorphic_revision.run.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/metamorphic_revision.stderr.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/metamorphic_revision.stdout.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/metrics_revision.run.json` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/metrics_revision.stderr.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/metrics_revision.stdout.log` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/prepare_development_metrics.py` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/qualify_live_current.py` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/ranked_execution_plan.md` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/reinspect_current.py` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/report_evidence_map.md` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/research_metrics.py` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/run_analysis_checks.ps1` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/run_artifact.ps1` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/run_current_qualification.ps1` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/run_e03_pilot.py` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/run_e12_development.ps1` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/run_e12_revision.ps1` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/run_metamorphic_development.ps1` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/run_metamorphic_revision.ps1` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/run_metrics_revision.ps1` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/sprint_results.md` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/submit_current.py` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/test_research_metrics.py` |
| INCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/verify_e08_reference.py` |
| INCLUDE | `results/STEP4A_EXECUTION_READINESS_2026-11-03.md` |

### EXCLUDE — 1 file

| Classification | Repository-relative path | Reason |
| --- | --- | --- |
| EXCLUDE | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/acceptance_registry.sqlite` | Local SQLite acceptance-registry state; prohibited from the Git/public handoff. Its exclusion means the staged subset cannot satisfy the unchanged full-local manifest. |

### Verification of the repaired list

- **Counts:** 283 INCLUDE, 1 EXCLUDE, 0 REVIEW; 284 classified files across the 283-file package plus the Step 4A report. This audit report is a later new document and is not counted in the original 283 INCLUDE classification.
- **Existence:** every one of the 284 classified paths independently exists in the current working tree. There are no duplicate paths, missing inventory files or extra classified paths.
- **Manifest coverage:** 281 INCLUDE package files are entries in the unchanged current full-local manifest. The two documented INCLUDE exceptions are `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/file_manifest.json` (self-reference is impossible) and `results/STEP4A_EXECUTION_READINESS_2026-11-03.md` (later addition outside the five-hour package). The EXCLUDE SQLite file is also an entry in the full-local manifest.
- **Handoff limitation:** do not claim the proposed staged subset passes whole-manifest verification. The Step 1 verified snapshot and refreshed manifest remain unchanged; `audit.sqlite` must never be staged. The two absolute-path logs need owner publication review, and the E08 MIT license must stay with the retained reference source. No E01–E13 research result is fully contract-qualified.
