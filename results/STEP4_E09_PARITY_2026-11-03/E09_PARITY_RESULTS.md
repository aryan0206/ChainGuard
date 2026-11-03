# E09 parity results — retained evidence only

No new variant or mutation check was executed in this sprint. The table reproduces the existing **A3 engineering-development** ledger, not a research denominator. Frozen expectations are from [e09_variant_and_mutation_plan.json](../completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_variant_and_mutation_plan.json); actuals are from the unchanged [mutation_results.json](../completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e09_mutants_revision/mutation_results.json) and per-case verifier reports. See [readiness](E09_PARITY_READINESS.md), [variant matrix](E09_VARIANT_MATRIX.md), [evidence audit](E09_EVIDENCE_AUDIT.md), and [final status](E09_FINAL_STATUS.md).

| Existing case | Mutation | Predeclared expected dimension/status; overall inspection | Observed dimension/status; overall inspection | Expectation match |
| --- | --- | --- | --- | --- |
| E09-DEV-A3-00 | none | commitment_integrity PASS; inspection true | commitment_integrity PASS; true | **YES** |
| E09-DEV-A3-01 | noncanonical-trailing-byte | package_schema FAIL; false | package_schema FAIL; false | **YES** |
| E09-DEV-A3-02 | edit-first-event-sequence | commitment_integrity FAIL; false | **package_schema FAIL; commitment_integrity NOT_CHECKED**; false | **NO — preserved mismatch** |
| E09-DEV-A3-03 | delete-last-record | commitment_integrity FAIL; false | **package_schema FAIL; commitment_integrity NOT_CHECKED**; false | **NO — preserved mismatch** |
| E09-DEV-A3-04 | wrong-assessor-configuration | expected_binding FAIL; false | expected_binding FAIL; false | **YES** |

**Existing development check accounting:** five attempted, **three expected-dimension matches**, **two expected-dimension failures/mismatches**, zero excluded, zero unobserved among these five. The two mutated packages were rejected by schema validation before commitment integrity was checked; their overall inspection failure does **not** satisfy the frozen expected dimension. Historical pinned runner exit code was **1** and stdout said `matched_expectations=3/5 research_cells=0`. This is not a new run or a pass/fail rate for seven-variant parity. No new checks, retries, timeouts or exclusions occurred in this sprint. Six other variant mechanisms have **zero E09 parity cells**, so no seven-variant success count or comparative metric exists. E09 remains **INCONCLUSIVE**, with **zero research-qualified observations**.

No detector/evidence superiority, tamper-detection rate, cryptographic failure probability, acceptance effectiveness, or A3/A3T cost comparison can be inferred from these five designed development cells. Preserve both mismatch reports and original expected results exactly.
