# E09 retained-evidence and integrity audit

This audit read only the existing E09 plan, runner, result ledger and per-case packages/reports. It did **not** access either `audit.sqlite` or `acceptance_registry.sqlite`, run any mutation/verifier command, or change a prior artifact. See [readiness](E09_PARITY_READINESS.md), [variant matrix](E09_VARIANT_MATRIX.md), [results](E09_PARITY_RESULTS.md), and [status](E09_FINAL_STATUS.md).

The unchanged current full-local [file manifest](../completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/file_manifest.json) records SHA-256 for the following, and current local hashes matched its entries during this audit:

| Retained artifact under `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/` | SHA-256 |
| --- | --- |
| `e09_variant_and_mutation_plan.json` | `e576aea13ada2e63ba224c6c3813620d30e4a39855005808c33f0ab8889691e8` |
| `e09_a3_mutation_development.py` | `db4a48cabb39f734a5b5d004387e868d6605fa963ce27f73cf3eec301da58f42` |
| `e09_mutants_revision/mutation_results.json` | `d03d987914016851e47cea651cd6a430cdc8731ed429319613303dc936a35e8d` |
| `e09_mutants_revision/E09-DEV-A3-02.package.bin` | `82b3bfbd2a46582af1ed80f788b9c2a6d0635ca311f42e3527f58271a39e4f19` |
| `e09_mutants_revision/E09-DEV-A3-02.verifier.json` | `9c7b02fc47f11b2f4b7485d86fa066c52fd22c71e46a66078a6ff6defe094a55` |
| `e09_mutants_revision/E09-DEV-A3-03.package.bin` | `0c36589d334b4e7dd61f55b94af2b17b7bfaad8dcdd02e670f6cf393b4ae899e` |
| `e09_mutants_revision/E09-DEV-A3-03.verifier.json` | `9c7b02fc47f11b2f4b7485d86fa066c52fd22c71e46a66078a6ff6defe094a55` |

The two verifier reports happen to have equal SHA-256 bytes; both separately remain present under their distinct case IDs. Each records `package_schema=FAIL`, `commitment_integrity=NOT_CHECKED`, `inspection_passed=false`. Their predeclared expected `commitment_integrity=FAIL` remains in the plan. The pinned run metadata at `e09_a3_mutations_pinned.run.json` records `2026-11-03T13:11:25.9215196+05:30` to `13:11:27.2703526+05:30`, Python 3.14.3, PowerShell 7.6.5, owner revision `89dfbf78a953701cad2eb17da03218ff2abec709`, exit **1**, with stdout/stderr paths retained. All five A3 inputs and verifier outputs remain in `e09_mutants_revision/`; an earlier `e09_mutants/` attempt is also retained. These are historical engineering artifacts, not a prospective research sample.

Existing evidence supports the exact 3/5 development-dimension account and the two mismatches. It does not supply equal-content A0/A1/A2/A3T/A4/A4T packages, case-level expected dimensions, mutation ledgers, trusted digest controls or paired cost data. The [Step 4A readiness report](../STEP4A_EXECUTION_READINESS_2026-11-03.md) already classifies E09 as inconclusive. Hash agreement demonstrates current file consistency with the saved manifest; it does not validate research ground truth. The manifest's SQLite entry remains a full-local inventory issue described in the [Git inclusion audit](../SPRINT_EVIDENCE_GIT_AUDIT_2026-11-03.md); no database was opened here.
