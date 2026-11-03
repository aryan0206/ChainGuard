# Current-source live M6 qualification gate

**Status: BLOCKED.** H22–H25's supplied revision `8b27b5a980a87887be66c409c5a6a31d415a3326` predates the final environment-guard source change. The H22 package binds an older `m6_live_runtime.py` digest (`ed1574f4599d61714c0d3db670d0a64dd82c74acb314433f2966334fdb96325e`); current file digest in the engineering preflight is `c136f3c68306a3fb2b377da9002738bcf3fab6276e84fef57c2047f47c0dd15d`. A successful focused engineering test cannot establish signed current-source qualification.

The owner must provide and independently attest a new lowercase 40-hex revision that identifies the exact frozen application source being qualified. The assessor must separately hash and retain this run harness. No agent Git query or synthetic pin is allowed for this gate. The assessor must retain the pin, source manifest/digests, frozen eight-case plan, controls and inventory outside the signed package, and confirm that the runner's trusted runtime environment value matches that independent pin. The gate then requires raw proposal/response bytes, child and host witness streams, independent source/handler/sink exact bytes and digests, control/reservation COMMIT, task completion, signed export and offline inspect results, with timestamps/exit code and every failed case retained. Absence claims require complete capture coverage and clean process closure. Existing H22 M6Q output is historical engineering evidence, not current-source evidence.

Prepared command for a **separate authorized future run**, only after the owner has supplied the matching pin and frozen the source:

```powershell
$env:CHAINGUARD_ASSESSOR_REVISION_PIN = '<owner-attested-current-source-40-hex>'
$env:CHAINGUARD_TRUSTED_CODE_REVISION = $env:CHAINGUARD_ASSESSOR_REVISION_PIN
$env:PYTHONPATH = (Resolve-Path '.').Path
.\.venv\Scripts\python.exe -B results/completion_sprint_2026-11-02/RESEARCH_UNBLOCKING/qualify_current_after_pin.py
```

The new wrapper refuses the prior revision and existing output directory, then invokes the retained eight-case harness with an assessor pin separate from the runtime source variable. It has **not** been executed or qualified. The owner-attested revision must be checked against the exact current source independently; matching two environment strings alone does not establish source identity. The future run must record its own raw logs and exit code. Do not promote M6Q checks to E01–E13 observations without separately frozen research cases and oracle.
