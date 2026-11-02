# Owner decision sheet — evidence labels and external baseline pin

Prepared 2 November 2026. No locked document, label, or pin was changed. These are owner decisions needed before E09 or E08 execution; neither affects the development-only E02/E13 capture in this directory.

## Decision 1: A1/A2 evidence labels

**Conflicting source statements (verbatim):**

- `docs/EVALUATION_PROTOCOL.md:11`, supplied protocol column: “A0 no integrity; A1 hash chain; A2 signed closure”.
- `docs/PROJECT_CHARTER.md:90`: “A1 | Independent event hashes”.
- `docs/PROJECT_CHARTER.md:91`: “A2 | Unkeyed event hash chain”.
- `docs/EVALUATION_PROTOCOL.md:125-126` repository variant table: “A1 | Independent event hashes” and “A2 | Unkeyed hash chain”.
- `docs/EVALUATION_PROTOCOL.md:11` treatment: “Use repository labels below; retain supplied alternatives here pending explicit resolution before ablation execution. No A2 signed-closure experiment is silently substituted.”

**Consequences:** following the supplied shorthand would call a signed closure A2 and collapse the independent-hash/unkeyed-chain distinction, changing E09 variant identities, mutant expectations, result tables and paper claims. Following the repository labels preserves the charter/lock-aligned A0–A4/A3T/A4T study but requires the owner to explicitly retire or reconcile the supplied shorthand. Do not map old A1/A2 results to repository A1/A2 by name alone.

**Proposed decision for approval:** retain repository A1=independent event hashes, A2=unkeyed event hash chain, A3=signed chain, A3T=signed transcript, A4/A4T=their expected-run acceptance wrappers. Record the supplied shorthand as superseded wording only after owner approval. Freeze exact mutant-by-variant expectations before E09. No implementation or protocol edit follows from this sheet alone.

## Decision 2: E08 external baseline revision and conformance

**Conflicting source statements (verbatim):**

- `docs/EVALUATION_PROTOCOL.md:12`, supplied protocol column: “`3dd9690b5b6f9c4ef385289714b314d13f6ad1`”.
- `docs/ARCHITECTURE_LOCK.md:310`: “Pinned revision: 3dd9690b5b6f9c4ef385289714b314d13f6ad9a1.”
- `docs/EVALUATION_PROTOCOL.md:12` treatment: “These strings differ; supplied string is not a full 40-character SHA. Locked pin remains authoritative; owner resolution required before baseline work.”
- `docs/BASELINE_NOTES.md`, conformance gate: “Before comparison, a pinned reference-subset driver and adapter must receive common frozen sensitivity facts and agree on decision, matched R02 rule, effective sensitivity and post-outcome accumulated sensitivity”.

**Consequences:** using the shorter supplied string risks selecting a different or nonexistent revision and makes the comparison unreproducible. Using the locked full pin still requires source verification, a frozen R02 subset/mapping, and passing differential conformance; it does not permit a baseline performance or superiority claim now. A different pin would be a material lock amendment.

**Proposed decision for approval:** confirm the exact full revision in Lock §17, `3dd9690b5b6f9c4ef385289714b314d13f6ad9a1`, or approve an explicit lock amendment if incorrect. After approval, pin the source/driver and execute the complete common-fact R02 conformance set **before** any paired E08 comparison. No Git/network retrieval or conformance execution occurred in this checkpoint.
