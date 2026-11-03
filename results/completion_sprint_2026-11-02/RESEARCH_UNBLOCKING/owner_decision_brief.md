# Owner decision brief — 3 November 2026

**Owner replies received 3 November 2026:** “Approve repository labels” for A1/A2, and “Confirm the lock’s revision” for E08. The recommendations below are now recorded owner decisions. Approval of the E08 pin does not verify that source locally or pass conformance. No experiment result follows from either decision.

## A1/A2 provenance and recommendation

The supplied shorthand in `docs/EVALUATION_PROTOCOL.md:11` says **A1 hash chain; A2 signed closure**. The project charter (`docs/PROJECT_CHARTER.md:90-91`) and repository protocol variant table (`docs/EVALUATION_PROTOCOL.md:125-126`) say **A1 independent event hashes; A2 unkeyed hash chain**. The Architecture Lock preserves signed-chain/transcript variants as A3/A3T and expected-run acceptance as A4/A4T. The H9–H12 conflict note and H12–H16 owner decision sheet record the discrepancy; neither is an approval. Independent *experimental* evidence cannot decide a naming convention. The independent documentary authority favors the repository labels because the charter, protocol variant table and lock contracts agree.

**Recommendation:** owner explicitly confirms repository labels A1=independent event hashes, A2=unkeyed event hash chain, A3=signed chain, A3T=signed transcript, A4/A4T=acceptance wrappers, and marks the supplied shorthand superseded. If the shorthand is chosen instead, E09's seven-variant matrix, mutant expectations, cost comparison, result labels and related RQ3/RQ5/RQ6/RQ8 claims require explicit redesign and lock review. Existing outputs must be remapped by mechanism, never by A-label alone. No E09 ablation may run before the owner decision and frozen variant/mutation ledger.

**Owner answer A:** Approved repository labels; the conflicting supplied shorthand is superseded. E09 remains blocked on frozen variants, mutant ledger and comparable evidence.

## E08 baseline identity and recommendation

The intended external implementation is `wilesanGH/mcp-pep-agent-security`, narrowed to a Wang-style R02 sensitivity-policy subset, not its full system (`docs/ARCHITECTURE_LOCK.md:310-322`, `docs/BASELINE_NOTES.md`). The supplied `docs/EVALUATION_PROTOCOL.md:12` candidate is `3dd9690b5b6f9c4ef385289714b314d13f6ad1` (short/incomplete). Lock §17 specifies `3dd9690b5b6f9c4ef385289714b314d13f6ad9a1` (40 hex). A local file-name search for the reference's `enforcer.py`, `label_tracker.py`, `rules.py`, `datatypes.py` and `mcp-pep*` returned no matches in this workspace; no pinned reference source, driver, adapter or local identity proof is available. No Git or network retrieval was attempted. The lock is documentary support for the intended pin, not proof that the source is present or conforms.

**Recommendation:** owner confirms the Lock §17 full revision if intended. Then obtain and independently identify that exact source under the owner's Git workflow, retain source digest/provenance, freeze the shared R02 facts/mapping and run the complete differential conformance gate before a paired E08 comparison. An alternate revision requires an explicit lock amendment. The short candidate cannot support reproducibility. Fairness additionally requires equal input facts, histories, destinations, controller envelope and independent workflow oracle. There is no E08 comparative result.

**Owner answer B:** Confirmed `3dd9690b5b6f9c4ef385289714b314d13f6ad9a1`. E08 remains blocked on the exact source, adapter, differential conformance and independently labeled common-domain cases.
