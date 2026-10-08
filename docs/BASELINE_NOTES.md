# External baseline notes

**Status: NOT STARTED / CONFORMANCE PENDING. No comparative result exists.** This document specifies future controls; Phase 1 implements no adapter and runs no baseline.

## Pin and narrow scope

Authoritative [Architecture Lock](ARCHITECTURE_LOCK.md) Section 17 references [mcp-pep-agent-security](https://github.com/wilesanGH/mcp-pep-agent-security), revision `3dd9690b5b6f9c4ef385289714b314d13f6ad9a1`. The supplied Astra task instead states `3dd9690b5b6f9c4ef385289714b314d13f6ad1`. Preserve this discrepancy; the latter is not a full 40-character SHA. Do not silently fetch a substitute or amend the lock. Resolve with the owner before baseline implementation/conformance. No external revision was fetched or verified here.

The intended subset is R02 with default-allow behavior on the declared common surface, using `prototype/pep/enforcer.py`, `prototype/pep/label_tracker.py`, `prototype/pep/rules.py` and `prototype/datatypes.py` at the locked revision. Keep the baseline's name distinct from B0/B1/B2. This is a Wang-style sensitivity-policy subset adaptation, not full reproduction of the published system.

At each proposal merge current-argument sensitivity with accumulated successful-result sensitivity; SENSITIVE wins. Accumulation starts NORMAL and is sticky. Current arguments affect the current decision but do not alone update accumulation without a result. Denied/failed-without-result acquisition does not create successful exposure; unknown results terminate covered evaluation. Grants do not bypass R02; destination identity does not add exceptions.

| Common tool | Locked mapping |
| --- | --- |
| Acquisition | `filesystem.read_file` |
| Declared transformations | Neutral non-R02 tools |
| Every configured capture-sink destination | `http_post.post`, not internal notify/send_message |

Enable token/tool admission and keep call limits nonbinding on the common valid surface. Exclude R01/R03/R04/R05, source-integrity propagation, intent-taint, confirmation UX, rate limits, capability exhaustion, source path-normalization experiments, original logging and LLM behavior. Exclusions do not remove accumulated sensitivity.

## Conformance-first gate

Before comparison, a pinned reference-subset driver and adapter must receive common frozen sensitivity facts and agree on decision, matched R02 rule, effective sensitivity and post-outcome accumulated sensitivity for:

- Sensitive outbound arguments without history; benign outbound without history.
- Successful sensitive result followed by benign-looking outbound.
- Public results and transformations after sensitive exposure.
- Denied/failed acquisition; sensitive current arguments without a subsequent result.
- Every mapped destination, grant presence and permitted reconnect without reset.

Record supported-domain definitions, pins/digests, exact differential inputs/outputs and mismatches. If conformance fails, stop inclusion and comparative claims. The driver qualifies policy semantics; it does not replace the independent workflow oracle. Common extraction does not reproduce the original regex pipeline.

## Fairness and prohibited asymmetries

| Constraint | Required equality / explicit boundary |
| --- | --- |
| Facts/results | Same sensitivity facts and successful/failed/unknown result observations; no richer extraction for one system |
| Tools/destinations | Same frozen mapping; no selective destination exception or grant bypass for R02 |
| Tasks/history | Same task boundaries and histories in shadow comparisons; no hidden reset after exposure or reconnect |
| Execution | Same static safety envelope/controller; enforcement uses separate equivalent workflows and reports divergent trajectories |
| Oracle | Same independently specified workflow definitions, pre-decision labels, source/sink/task and consumption observations |
| Unsupported/unknown | Same handling on the declared common domain; exclusions and denominator changes disclosed |
| Measurement | Same hardware, repetition policy and timing/storage/memory boundaries; do not charge evidence overhead selectively |

Do not weaken a baseline after seeing cases, credit common-controller prevention to its detector, compare unsupported domains as conformant, leak future results or use unequal task-completion definitions. R02 and scoped authorization serve different policy objectives; report that semantic difference rather than equating all denials with errors. E08/E05 outcomes and E12 cost remain unmeasured. [Protocol](EVALUATION_PROTOCOL.md) and [claims register](CLAIMS_REGISTER.md) govern interpretation.
