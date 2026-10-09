# ChainGuard contributor instructions

## Authority and current gate

The student/project owner approves major research, architecture, implementation and dependency decisions. Explicit owner instructions take precedence over these local guidelines.

On 7 October 2026, the owner approved research direction and mandatory scope, selected ECDSA P-256, and authorized final synchronization of the reviewed contracts. The owner explicitly declared ARCHITECTURE LOCKED — ChainGuard Architecture v1.1 without changing the architecture. **Application code and dependency installation are explicitly prohibited for this stage.** Neither synchronization nor formal architecture lock authorizes implementation. A later explicit implementation instruction can open that gate; dependency approval remains separate.

Chronology clarification, 9 October 2026: the preceding prohibition is the historical 7 October lock-stage rule. Subsequent explicit owner milestone authorizations are recorded in [the engineering history](docs/SPIKE_LOG.md#historical-engineering-readme-at-checkpoint-5d00057). Preserve the rule: architecture lock alone grants no implementation or dependency permission. The initial 9 October cleanup request authorized the specified Markdown cleanup and viva guide without commit or push. That restriction describes that historical request, not a standing prohibition on later explicitly authorized work.

Read [the charter](docs/PROJECT_CHARTER.md), [the Architecture Lock](docs/ARCHITECTURE_LOCK.md), [the threat model](docs/THREAT_MODEL.md), and [the playbook](ENGINEERING_PLAYBOOK.md) before project work. The Architecture Lock is the single authoritative source of architecture contracts. Supporting documents must agree with it. ARCHITECTURE_AMENDMENTS_V1.md is historical/supporting material only and cannot independently override the lock.

Normal observation mode MUST NOT bypass authorization. Unauthorized forwarding is permitted ONLY by the explicitly configured synthetic local-sink override in the committed controller profile. Grant/revoke/one-use consumption remain CORE final-project capabilities. M1–M5 are the minimum Evaluation-1 slice; M6 is optional for Evaluation 1 but mandatory for final completion, without weakening or redefining architecture.

## Change control

Do not silently change mandatory components, transport coverage, detection methodology, cryptographic algorithms, trust assumptions or research claims. For a material change, present the current design, proposed change, reason, benefit, cost, affected modules/tests/paper, and timeline impact; wait for owner approval before implementing the change.

Routine decisions within an authorized implementation task may proceed without repeated approval. Explain each proposed new dependency before installation; obtain approval for the dependency set and compatible version pins. Do not install speculative packages, or introduce Docker, cloud services, complex frontends, packet capture, or empty source directories.

Optional extensions are not permission to implement them. ML requires a separate data and evaluation justification. Retaining sensitive payloads requires approval and the confidentiality controls in the Architecture Lock.

## Engineering and evidence

- Prefer deterministic, explainable methods and reviewed cryptographic libraries; never implement cryptographic primitives or ECDSA nonce generation manually.
- Keep behavioral verdicts, authorization decisions, and evidence verification statuses distinct.
- Never claim hashes alone authenticate evidence, signatures prove detector correctness, local timestamps provide trusted timestamping, or evidence replay checks prevent replay of tool executions.
- Use synthetic sensitive data and a local capture sink for experiments. Keep private keys, raw sensitive content and local secrets out of Git and public reports.
- Ground truth must come from independently specified fixtures and oracle observations, not from the detector being evaluated.
- Run meaningful checks appropriate to the change. Record real results, limitations, versions and reproducibility details. Do not fabricate numbers or present future work as implemented.
- Keep the controlled tool surface and observation boundary explicit. Do not claim arbitrary information-flow tracking or universal MCP protection.

## Workflow and student understanding

Follow research, critique, proposal, owner approval, architecture lock, authorized implementation, testing, explanation, student verification, milestone commit, and paper update. Do not create a milestone commit before student verification. Do not push or publish without authorization.

For each major component, explain what it does, why it exists, how it works, why it was chosen, alternatives, limitations and likely viva questions. Update the existing control documents when facts change; add documents only when justified by actual work. Record unimplemented, untested and incomplete items candidly.
