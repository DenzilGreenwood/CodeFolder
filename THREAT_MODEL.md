# CIAF / LCM Threat Model & Trust Boundaries

## 1. System Goals
The Lifecycle Canonicalization and Measurement (LCM) framework provides **tamper-evidence, non-repudiation, and independent verifiability** for AI agent workflows. It transforms unstructured agent logs into cryptographically bound evidence records.

---

## 2. In-Scope Protections (What Cryptography Guarantees)
* **Post-Signing Tamper Detection**: Any modification to agent context, parameters, or gate decisions after signing invalidates the SHA-256 hash and Ed25519 signature.
* **Cross-Context Replay Attacks**: Domain separation prefixes (`AGEI:agent-tool-call:ciaf-json-v1\0`) prevent valid receipts from being replayed in unauthorized contexts.
* **Policy Governance Drift**: Policy definitions are signed and anchored under the `POLICY_VERSION` domain, preventing silent modifications to rule definitions.
* **Causal Chain Integrity**: Step $N+1$ binds the `content_hash` of Step $N$, creating an immutable audit trail.

---

## 3. Out-of-Scope Risks (What Cryptography Does NOT Guarantee)
* **Valid Signature over Bad Decisions (Hallucinations)**: If an agent hallucinates a parameter that complies with policy rules, LCM will successfully sign and execute it. Cryptography guarantees *non-repudiation of the decision*, not the *wisdom of the decision*.
* **Prompt Injection / Compromised Agents**: If an attacker tricks an agent into generating a malicious plan, the agent's key will legitimately sign the bad payload.
  * *Mitigation*: Agents are untrusted event producers. Independent, deterministic Policy Gates evaluate plans against strict boundaries before live execution.
* **Standing Privilege**: LCM's signature-and-policy-gate model proves an action was signed by an authorized key and approved by policy at time of signing. It does not currently implement scoped, time-bound privilege elevation (per Governance Planes §4) — a compromised or misdirected agent with valid standing key authority could sign multiple approved-shaped transactions without requiring fresh, per-action authorization.

---

## 4. Trust Assumptions
1. **Event-Level Key Custody**: Signing keys assigned to agents and gates for frequent, local event signing are stored securely. These provide immediate causal chain integrity but rely on self-asserted timestamps.
2. **Policy Gate Independence**: Policy evaluation runtime operates independently of the LLM generation context. *(Note: The reference implementation enforces this by requiring gates to be deterministic rule engines—e.g., comparing `requested_amount_cents` against `spending_limit_cents`—rather than secondary LLM calls susceptible to the same prompt injections).*
3. **Policy Authorship Integrity**: The policy definitions anchored in the ledger (under the `POLICY_VERSION` domain) are authored, reviewed, and signed by human administrators or a separate trusted governance process, not generated dynamically by the agent stack.
4. **Ledger-State Custody (Checkpointing)**: A highly secure, independent HSM/KMS periodically signs the WORM Merkle root to attest to the state of the ledger at time *T*. If the WORM operator is independent, this provides cryptographic proof of external time.
5. **Identity Binding**: Each signed event carries a structured identity claim (service identity, delegating principal, workflow role, session context). The service identity, delegating principal, and workflow role are cross-checked by the Policy Gate against an independently signed provisioning record anchored under the `IDENTITY_BINDING` domain (signed by the same human governance process described in Assumption 3). The session context is self-asserted and protected only by the causal hash chain (see Assumption 1). [cite: Governance Planes for Agentic AI, §3]

---

## 5. Checkpoint Attestation & Time-Stamping

The LCM framework employs a dual-signature architecture to balance speed and high-assurance time-attestation (similar to Certificate Transparency logs):

* **Local Event Signatures (Fast)**: Every individual event (planner, gate, executor) keeps its local Ed25519 signature. This preserves the hash chain's integrity instantly and cheaply, preventing retroactive tampering.
* **Checkpoint Signatures (High Assurance)**: Periodically, a high-assurance HSM/KMS signs a **checkpoint** over the aggregate WORM Merkle root hash. This attests to the *state of the ledger* at time *T*.

### Bounding the External-Timestamp Gap
If the checkpoint signer is the independent third-party hosting the WORM server, the HSM-signed audit receipt proves that "this Merkle root existed and was attested to at time T" by a party with no incentive to backdate it. This provides a true external time-attestation, significantly stronger than the self-asserted timestamps of individual events.

### Limitations & Checkpoint Frequency
An HSM-signed root at time *T* proves that everything included in the tree up to that point existed in that exact form. However, it says nothing about events that occur *after* the last checkpoint but *before* the next one. During this window, the system relies purely on local signing for time-integrity. 

Therefore, the **checkpoint interval** is a critical design parameter. The gap between checkpoints defines the maximum window of weaker external-time assurance. Checkpoints SHOULD occur no less frequently than every 24 hours, though this is configurable per deployment depending on transaction volume and risk tolerance.

---

## 6. Governance Plane Coverage

The following table maps the LCM implementation to the five agent governance planes (per *Governance Planes for Agentic AI*):

| Plane | Status | Notes & Cross-References |
|-------|--------|--------------------------|
| **Identity** | Implemented | Event payloads include structured Agent Identity claims which are validated against anchored provisioning records. (See *Trust Assumption 5*) |
| **Policy** | Implemented | Enforced via independent deterministic rule engines. (See *Trust Assumption 2 & 3*) |
| **Privilege** | Not Implemented | Currently relies on standing authority rather than JIT elevation. (See *Out-of-Scope Risks: Standing Privilege*) |
| **Execution** | Implemented | Mediated through cryptographic circuit breakers before live execution. |
| **Evidence** | Implemented | Core LCM focus. Strong WORM Merkle attestations and detached signatures. |
