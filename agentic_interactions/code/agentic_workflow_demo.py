import logging
import sys
from typing import Dict, Any
from datetime import datetime, timezone

# Configure structured, verbose logging to explain every LCM pipeline step
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("Agentic_AI_Demo")

import os
import sys
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, project_root)

# Import CIAF core modules
from core.domain_binder import CIAFDomainBinder
from core.signer_envelope import Ed25519Signer, CIAFEnvelopeBuilder
from core.worm_verifier import WORMMerkleTree, CIAFVerifier
from core.agent_identity import AgentIdentity


def run_agentic_workflow_demo():
    logger.info("==================================================================")
    logger.info("  STARTING AGENTIC AI LCM WORKFLOW DEMO")
    logger.info("==================================================================")

    # 1. Initialize Framework Infrastructure
    logger.info("[INIT] Loading CIAF infrastructure services...")
    binder = CIAFDomainBinder()  # Loads domain mappings from core/domainsjson/domains.json
    envelope_builder = CIAFEnvelopeBuilder(binder)
    verifier = CIAFVerifier(binder)
    merkle_ledger = WORMMerkleTree()
    logger.info("[INIT] Services loaded: CIAFDomainBinder, EnvelopeBuilder, Verifier, WORMMerkleTree.")

    # 2. Provision Cryptographic Identities (Key Pairs) for Agents & Policy Gate
    logger.info("[KEYS] Provisioning Ed25519 key pairs for agents and governance gates...")
    planner_signer = Ed25519Signer(key_id="agent_planner_v3_key")
    gate_signer = Ed25519Signer(key_id="policy_gate_v1_key")
    executor_signer = Ed25519Signer(key_id="agent_executor_v1_key")
    policy_admin_signer = Ed25519Signer(key_id="policy_admin_v1_key")

    logger.info(f"  - Planner Key ID:   {planner_signer.key_id}")
    logger.info(f"  - Gate Key ID:      {gate_signer.key_id}")
    logger.info(f"  - Executor Key ID:  {executor_signer.key_id}")
    logger.info(f"  - Admin Key ID:     {policy_admin_signer.key_id}")

    # -------------------------------------------------------------------------
    # PRE-REQUISITE: Policy Version Anchor Pre-Registration
    # -------------------------------------------------------------------------
    logger.info("\n------------------------------------------------------------------")
    logger.info("  PRE-REQUISITE: Policy Version Anchor Pre-Registration")
    logger.info("------------------------------------------------------------------")
    policy_definition = {
        "policy_version_id": "pol_2026_q3_v2",
        "spending_limit_cents": 500000,  # $5,000.00 limit
        "allowed_vendors": ["vendor_acme_corp", "vendor_globex"]
    }

    # Stages 4-8: Sign and anchor policy definition
    policy_record = envelope_builder.create_evidence_record(
        payload=policy_definition,
        domain="POLICY_VERSION",  # Bound under AGEI:policy-version:ciaf-json-v1\0
        signer=policy_admin_signer,
        payload_key="policy"
    )

    policy_hash = policy_record["integrity"]["content_hash"]
    root_policy = merkle_ledger.append_leaf(policy_hash)  # Anchored in ledger
    logger.info(f"[WORM LEDGER] Policy Anchored. Merkle Root: {root_policy}")

    # -------------------------------------------------------------------------
    # PRE-REQUISITE 2: Identity Binding Anchor Pre-Registration
    # -------------------------------------------------------------------------
    logger.info("\n------------------------------------------------------------------")
    logger.info("  PRE-REQUISITE 2: Identity Binding Anchor Pre-Registration")
    logger.info("------------------------------------------------------------------")
    
    provisioned_identity = AgentIdentity(
        service_identity="planner_v3",
        delegating_principal="user_7781_finance",
        workflow_role="procurement_drafter"
    )

    identity_record = envelope_builder.create_evidence_record(
        payload=provisioned_identity.to_dict(),
        domain="IDENTITY_BINDING",  # Bound under AGEI:identity-binding:ciaf-json-v1\0
        signer=policy_admin_signer,
        payload_key="identity_binding"
    )

    identity_binding_hash = identity_record["integrity"]["content_hash"]
    root_identity = merkle_ledger.append_leaf(identity_binding_hash)
    logger.info(f"[WORM LEDGER] Identity Binding Anchored. Merkle Root: {root_identity}")

    # -------------------------------------------------------------------------
    # STEP 1: Planning Agent Generates Purchase Order
    # -------------------------------------------------------------------------
    logger.info("\n------------------------------------------------------------------")
    logger.info("  STEP 1: Planning Agent Generates Purchase Order")
    logger.info("------------------------------------------------------------------")
    
    planner_identity = AgentIdentity(
        service_identity="planner_v3",
        delegating_principal="user_7781_finance",
        workflow_role="procurement_drafter",
        session_context="session_99421_alpha"
    )
    
    order_payload = {
        "agent_identity": planner_identity.to_dict(),
        "task_id": "task_99421",
        "vendor_id": "vendor_acme_corp",
        "requested_amount_cents": 450000,
        "item_description": "Server hardware upgrade",
        "timestamp": "2026-09-20T19:23:01Z"
    }
    logger.info(f"[PLANNER] Unsigned Order Payload: {order_payload}")

    logger.info("[LCM STAGES 4-8] Canonicalizing (RFC 8785), Binding Domain ('RECEIPT'), Measuring (SHA-256), & Signing (Ed25519)...")
    step1_record = envelope_builder.create_evidence_record(
        payload=order_payload,
        domain="RECEIPT",  # Resolved to AGEI:receipt:ciaf-json-v1\0
        signer=planner_signer,
        payload_key="order"
    )
    
    hash_step_1 = step1_record["integrity"]["content_hash"]
    logger.info(f"[MEASUREMENT] Generated Content Hash (Step 1): {hash_step_1}")
    logger.info(f"[ENVELOPE] Signature (Base64Url): {step1_record['integrity']['signature']}")

    logger.info("[LCM STAGE 9] Appending Leaf 1 to WORM Merkle Ledger...")
    root_1 = merkle_ledger.append_leaf(hash_step_1)
    logger.info(f"[WORM LEDGER] Updated Merkle Root Hash: {root_1}")

    # -------------------------------------------------------------------------
    # STEP 2: Safety & Policy Gate Evaluation
    # -------------------------------------------------------------------------
    logger.info("\n------------------------------------------------------------------")
    logger.info("  STEP 2: Safety & Policy Gate Evaluates Budget & Limits")
    logger.info("------------------------------------------------------------------")

    logger.info("[GATE] Fetching and verifying WORM Identity Binding record before cross-check...")
    
    # In a real system, `identity_record` is fetched from the WORM ledger database by `identity_binding_hash`
    # Here, we pass the in-memory record to the Verifier to simulate the strict cryptographic validation.
    identity_verification = verifier.verify_evidence_record(
        evidence_record=identity_record,
        public_key_bytes=policy_admin_signer.public_key_bytes,
        domain="IDENTITY_BINDING",
        payload_key="identity_binding"
    )

    if not identity_verification["valid"]:
        logger.error("[GATE REJECTED] The Provisioned Identity Record itself failed cryptographic verification!")
        sys.exit(1)

    # Extract the verified provisioned identity
    verified_provisioned_identity = identity_record["identity_binding"]

    # Gate explicitly cross-checks self-asserted identity against the ledger
    logger.info("[GATE] Cross-checking Planner's self-asserted identity against verified WORM Identity Binding...")
    claimed_identity = order_payload["agent_identity"]
    
    # Check that static provisioned fields match
    identity_valid = (
        claimed_identity["service_identity"] == verified_provisioned_identity["service_identity"] and
        claimed_identity["delegating_principal"] == verified_provisioned_identity["delegating_principal"] and
        claimed_identity["workflow_role"] == verified_provisioned_identity["workflow_role"]
    )

    if not identity_valid:
        # Note: We deliberately use a generic reason code (IDENTITY_BINDING_MISMATCH) instead of specifying
        # which field failed. This prevents the gate from acting as an oracle for attackers to brute-force combinations.
        logger.error("[GATE DENIED] Identity Binding mismatch detected! Emitting Denial Receipt.")
        denial_payload = {
            "gate_id": "procurement_budget_gate_v1",
            "input_step_hash": hash_step_1,
            "evaluation_outcome": "DENIED",
            "reason_code": "IDENTITY_BINDING_MISMATCH",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        denial_record = envelope_builder.create_evidence_record(
            payload=denial_payload,
            domain="GATE_EVALUATION",
            signer=gate_signer,
            payload_key="gate_decision"
        )
        hash_denial = denial_record["integrity"]["content_hash"]
        root_denial = merkle_ledger.append_leaf(hash_denial)
        logger.info(f"[WORM LEDGER] Denial Receipt Anchored. Merkle Root: {root_denial}")
        sys.exit(1)

    logger.info("[GATE] Identity Binding verified. Proceeding to Budget Evaluation.")

    gate_payload = {
        "gate_id": "procurement_budget_gate_v1",
        "policy_version_id": "pol_2026_q3_v2",
        "input_step_hash": hash_step_1,  # Cryptographic causal link to Step 1
        "evaluation_outcome": "APPROVED",
        "spending_limit_cents": 500000,
        "timestamp": "2026-09-20T19:23:02Z"
    }
    logger.info(f"[GATE] Unsigned Policy Evaluation Payload: {gate_payload}")

    logger.info("[LCM STAGES 4-8] Canonicalizing, Binding Domain ('GATE_EVALUATION'), Measuring, & Signing...")
    step2_record = envelope_builder.create_evidence_record(
        payload=gate_payload,
        domain="GATE_EVALUATION",  # Resolved to AGEI:gate-evaluation:ciaf-json-v1\0
        signer=gate_signer,
        payload_key="gate_decision"
    )

    hash_step_2 = step2_record["integrity"]["content_hash"]
    logger.info(f"[MEASUREMENT] Generated Content Hash (Step 2): {hash_step_2}")

    logger.info("[LCM STAGE 9] Appending Leaf 2 to WORM Merkle Ledger...")
    root_2 = merkle_ledger.append_leaf(hash_step_2)
    logger.info(f"[WORM LEDGER] Updated Merkle Root Hash: {root_2}")

    # -------------------------------------------------------------------------
    # STEP 3: Execution Agent Pre-Execution Circuit Breaker Check
    # -------------------------------------------------------------------------
    logger.info("\n------------------------------------------------------------------")
    logger.info("  STEP 3: Execution Agent Pre-Execution Circuit Breaker")
    logger.info("------------------------------------------------------------------")

    logger.info("[CIRCUIT BREAKER] Verifying Step 2 Gate Decision before invoking live payment API...")
    
    # Execution Agent executes Stage 10 Independent Verification over Step 2 record
    gate_verification = verifier.verify_evidence_record(
        evidence_record=step2_record,
        public_key_bytes=gate_signer.public_key_bytes,
        domain="GATE_EVALUATION",
        payload_key="gate_decision"
    )

    logger.info(f"[VERIFIER] Re-computed Hash Check: {gate_verification['hash_match']}")
    logger.info(f"[VERIFIER] Ed25519 Signature Check: {gate_verification['signature_valid']}")

    # Circuit Breaker Logic
    if not gate_verification["valid"]:
        logger.error("[CIRCUIT BREAKER TRIGGERED] Gate Decision Signature or Hash Invalid!")
        sys.exit(1)

    if step2_record["gate_decision"]["evaluation_outcome"] != "APPROVED":
        logger.warning("[CIRCUIT BREAKER TRIGGERED] Gate Decision was NOT Approved!")
        sys.exit(1)

    logger.info("[PASSED] Pre-execution cryptographic verification succeeded. Gate approval confirmed.")

    # -------------------------------------------------------------------------
    # STEP 4: Execution Agent Executes Action on Live Systems
    # -------------------------------------------------------------------------
    logger.info("\n------------------------------------------------------------------")
    logger.info("  STEP 4: Executing Action on Live Procurement API")
    logger.info("------------------------------------------------------------------")

    executor_identity = AgentIdentity(
        service_identity="executor_v1",
        delegating_principal="system_procurement_orchestrator",
        workflow_role="payment_executor",
        session_context="session_99421_alpha"
    )

    execution_payload = {
        "agent_identity": executor_identity.to_dict(),
        "action": "call_payment_api",
        "target_resource": "api.procurement.internal/v1/payout",
        "approval_receipt_hash": hash_step_2,  # Causal link to Step 2 approval
        "payment_details": {
            "vendor_id": "vendor_acme_corp",
            "amount_cents": 450000
        },
        "timestamp": "2026-09-20T19:23:03Z"
    }
    logger.info(f"[EXECUTOR] Payload submitted to API: {execution_payload}")

    step3_record = envelope_builder.create_evidence_record(
        payload=execution_payload,
        domain="RECEIPT",
        signer=executor_signer,
        payload_key="execution_receipt"
    )

    hash_step_3 = step3_record["integrity"]["content_hash"]
    merkle_root = merkle_ledger.append_leaf(hash_step_3)

    logger.info("[SUCCESS] Action executed on live API.")
    logger.info(f"[MEASUREMENT] Generated Content Hash (Step 3): {hash_step_3}")
    logger.info(f"[WORM LEDGER] Final Merkle Ledger Root Hash: {merkle_root}")

    # -------------------------------------------------------------------------
    # DEMO: SIMULATING SILENT FAILURE & TAMPER DETECTION
    # -------------------------------------------------------------------------
    logger.info("\n------------------------------------------------------------------")
    logger.info("  DEMO: Simulating Silent Failure / Post-Execution Tamper Check")
    logger.info("------------------------------------------------------------------")
    
    logger.info("[TAMPER SIMULATION] Modifying payment amount from $4,500.00 to $45,000.00 in Step 3 receipt after signing...")
    tampered_record = dict(step3_record)
    tampered_record["execution_receipt"]["payment_details"]["amount_cents"] = 4500000

    logger.info("[AUDITOR] Running independent verification over tampered record...")
    tamper_check = verifier.verify_evidence_record(
        evidence_record=tampered_record,
        public_key_bytes=executor_signer.public_key_bytes,
        domain="RECEIPT",
        payload_key="execution_receipt"
    )

    logger.info(f"[AUDITOR RESULT] Valid Record:   {tamper_check['valid']}")
    logger.info(f"[AUDITOR RESULT] Hash Match:     {tamper_check['hash_match']}")
    logger.info(f"[AUDITOR RESULT] Error Message:  '{tamper_check['error']}'")
    
    assert tamper_check["valid"] is False
    logger.info("[SUCCESS] Tamper attempt caught instantly by hash recalculation!")
    logger.info("==================================================================")
    logger.info("  DEMO COMPLETED SUCCESSFULLY")
    logger.info("==================================================================")


if __name__ == "__main__":
    run_agentic_workflow_demo()
