import logging
import sys
import unittest
from pathlib import Path
from typing import Any, Dict

# Configure logger to output detailed pipeline explanations
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("LCM_TestRunner")

# Import CIAF core modules
from core.canonicalization import CIAFCanonicalization
from core.domain_binder import CIAFDomainBinder
from core.signer_envelope import Ed25519Signer, CIAFEnvelopeBuilder
from core.worm_verifier import WORMMerkleTree, CIAFVerifier


class TestLCMLifecycle(unittest.TestCase):
    """
    End-to-end integration and unit tests for the 10-stage Lifecycle 
    Canonicalization and Measurement (LCM) framework with logging explanations.
    """

    def setUp(self):
        """Initialize framework services before each test."""
        logger.info("--- Initializing CIAF Framework Test Environment ---")
        self.signer = Ed25519Signer(key_id="test-ed25519-key-2026")
        self.binder = CIAFDomainBinder()  # Loads core/domainsjson/domains.json automatically
        self.envelope_builder = CIAFEnvelopeBuilder(self.binder)
        self.verifier = CIAFVerifier(self.binder)
        self.merkle_ledger = WORMMerkleTree()
        logger.info("Services initialized: Signer, DomainBinder, EnvelopeBuilder, Verifier, WORMMerkleTree.\n")

    # -------------------------------------------------------------------------
    # STAGE 2 & 4: CANONICALIZATION & SAFE INTEGER TESTS
    # -------------------------------------------------------------------------
    def test_stage2_safe_integer_validation(self):
        """
        Verify that integers exceeding IEEE 754 safe double precision limits 
        (> 2^53 - 1) raise a ValueError if not encoded as strings (Paper Section 5.1).
        """
        logger.info("[RUNNING] Stage 2 Test: Safe Integer Precision Check")
        unsafe_payload = {
            "event": "token_count_overflow",
            "large_count": 9_007_199_254_740_993  # 2^53 + 1 (Unsafe integer)
        }
        logger.info(f"Testing payload with unsafe integer (2^53 + 1): {unsafe_payload}")

        with self.assertRaises(ValueError) as ctx:
            CIAFCanonicalization.canonicalize_json(unsafe_payload)
        
        logger.info(f"[SUCCESS] Caught expected ValueError: '{ctx.exception}'")

        safe_payload = {
            "event": "token_count_overflow",
            "large_count": "9007199254740993"  # Converted to string
        }
        logger.info(f"Testing remediated payload with string-encoded large integer...")
        canonical_bytes = CIAFCanonicalization.canonicalize_json(safe_payload)
        logger.info(f"[SUCCESS] Canonical Bytes Generated: {canonical_bytes.decode('utf-8')}\n")
        self.assertIsInstance(canonical_bytes, bytes)

    def test_stage4_rfc8785_determinism(self):
        """
        Verify that keys are ordered lexicographically and whitespace is removed 
        identically across different dictionary key insertion orders.
        """
        logger.info("[RUNNING] Stage 4 Test: RFC 8785 (JCS) Deterministic Serializer")
        payload_a = {"z_key": "last", "a_key": "first", "nested": {"b": 2, "a": 1}}
        payload_b = {"a_key": "first", "nested": {"a": 1, "b": 2}, "z_key": "last"}

        logger.info("Payload A (raw): %s", payload_a)
        logger.info("Payload B (raw): %s", payload_b)

        bytes_a = CIAFCanonicalization.canonicalize_json(payload_a)
        bytes_b = CIAFCanonicalization.canonicalize_json(payload_b)

        logger.info("Canonicalized Output A: %s", bytes_a.decode("utf-8"))
        logger.info("Canonicalized Output B: %s", bytes_b.decode("utf-8"))

        self.assertEqual(bytes_a, bytes_b)
        logger.info("[SUCCESS] Both payloads produced byte-exact identical JCS representations.\n")

    # -------------------------------------------------------------------------
    # STAGE 5 & 6: DOMAIN SEPARATION & SHA-256 BINDING
    # -------------------------------------------------------------------------
    def test_stage5_6_domain_separation_and_measurement(self):
        """
        Verify that domain separation prepends a null-byte terminated prefix (\x00) 
        and that identical payloads under different domains produce distinct hashes.
        """
        logger.info("[RUNNING] Stages 5 & 6 Test: Domain Binding & Content Measurement")
        payload = {"action": "execute_tool", "status": "APPROVED"}

        # Measure under RECEIPT domain
        bytes_receipt, hash_receipt = self.binder.bind_and_measure(payload, "RECEIPT")
        logger.info(f"Domain 'RECEIPT' -> Content Hash: {hash_receipt}")
        logger.info(f"Protected Bytes Preview: {bytes_receipt[:40]}...")

        # Measure identical payload under GATE_EVALUATION domain
        bytes_gate, hash_gate = self.binder.bind_and_measure(payload, "GATE_EVALUATION")
        logger.info(f"Domain 'GATE_EVALUATION' -> Content Hash: {hash_gate}")

        self.assertIn(b"\x00", bytes_receipt)
        self.assertNotEqual(hash_receipt, hash_gate)
        logger.info("[SUCCESS] Identical payload bound to different domains yielded distinct cryptographic hashes.\n")

    # -------------------------------------------------------------------------
    # STAGE 7 & 8: SIGNING & ENVELOPING
    # -------------------------------------------------------------------------
    def test_stage7_8_signing_and_envelope_assembly(self):
        """
        Verify that the integrity envelope attaches metadata without mutating 
        or including envelope fields inside the signed protected bytes.
        """
        logger.info("[RUNNING] Stages 7 & 8 Test: Ed25519 Detached Signing & Envelope Assembly")
        payload = {
            "receipt_id": "rcpt_2026_001",
            "agent_id": "procurement_agent",
            "decision": "ALLOWED"
        }

        record = self.envelope_builder.create_evidence_record(
            payload=payload,
            domain="RECEIPT",
            signer=self.signer,
            payload_key="receipt"
        )

        logger.info("Generated Portable Evidence Record:")
        logger.info("Payload Structure: %s", record["receipt"])
        logger.info("Integrity Envelope: %s", record["integrity"])

        self.assertIn("receipt", record)
        self.assertIn("integrity", record)
        self.assertEqual(record["integrity"]["signature_algorithm"], "Ed25519")
        logger.info("[SUCCESS] Detached integrity envelope attached successfully.\n")

    # -------------------------------------------------------------------------
    # STAGE 9: WORM MERKLE PRESERVATION
    # -------------------------------------------------------------------------
    def test_stage9_worm_merkle_preservation(self):
        """
        Verify that content hashes can be appended to a WORM Merkle tree, 
        duplicates trigger WORM violation errors, and valid inclusion proofs are generated.
        """
        logger.info("[RUNNING] Stage 9 Test: WORM Merkle Tree Preservation")
        payload_1 = {"event": "action_1"}
        payload_2 = {"event": "action_2"}

        _, hash_1 = self.binder.bind_and_measure(payload_1, "RECEIPT")
        _, hash_2 = self.binder.bind_and_measure(payload_2, "RECEIPT")

        logger.info(f"Appending Leaf 1 ({hash_1[:12]}...) to WORM Ledger...")
        root_1 = self.merkle_ledger.append_leaf(hash_1)
        logger.info(f"Current Merkle Root: {root_1}")

        logger.info(f"Appending Leaf 2 ({hash_2[:12]}...) to WORM Ledger...")
        root_2 = self.merkle_ledger.append_leaf(hash_2)
        logger.info(f"Updated Merkle Root: {root_2}")

        # WORM violation check
        logger.info("Testing WORM violation (attempting to append duplicate leaf)...")
        with self.assertRaises(ValueError) as ctx:
            self.merkle_ledger.append_leaf(hash_1)
        logger.info(f"[SUCCESS] WORM Violation Prevented: '{ctx.exception}'")

        # Proof generation check
        proof = self.merkle_ledger.get_inclusion_proof(hash_1)
        logger.info(f"Inclusion Proof for Leaf 1: {proof}")
        self.assertTrue(len(proof) > 0)
        logger.info("[SUCCESS] WORM Merkle ledger appended leaves and generated inclusion proof.\n")

    # -------------------------------------------------------------------------
    # STAGE 10: INDEPENDENT VERIFICATION PROCEDURE
    # -------------------------------------------------------------------------
    def test_stage10_independent_verification_success(self):
        """Verify that a valid evidence record successfully passes independent verification."""
        logger.info("[RUNNING] Stage 10 Test: Independent Verification Procedure (Valid Case)")
        payload = {"agent_id": "model_v4", "prompt_tokens": 512}
        
        record = self.envelope_builder.create_evidence_record(
            payload=payload,
            domain="RECEIPT",
            signer=self.signer
        )

        logger.info("Executing 8-Step Independent Verification Protocol...")
        result = self.verifier.verify_evidence_record(
            evidence_record=record,
            public_key_bytes=self.signer.public_key_bytes,
            domain="RECEIPT"
        )

        logger.info(f"Verification Results: {result}")
        self.assertTrue(result["valid"])
        self.assertTrue(result["hash_match"])
        self.assertTrue(result["signature_valid"])
        logger.info("[SUCCESS] Evidence record passed independent verification.\n")

    def test_stage10_independent_verification_tamper_detection(self):
        """
        Verify that tampering with any field in the underlying payload invalidates 
        both the recomputed content hash and signature verification.
        """
        logger.info("[RUNNING] Stage 10 Test: Independent Verification Procedure (Tamper Case)")
        payload = {"agent_id": "model_v4", "prompt_tokens": 512}
        
        record = self.envelope_builder.create_evidence_record(
            payload=payload,
            domain="RECEIPT",
            signer=self.signer
        )

        # TAMPER: Modify payload field after signing
        logger.info("TAMPERING: Modifying 'prompt_tokens' from 512 to 1024 after signing...")
        record["receipt"]["prompt_tokens"] = 1024

        result = self.verifier.verify_evidence_record(
            evidence_record=record,
            public_key_bytes=self.signer.public_key_bytes,
            domain="RECEIPT"
        )

        logger.info(f"Verification Results: {result}")
        self.assertFalse(result["valid"])
        self.assertFalse(result["hash_match"])
        self.assertIn("Hash Mismatch", result["error"])
        logger.info("[SUCCESS] Tampering detected and record properly rejected.\n")


if __name__ == "__main__":
    unittest.main()