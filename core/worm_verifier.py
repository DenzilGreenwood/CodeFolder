import hashlib
from typing import Any, Dict, List, Optional, Tuple, Union

# Import previous modules
from .canonicalization import CIAFCanonicalization
from .domain_binder import CIAFDomainBinder
from .signer_envelope import Ed25519Signer


class WORMMerkleTree:
    """
    Stage 9 (Preserve): Write-Once-Read-Many (WORM) Merkle Ledger.
    
    Aggregates evidence content hashes into a Merkle tree, enabling amortized
    batch verification and inclusion proofs (Paper Section 4.3 & 9.3).

    Hierarchical Merkle Trees (Tree of Trees)
    -----------------------------------------
    Because the output of a Merkle Tree (`get_root()`) is a standard SHA-256 hash,
    multiple WORMMerkleTree instances can be composed hierarchically. This allows
    an entire AI lifecycle to be cryptographically bound to a single master root.
    
    For example, each AI event or system component can have its own tree:
      - ingestion_tree.get_root() -> hash_A
      - training_tree.get_root()  -> hash_B
      - inference_tree.get_root() -> hash_C
      
    These sub-roots can then act as leaves in a master Model Version tree:
      master_tree = WORMMerkleTree()
      master_tree.append_leaf(hash_A)
      master_tree.append_leaf(hash_B)
      master_tree.append_leaf(hash_C)
      master_root = master_tree.get_root()
      
    If any single document, training parameter, or inference log is tampered with,
    its sub-tree root will change, instantly invalidating the master_root.
    """

    def __init__(self)-> None:
        self.leaves: List[str] = []  # List of content_hashes (hex strings)
        self.leaf_set: set = set()

    def append_leaf(self, content_hash: str) -> str:
        """
        Appends a content hash to the WORM tree.
        
        Enforces WORM invariant: duplicate leaves or modifications raise an error.
        """
        if content_hash in self.leaf_set:
            raise ValueError(f"WORM Violation: Content hash {content_hash} already exists in ledger.")

        self.leaves.append(content_hash)
        self.leaf_set.add(content_hash)
        return self.get_root()

    def get_root(self) -> str:
        """Computes current Merkle root using deterministic SHA-256 byte concatenation."""
        if not self.leaves:
            return hashlib.sha256(b"empty_tree").hexdigest()

        if len(self.leaves) == 1:
            return self.leaves[0]

        current_level = self.leaves[:]
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                
                # Pairwise concatenation of binary digests
                parent_bytes = bytes.fromhex(left) + bytes.fromhex(right)
                parent_hash = hashlib.sha256(parent_bytes).hexdigest()
                next_level.append(parent_hash)

            current_level = next_level

        return current_level[0]

    def get_inclusion_proof(self, content_hash: str) -> List[Tuple[str, str]]:
        """
        Generates a Merkle inclusion proof path for a leaf hash.
        
        Returns:
            List of (sibling_hash, position) tuples where position is 'left' or 'right'.
        """
        if content_hash not in self.leaf_set:
            raise ValueError(f"Hash {content_hash} not found in Merkle ledger.")

        idx = self.leaves.index(content_hash)
        proof = []
        current_level = self.leaves[:]

        while len(current_level) > 1:
            if idx % 2 == 0:
                sibling_idx = idx + 1 if idx + 1 < len(current_level) else idx
                proof.append((current_level[sibling_idx], "right"))
            else:
                proof.append((current_level[idx - 1], "left"))

            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                parent_hash = hashlib.sha256(bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()
                next_level.append(parent_hash)

            current_level = next_level
            idx //= 2

        return proof


class CIAFVerifier:
    """
    Stage 10 (Verify): Independent Verification Procedure.
    
    Executes the exact 8-step verification pipeline defined in Paper Section 7.
    Reconstructs protected bytes on-demand to verify signature and hash integrity.
    """

    def __init__(self, binder: Optional[CIAFDomainBinder] = None) -> None:
        self.binder = binder or CIAFDomainBinder()

    def verify_evidence_record(
        self,
        evidence_record: Dict[str, Any],
        public_key_bytes: bytes,
        domain: str,
        payload_key: str = "receipt"
    ) -> Dict[str, Any]:
        """
        Verifies a portable evidence record according to Paper Section 7.
        
        Args:
            evidence_record: The complete evidence record dictionary
            public_key_bytes: Raw Ed25519 public key bytes
            domain: Expected domain string or key
            payload_key: Key wrapping the raw payload (e.g., 'receipt')
            
        Returns:
            Dictionary containing verification status and detailed checks.
        """
        results: Dict[str, Any] = {
            "valid": False,
            "hash_match": False,
            "signature_valid": False,
            "error": None
        }

        try:
            # Step 1: Parse envelope
            if "integrity" not in evidence_record or payload_key not in evidence_record:
                raise ValueError(f"Missing 'integrity' or '{payload_key}' field in record.")

            integrity = evidence_record["integrity"]
            payload = evidence_record[payload_key]

            # Step 2: Validate metadata constants
            if integrity.get("canonicalization_version") != "ciaf-json-v1":
                raise ValueError("Unsupported canonicalization version.")
            if integrity.get("hash_algorithm") != "SHA-256":
                raise ValueError("Unsupported hash algorithm.")
            if integrity.get("signature_algorithm") != "Ed25519":
                raise ValueError("Unsupported signature algorithm.")

            # Step 3, 4, 5, 6: Re-canonicalize, bind domain, and recompute hash
            protected_bytes, recomputed_hash = self.binder.bind_and_measure(payload, domain)
            
            declared_hash = integrity.get("content_hash")
            if recomputed_hash != declared_hash:
                results["error"] = f"Hash Mismatch! Recomputed: {recomputed_hash}, Declared: {declared_hash}"
                return results
            
            results["hash_match"] = True

            # Step 7 & 8: Verify Ed25519 signature over protected bytes
            signature = integrity.get("signature", "")
            sig_valid = Ed25519Signer.verify(protected_bytes, signature, public_key_bytes)

            if not sig_valid:
                results["error"] = "Invalid Ed25519 signature."
                return results

            results["signature_valid"] = True
            results["valid"] = True
            return results

        except Exception as e:
            results["error"] = str(e)
            return results