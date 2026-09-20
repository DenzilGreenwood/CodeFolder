import base64
from typing import Any, Dict, List, Optional, Union
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Import domain binder
from .domain_binder import CIAFDomainBinder


class Ed25519Signer:
    """
    Handles Ed25519 cryptographic key management, signing, and verification
    conforming to RFC 8032 and paper Section 5.3 specifications.
    """

    def __init__(self, key_id: str, private_key: Optional[ed25519.Ed25519PrivateKey] = None) -> None:
        self.key_id = key_id
        self._private_key = private_key or ed25519.Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()

    @property
    def public_key_bytes(self) -> bytes:
        """Returns raw public key bytes."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def sign(self, protected_bytes: bytes) -> str:
        """
        Signs protected_bytes using Ed25519 and returns unpadded base64url string.
        
        Args:
            protected_bytes: UTF8(domain_separator) + \x00 + UTF8(JCS(payload))
            
        Returns:
            Base64url-encoded Ed25519 signature (86 characters, no padding)
        """
        raw_signature = self._private_key.sign(protected_bytes)
        # Paper Section 5.4 requirement: Base64url-encoded Ed25519 signature without padding
        return base64.urlsafe_b64encode(raw_signature).rstrip(b'=').decode('utf-8')

    @staticmethod
    def verify(protected_bytes: bytes, signature_b64url: str, public_key_bytes: bytes) -> bool:
        """
        Verifies an Ed25519 signature over protected_bytes.
        
        Returns:
            True if signature is valid, False otherwise.
        """
        try:
            # Restore base64url padding if missing
            padded_sig = signature_b64url + '=' * (-len(signature_b64url) % 4)
            raw_signature = base64.urlsafe_b64decode(padded_sig.encode('utf-8'))
            
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(raw_signature, protected_bytes)
            return True
        except Exception:
            return False


class CIAFEnvelopeBuilder:
    """
    Handles Stage 7 (Sign) and Stage 8 (Envelope) of the LCM flow.
    
    Attaches the integrity envelope to payload without mutating or including 
    envelope metadata in the signed protected_bytes (Paper Section 5.4).
    """

    def __init__(self, binder: Optional[CIAFDomainBinder] = None) -> None:
        self.binder = binder or CIAFDomainBinder()

    def create_evidence_record(
        self,
        payload: Union[Dict[str, Any], List[Any]],
        domain: str,
        signer: Ed25519Signer,
        payload_key: str = "receipt"
    ) -> Dict[str, Any]:
        """
        Constructs a complete portable evidence record with a detached integrity envelope.
        
        Args:
            payload: Unsigned semantic payload (dict/list)
            domain: Registered domain key or explicit separator string
            signer: Ed25519Signer instance
            payload_key: Root object wrapper key (e.g., 'receipt', 'policy', 'event')
            
        Returns:
            Portable Evidence Record dictionary containing payload and integrity envelope
        """
        # Stage 4-6: Canonicalize, Bind Domain, and Measure
        protected_bytes, content_hash = self.binder.bind_and_measure(payload, domain)
        
        # Stage 7: Sign protected_bytes using Ed25519
        signature = signer.sign(protected_bytes)
        
        # Stage 8: Envelope Assembly (Paper Section 5.4 Specification)
        # Note: Envelope metadata is excluded from the signed protected_bytes
        evidence_record = {
            payload_key: payload,
            "integrity": {
                "canonicalization_version": "ciaf-json-v1",
                "hash_algorithm": "SHA-256",
                "content_hash": content_hash,
                "signature_algorithm": "Ed25519",
                "key_id": signer.key_id,
                "signature": signature
            }
        }
        
        return evidence_record