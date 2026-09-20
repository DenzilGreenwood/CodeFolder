import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# Import canonicalization class
from .canonicalization import CIAFCanonicalization

# The domains for the ciaf 
DEFAULT_DOMAINS_PATH = Path("core") / "domainsjson" / "domains.json"


class CIAFDomainBinder:
    """
    Handles Stage 5 (Binding) and Stage 6 (Measurement) of the LCM flow.
    
    Loads domain taxonomy dynamically from an external configuration file to accommodate
    the evolving scope of AI events, while enforcing RFC 8785 canonicalization and
    null-byte terminated domain prefixing (Paper Section 5.2).
    """

    def __init__(self, config_path: Optional[Union[str, Path]] = None) -> None:
        self._domains: Dict[str, str] = {}
        self.version: str = "1.0.0"
        
        # Use default path 'core/domainsjson/domains.json' if none provided
        target_path = Path(config_path) if config_path else DEFAULT_DOMAINS_PATH
        self.load_domains(target_path)

    def load_domains(self, config_path: Union[str, Path]) -> None:
        """
        Loads domain taxonomy from a JSON configuration file.
        
        Args:
            config_path: Path to the JSON configuration file.
        """
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Domain registry configuration file not found at: {path.resolve()}")

        with open(path, "r", encoding="utf-8") as f:
            config = json.load(f)

        self.version = config.get("version", "1.0.0")
        loaded_domains = config.get("domains", {})

        for key, value in loaded_domains.items():
            self.register_domain(key, value)

    def register_domain(self, domain_key: str, domain_string: str) -> None:
        """
        Dynamically registers a new domain mapping at runtime.
        
        Args:
            domain_key: Short key identifier (e.g., 'AGENT_TOOL_CALL')
            domain_string: Full domain separator (e.g., 'AGEI:agent-tool-call:ciaf-json-v1')
        """
        if not domain_string or not isinstance(domain_string, str):
            raise ValueError(f"Invalid domain separator string for key '{domain_key}'")

        self._domains[domain_key.upper()] = domain_string

    def get_domain_prefix(self, domain_key_or_str: str) -> str:
        """Resolves a domain key or raw string to its domain separator string."""
        upper_key = domain_key_or_str.upper()
        if upper_key in self._domains:
            return self._domains[upper_key]
        
        # Fallback to direct string if given an unregistered explicit separator
        return domain_key_or_str

    def bind_and_measure(
        self, 
        payload: Union[Dict[str, Any], List[Any]], 
        domain: str
    ) -> Tuple[bytes, str]:
        """
        Canonicalizes payload, binds domain separator with null-byte terminator,
        and computes SHA-256 content hash (Paper Section 5.2 & 5.3)[cite: 1].
        
        Args:
            payload: Unsigned AI lifecycle event object (dict/list)
            domain: Domain key (e.g., 'RECEIPT') or explicit domain separator string
            
        Returns:
            Tuple containing:
            - protected_bytes (bytes): UTF8(domain_prefix) + b'\\x00' + canonical_bytes[cite: 1]
            - content_hash (str): Lowercase hex-encoded SHA-256 digest[cite: 1]
        """
        # Stage 4: Canonicalize to RFC 8785 bytes[cite: 1]
        canonical_bytes = CIAFCanonicalization.canonicalize_json(payload)
        
        # Stage 5: Resolve Domain & Apply Domain Separation[cite: 1]
        domain_str = self.get_domain_prefix(domain)
        
        # Paper Requirement: Prefix MUST terminate with a single null byte (\x00)[cite: 1]
        domain_prefix = f"{domain_str}\x00".encode('utf-8')
        protected_bytes = domain_prefix + canonical_bytes
        
        # Stage 6: Measurement (SHA-256 Content Hash)[cite: 1]
        content_hash = hashlib.sha256(protected_bytes).hexdigest()
        
        return protected_bytes, content_hash