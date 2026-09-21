from typing import Any, Dict, List, Union
import jcs  # RFC 8785 compliant canonicalization library


class CIAFCanonicalization:
    """
    CIAF Concept: RFC 8785 JSON Canonicalization Scheme (ciaf-json-v1 / agei-json-v1)
    
    Provides deterministic RFC 8785 serialization along with Stage 2/3 safe-integer 
    validation to ensure cryptographic reproducibility across platforms.
    
    Why is it needed?
        • Cryptographic Variance vs. Semantic Equivalence: Standard JSON tools serialize data differently based on language, platform, or database engine (e.g., key order, extra spaces, integer notation).
        • Hash & Signature Consistency: Cryptographic hashes operate on exact bytes. Without canonicalization, semantically identical payloads generate different digests and invalidate digital signatures.
        • Safe-Integer Protection: Numbers outside IEEE 754 double precision (±2^53 - 1) can silently corrupt during JSON serialization. Pre-validation ensures large numbers are string-encoded to preserve audit integrity.
                
    How is it used in CIAF/LCM?
        • On-Demand Processing : Canonical bytes are computed at write and verify times rather than persisted in storage, minimizing storage costs.
        • Integrity Binding: Precedes Domain Separation and SHA-256 content hashing to generate verifiable content pointers across independent auditors and platforms.
    """
    
    # IEEE 754 safe integer limits: [-(2^53 - 1), 2^53 - 1]
    JS_MAX_SAFE_INTEGER: int = 9_007_199_254_740_991
    JS_MIN_SAFE_INTEGER: int = -9_007_199_254_740_991

    @classmethod
    def _prepare_payload(cls, data: Any, path: str = "$") -> Any:
        """
        Recursively prepares the payload for canonicalization:
        1. Validates IEEE 754 safe integer limits to prevent silent corruption.
        2. Normalizes CRLF and CR line endings to LF (\\n) in strings (Paper Section 8.5).
        
        Returns the prepared data structure.
        """
        if isinstance(data, bool):
            return data
        
        if isinstance(data, int):
            if data > cls.JS_MAX_SAFE_INTEGER or data < cls.JS_MIN_SAFE_INTEGER:
                raise ValueError(
                    f"Unsafe integer detected at '{path}': {data}. "
                    f"Numbers outside [-(2^53 - 1), 2^53 - 1] MUST be formatted as "
                    f"strings prior to canonicalization to prevent silent corruption."
                )
            return data
        elif isinstance(data, float):
            if data != data or data in (float('inf'), float('-inf')):
                raise ValueError(f"Invalid float value (NaN/Infinity) at '{path}': {data}")
            return data
        elif isinstance(data, str):
            # Normalize CRLF and CR to LF
            return data.replace('\r\n', '\n').replace('\r', '\n')
        elif isinstance(data, dict):
            return {key: cls._prepare_payload(value, path=f"{path}.{key}") for key, value in data.items()}
        elif isinstance(data, list):
            return [cls._prepare_payload(item, path=f"{path}[{index}]") for index, item in enumerate(data)]
        
        return data

    @classmethod
    def canonicalize_json(cls, data: Union[Dict[str, Any], List[Any]]) -> bytes:
        """
        Transforms a data object into RFC 8785 (JCS) compliant canonical JSON bytes.
        
        Args:
            data: The dictionary or list to canonicalize.
            
        Returns:
            Canonical UTF-8 encoded bytes.
        """
        prepared_data = cls._prepare_payload(data)
        return jcs.canonicalize(prepared_data)

    @classmethod
    def canonicalize_json_str(cls, data: Union[Dict[str, Any], List[Any]]) -> str:
        """Convenience wrapper returning canonicalized output as a UTF-8 string."""
        return cls.canonicalize_json(data).decode('utf-8')