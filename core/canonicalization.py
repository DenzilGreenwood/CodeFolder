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
    def _validate_safe_numbers(cls, data: Any, path: str = "$") -> None:
        """
        Recursively validates that all integer values fall within the IEEE 754 
        safe integer range [-(2^53 - 1), 2^53 - 1].
        """
        if isinstance(data, bool):
            return  # bool is a subclass of int in Python
        
        if isinstance(data, int):
            if data > cls.JS_MAX_SAFE_INTEGER or data < cls.JS_MIN_SAFE_INTEGER:
                raise ValueError(
                    f"Unsafe integer detected at '{path}': {data}. "
                    f"Numbers outside [-(2^53 - 1), 2^53 - 1] MUST be formatted as "
                    f"strings prior to canonicalization to prevent silent corruption."
                )
        elif isinstance(data, float):
            if data != data or data in (float('inf'), float('-inf')):
                raise ValueError(f"Invalid float value (NaN/Infinity) at '{path}': {data}")
        elif isinstance(data, dict):
            for key, value in data.items():
                cls._validate_safe_numbers(value, path=f"{path}.{key}")
        elif isinstance(data, list):
            for index, item in enumerate(data):
                cls._validate_safe_numbers(item, path=f"{path}[{index}]")

    @classmethod
    def canonicalize_json(cls, data: Union[Dict[str, Any], List[Any]]) -> bytes:
        """
        Transforms a data object into RFC 8785 (JCS) compliant canonical JSON bytes.
        
        Args:
            data: The dictionary or list to canonicalize.
            
        Returns:
            Canonical UTF-8 encoded bytes.
        """
        cls._validate_safe_numbers(data)
        return jcs.canonicalize(data)

    @classmethod
    def canonicalize_json_str(cls, data: Union[Dict[str, Any], List[Any]]) -> str:
        """Convenience wrapper returning canonicalized output as a UTF-8 string."""
        return cls.canonicalize_json(data).decode('utf-8')