from dataclasses import dataclass, asdict
from typing import Any, Dict

@dataclass
class AgentIdentity:
    """
    Formal representation of the Identity Plane (Governance Planes for Agentic AI, §3).
    Binds the service identity to its delegating principal, workflow role, and session context.
    """
    service_identity: str
    delegating_principal: str
    workflow_role: str
    session_context: str | None = None

    def to_dict(self) -> Dict[str, Any]:
        """Returns dictionary representation for JSON canonicalization."""
        return asdict(self)
