# langgraph-app/src/services/hypothesis_pre_filter.py

from typing import Dict, Any


class HypothesisPreFilter:
    """
    Cheap structural gate before LLM validation.
    Prevents obvious false positives from reaching the validator.
    """

    SECURITY_KEYWORDS = {
        "auth", "login", "logged", "token", "session", "role", "admin",
        "password", "privilege", "access", "permission", "authorize", "authentication"
    }

    def should_validate(self, hypothesis: Dict[str, Any], code_context: str) -> Dict[str, Any]:
        hypothesis_type = hypothesis.get("hypothesis_type")
        lowered = code_context.lower()

        if hypothesis_type == "client_side_security_enforcement":
            if not any(keyword in lowered for keyword in self.SECURITY_KEYWORDS):
                return {
                    "should_validate": False,
                    "reason": "No security-relevant indicators found in local code context for client-side security enforcement hypothesis."
                }

        return {
            "should_validate": True,
            "reason": "Passed pre-filter."
        }