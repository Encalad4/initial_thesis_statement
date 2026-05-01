#langgraph-app/src/services/hypothesis_builder.py

from typing import Dict, Any, List


class HypothesisBuilder:
    """
    Converts raw scanner signals into neutral security hypotheses.
    These are not final findings and not final CWE decisions.
    """

    def build(self, raw_matches: List[Dict[str, Any]]) -> Dict[str, Any]:
        hypotheses: List[Dict[str, Any]] = []

        for match in raw_matches:
            pattern_name = match.get("pattern_name")
            file_path = match.get("file_path")
            line_number = match.get("line_number")
            line = match.get("line", "")
            severity_hint = match.get("severity_hint", "medium")

            hypothesis = self._map_pattern_to_hypothesis(
                pattern_name=pattern_name,
                file_path=file_path,
                line_number=line_number,
                line=line,
                severity_hint=severity_hint
            )

            if hypothesis:
                hypotheses.append(hypothesis)

        return {
            "success": True,
            "data": {
                "hypotheses": hypotheses
            }
        }

    def _map_pattern_to_hypothesis(
        self,
        pattern_name: str,
        file_path: str,
        line_number: int,
        line: str,
        severity_hint: str
    ) -> Dict[str, Any] | None:

        mappings = {
            "hardcoded_secret": {
                "hypothesis_type": "hardcoded_secret",
                "candidate_cwes": ["CWE-798", "CWE-259"],
                "reasoning": "A secret-like value appears to be embedded directly in source code."
            },
            "client_side_auth_storage": {
                "hypothesis_type": "client_side_security_enforcement",
                "candidate_cwes": ["CWE-602"],
                "reasoning": "Security-relevant state appears to be stored or enforced on the client side."
            },
            "dom_xss_sink": {
                "hypothesis_type": "dom_xss_sink",
                "candidate_cwes": ["CWE-79"],
                "reasoning": "A dangerous DOM sink appears in the code and may be exploitable if attacker-controlled input reaches it."
            },
            "sql_query_concatenation": {
                "hypothesis_type": "sql_injection_signal",
                "candidate_cwes": ["CWE-89"],
                "reasoning": "A database query appears to be dynamically constructed or executed in a way that may allow untrusted input to alter SQL structure."
            },
            "command_execution": {
                "hypothesis_type": "command_injection_signal",
                "candidate_cwes": ["CWE-78"],
                "reasoning": "A system command execution sink appears and may become dangerous if command content or arguments are influenced by untrusted input."
            },
            "unsafe_deserialization": {
                "hypothesis_type": "unsafe_deserialization_signal",
                "candidate_cwes": ["CWE-502"],
                "reasoning": "A deserialization API associated with unsafe handling of untrusted input appears in the code."
            },
            "path_traversal_signal": {
                "hypothesis_type": "path_traversal_signal",
                "candidate_cwes": ["CWE-22"],
                "reasoning": "A filesystem path sink appears and may use externally influenced path components."
            },
            "dynamic_code_execution": {
                "hypothesis_type": "dynamic_code_execution_signal",
                "candidate_cwes": ["CWE-94"],
                "reasoning": "Dynamic code execution appears in the code and may be unsafe if influenced by untrusted input."
            }
        }

        base = mappings.get(pattern_name)
        if not base:
            return None

        return {
            "hypothesis_type": base["hypothesis_type"],
            "candidate_cwes": base["candidate_cwes"],
            "file_path": file_path,
            "line_start": line_number,
            "line_end": line_number,
            "evidence": line,
            "severity_hint": severity_hint,
            "reasoning": base["reasoning"],
            "status": "suspected"
        }