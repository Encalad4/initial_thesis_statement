# langgraph-app/src/services/finding_normalizer.py

from typing import Dict, Any, List


class FindingNormalizer:
    def normalize(self, raw_matches: List[Dict[str, Any]]) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []

        for match in raw_matches:
            pattern = match.get("pattern_name")
            file_path = match.get("file_path")
            line_number = match.get("line_number")
            line = match.get("line", "")
            severity_hint = match.get("severity_hint", "medium")

            normalized = self._normalize_match(
                pattern=pattern,
                file_path=file_path,
                line_number=line_number,
                line=line,
                severity_hint=severity_hint
            )

            if normalized:
                findings.append(normalized)

        return {
            "success": True,
            "data": {
                "findings": findings
            }
        }

    def _normalize_match(
        self,
        pattern: str,
        file_path: str,
        line_number: int,
        line: str,
        severity_hint: str
    ) -> Dict[str, Any] | None:

        mapping = {
            "hardcoded_secret": {
                "title": "Potential hardcoded secret",
                "vulnerability_type": "Hardcoded Credential",
                "cwe_id": "CWE-798",
                "description": "A credential or secret appears to be hardcoded in source code.",
                "semantic_query": "Hardcoded credential or secret embedded in application source code",
                "mitigation": "Remove hardcoded secrets from source code and load them from secure server-side configuration or a secrets manager.",
                "confidence": 0.85,
                "status": "suspected"
            },
            "client_side_auth_storage": {
                "title": "Potential client-side trust or access-control signal",
                "vulnerability_type": "Client-Side Enforcement of Security",
                "cwe_id": "CWE-602",
                "description": "Security-relevant state appears to be stored or checked on the client side, which may be modifiable by the user.",
                "semantic_query": "Client-side enforcement of security or authorization using browser-controlled state",
                "mitigation": "Do not rely on client-controlled state for authorization decisions. Enforce access control on the server side.",
                "confidence": 0.70,
                "status": "suspected"
            },
            "dom_xss_sink": {
                "title": "Potential DOM-based XSS sink",
                "vulnerability_type": "Cross-Site Scripting (DOM-based)",
                "cwe_id": "CWE-79",
                "description": "A DOM sink that can become dangerous if attacker-controlled input reaches it without proper sanitization.",
                "semantic_query": "DOM-based cross-site scripting through dangerous HTML sink in frontend code",
                "mitigation": "Avoid unsafe DOM sinks for untrusted input, and sanitize or encode data before inserting it into the DOM.",
                "confidence": 0.65,
                "status": "suspected"
            },
            "sql_query_concatenation": {
                "title": "Potential SQL injection signal",
                "vulnerability_type": "SQL Injection",
                "cwe_id": "CWE-89",
                "description": "Possible SQL query construction using string concatenation or interpolation.",
                "semantic_query": "SQL injection caused by unsafe query construction with string concatenation",
                "mitigation": "Use parameterized queries or prepared statements instead of string concatenation.",
                "confidence": 0.85,
                "status": "suspected"
            },
            "command_execution": {
                "title": "Potential command injection signal",
                "vulnerability_type": "OS Command Injection",
                "cwe_id": "CWE-78",
                "description": "A command execution API appears in the code and may become dangerous if attacker input reaches it.",
                "semantic_query": "OS command injection through unsafe command execution call in application code",
                "mitigation": "Avoid shell invocation with untrusted input and use safer APIs with strict argument separation and validation.",
                "confidence": 0.80,
                "status": "suspected"
            },
            "unsafe_deserialization": {
                "title": "Potential unsafe deserialization signal",
                "vulnerability_type": "Unsafe Deserialization",
                "cwe_id": "CWE-502",
                "description": "A deserialization API associated with unsafe handling of untrusted input appears in the code.",
                "semantic_query": "Unsafe deserialization of untrusted input in application code",
                "mitigation": "Do not deserialize untrusted input with unsafe serializers. Use safe formats and strict validation.",
                "confidence": 0.85,
                "status": "suspected"
            },
            "path_traversal_signal": {
                "title": "Potential path traversal signal",
                "vulnerability_type": "Path Traversal",
                "cwe_id": "CWE-22",
                "description": "A file access pattern may allow attacker-controlled path manipulation.",
                "semantic_query": "Path traversal caused by unsafe file path handling with user-controlled input",
                "mitigation": "Normalize and validate file paths and restrict access to an allowlisted base directory.",
                "confidence": 0.75,
                "status": "suspected"
            },
            "dynamic_code_execution": {
                "title": "Potential dynamic code execution signal",
                "vulnerability_type": "Code Injection",
                "cwe_id": "CWE-94",
                "description": "Dynamic code execution functionality appears in the code and may be unsafe if influenced by untrusted input.",
                "semantic_query": "Code injection through unsafe dynamic code execution in application logic",
                "mitigation": "Avoid dynamic code execution on untrusted input. Replace it with safer explicit logic.",
                "confidence": 0.80,
                "status": "suspected"
            }
        }

        base = mapping.get(pattern)
        if not base:
            return None

        return {
            "title": base["title"],
            "vulnerability_type": base["vulnerability_type"],
            "cwe_id": base["cwe_id"],
            "file_path": file_path,
            "line_start": line_number,
            "line_end": line_number,
            "evidence": line,
            "description": base["description"],
            "confidence": base["confidence"],
            "severity_hint": severity_hint,
            "semantic_query": base["semantic_query"],
            "mitigation": base["mitigation"],
            "related_cves": [],
            "status": base["status"]
        }