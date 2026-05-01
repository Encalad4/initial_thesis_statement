# langgraph-app/src/services/hypothesis_pre_filter.py

import re
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

    INPUT_KEYWORDS = {
        "request", "getparameter(", "getheader(", "cookie", "parameter", "param",
        "input", "userinput", "argv", "args", "querystring"
    }

    PATH_SINK_KEYWORDS = {
        "fileinputstream", "fileoutputstream", "new java.io.file", "new file(",
        "paths.get(", "files.read", "files.newinputstream", "files.newoutputstream"
    }

    COMMAND_SINK_KEYWORDS = {
        "runtime.getruntime().exec", "processbuilder", "exec("
    }

    SQL_SINK_KEYWORDS = {
        "select ", "insert ", "update ", "delete ",
        "executequery(", "executeupdate(", "executelargeupdate(",
        "preparestatement(", "statement"
    }

    SAFE_PATH_KEYWORDS = {
        "getcanonicalpath", "normalize(", "canonicalfile", "startswith(", "equals("
    }

    def _contains_any(self, lowered: str, keywords: set[str]) -> bool:
        return any(keyword in lowered for keyword in keywords)

    def should_validate(self, hypothesis: Dict[str, Any], code_context: str) -> Dict[str, Any]:
        hypothesis_type = hypothesis.get("hypothesis_type")
        lowered = code_context.lower()
        evidence = (hypothesis.get("evidence") or "").lower()

        if hypothesis_type == "client_side_security_enforcement":
            if not self._contains_any(lowered, self.SECURITY_KEYWORDS):
                return {
                    "should_validate": False,
                    "reason": "No security-relevant indicators found in local code context for client-side security enforcement hypothesis."
                }

        if hypothesis_type == "sql_injection_signal":
            if not self._contains_any(lowered, self.SQL_SINK_KEYWORDS):
                return {
                    "should_validate": False,
                    "reason": "No SQL execution indicators found in local code context."
                }

            safe_prepared_statement = (
                "preparedstatement" in lowered
                and "?" in code_context
                and any(token in lowered for token in [
                    "setstring(", "setint(", "setlong(", "setobject(",
                    "setdouble(", "setfloat(", "setboolean("
                ])
                and "+" not in code_context
                and ".concat(" not in lowered
                and "append(" not in lowered
            )

            if safe_prepared_statement:
                return {
                    "should_validate": False,
                    "reason": "PreparedStatement parameter binding appears to be used without dynamic SQL concatenation."
                }

        if hypothesis_type == "command_injection_signal":
            if not self._contains_any(lowered, self.COMMAND_SINK_KEYWORDS):
                return {
                    "should_validate": False,
                    "reason": "No command execution sink found in local code context."
                }

            constant_only_command = (
                re.search(r'exec\s*\(\s*"[^"]+"\s*\)', lowered) is not None
                or re.search(r'processbuilder\s*\(\s*"[^"]+"\s*(,\s*"[^"]+"\s*)*\)', lowered) is not None
            )

            has_dynamic_input_signal = (
                self._contains_any(lowered, self.INPUT_KEYWORDS)
                or "+" in code_context
                or ".concat(" in lowered
                or "append(" in lowered
            )

            if constant_only_command and not has_dynamic_input_signal:
                return {
                    "should_validate": False,
                    "reason": "Command execution appears to use only fixed literal arguments without visible untrusted input influence."
                }

        if hypothesis_type == "path_traversal_signal":
            if not self._contains_any(lowered, self.PATH_SINK_KEYWORDS):
                return {
                    "should_validate": False,
                    "reason": "No filesystem sink found in local code context."
                }

            safe_validation_context = (
                self._contains_any(lowered, self.SAFE_PATH_KEYWORDS)
                and ("utils.testfiles_dir" in lowered or "testfiles_dir" in lowered)
                and not self._contains_any(lowered, self.INPUT_KEYWORDS)
            )

            if safe_validation_context:
                return {
                    "should_validate": False,
                    "reason": "Path handling appears tied to a fixed test directory with visible validation or normalization cues."
                }

        return {
            "should_validate": True,
            "reason": "Passed pre-filter."
        }