#langgraph-app/src/tools/suspicious_pattern_tool.py

from pathlib import Path
from typing import Dict, Any, List
import re


class SuspiciousPatternTool:
    def __init__(self):
        self.patterns = [
            {
                "name": "hardcoded_secret",
                "regex": r"(password|secret|token|apikey|api_key)\s*[:=]\s*[\"'][^\"']+[\"']",
                "severity_hint": "medium"
            },
            {
                "name": "client_side_auth_storage",
                "regex": r"localStorage\.(getItem|setItem)\(",
                "severity_hint": "medium"
            },
            {
                "name": "dynamic_code_execution",
                "regex": r"\beval\s*\(|\bnew\s+Function\s*\(",
                "severity_hint": "high"
            },
            {
                "name": "dom_xss_sink",
                "regex": r"\b(innerHTML|outerHTML|document\.write)\b",
                "severity_hint": "high"
            },
            {
                "name": "sql_query_concatenation",
                "regex": (
                    r"("
                    r"\b(SELECT|INSERT|UPDATE|DELETE)\b[^\n;]*(\+|\.concat\s*\(|StringBuilder|append\s*\()|"
                    r"\b(execute|executeQuery|executeUpdate|executeLargeUpdate)\s*\([^)]*\+|"
                    r"\bprepareStatement\s*\([^)]*\+|"
                    r"\bcreateStatement\s*\(\s*\)\s*\.\s*execute(Query|Update|LargeUpdate)?\s*\([^)]*\+"
                    r")"
                ),
                "severity_hint": "high",
                "ignore_regexes": [
                    r"\bPreparedStatement\b",
                ]
            },
            {
                "name": "command_execution",
                "regex": (
                    r"\b("
                    r"os\.system|"
                    r"subprocess\.(run|Popen|call)|"
                    r"exec\s*\(|"
                    r"Runtime\.getRuntime\s*\(\)\.exec\s*\(|"
                    r"new\s+ProcessBuilder\s*\(|"
                    r"ProcessBuilder\s*\("
                    r")"
                ),
                "severity_hint": "high"
            },
            {
                "name": "path_traversal_signal",
                "regex": (
                    r"\b("
                    r"new\s+(?:[\w]+\.)*File\s*\(|"
                    r"new\s+(?:[\w]+\.)*FileInputStream\s*\(|"
                    r"new\s+(?:[\w]+\.)*FileOutputStream\s*\(|"
                    r"new\s+(?:[\w]+\.)*FileReader\s*\(|"
                    r"new\s+(?:[\w]+\.)*FileWriter\s*\(|"
                    r"new\s+(?:[\w]+\.)*RandomAccessFile\s*\(|"
                    r"(?:[\w]+\.)*Paths\.get\s*\(|"
                    r"(?:[\w]+\.)*Files\.(readAllBytes|readString|readAllLines|lines|newInputStream|newBufferedReader|newOutputStream)\s*\(|"
                    r"getCanonicalPath\s*\(|"
                    r"getAbsolutePath\s*\("
                    r")"
                ),
                "severity_hint": "medium",
                "ignore_regexes": [
                    r"\bSystem\.out\.print(ln)?\s*\(",
                    r"\bSystem\.err\.print(ln)?\s*\(",
                    r"\blogger\.(debug|info|warn|error|trace)\s*\(",
                    r"\bLOG\.(debug|info|warn|error|trace)\s*\(",
                ]
            },
            {
                "name": "unsafe_deserialization",
                "regex": r"\b(pickle\.loads|yaml\.load|marshal\.loads|unserialize\s*\()",
                "severity_hint": "high"
            }
        ]

    def _line_should_be_ignored(self, line: str, pattern: Dict[str, Any]) -> bool:
        for ignore_regex in pattern.get("ignore_regexes", []):
            if re.search(ignore_regex, line, flags=re.IGNORECASE):
                return True
        return False

    def _is_commented_line(self, line: str) -> bool:
        stripped = line.strip()
        return (
            stripped.startswith("//")
            or stripped.startswith("/*")
            or stripped.startswith("*")
            or stripped.startswith("*/")
        )

    def _is_structural_noise(self, line: str) -> bool:
        stripped = line.strip()
        return (
            stripped == ""
            or stripped.startswith("import ")
            or stripped.startswith("package ")
            or stripped in {"{", "}", "(", ")", ");"}
        )

    def _is_incomplete_path_fragment(self, line: str) -> bool:
        stripped = line.strip()
        return (
            stripped.endswith("(")
            or stripped in {"new java.io.File(", "new File("}
        )

    def scan_files(self, repo_path: str, candidate_files: List[Dict[str, Any]], max_matches: int = 200) -> Dict[str, Any]:
        root = Path(repo_path)

        if not root.exists() or not root.is_dir():
            return {
                "success": False,
                "error": f"Repository path does not exist or is not a directory: {repo_path}"
            }

        matches = []

        try:
            for candidate in candidate_files:
                relative_path = candidate.get("file_path")
                if not relative_path:
                    continue

                file_path = root / relative_path
                if not file_path.exists() or not file_path.is_file():
                    continue

                try:
                    text = file_path.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue

                for line_number, line in enumerate(text.splitlines(), start=1):
                    if self._is_commented_line(line):
                        continue

                    if self._is_structural_noise(line):
                        continue

                    for pattern in self.patterns:
                        if self._line_should_be_ignored(line, pattern):
                            continue

                        if pattern["name"] == "path_traversal_signal" and self._is_incomplete_path_fragment(line):
                            continue

                        if re.search(pattern["regex"], line, flags=re.IGNORECASE):
                            matches.append({
                                "file_path": relative_path,
                                "line_number": line_number,
                                "pattern_name": pattern["name"],
                                "severity_hint": pattern["severity_hint"],
                                "line": line.strip()
                            })

                            if len(matches) >= max_matches:
                                return {
                                    "success": True,
                                    "data": {
                                        "matches": matches,
                                        "truncated": True
                                    }
                                }

            return {
                "success": True,
                "data": {
                    "matches": matches,
                    "truncated": False
                }
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }