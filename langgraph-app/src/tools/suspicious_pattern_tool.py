# langgraph-app/src/tools/suspicious_pattern_tool.py

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
                "regex": r"(SELECT|INSERT|UPDATE|DELETE).*(\+|f\"|f'|format\()",
                "severity_hint": "high"
            },
            {
                "name": "command_execution",
                "regex": r"\b(os\.system|subprocess\.(run|Popen|call)|exec\()",
                "severity_hint": "high"
            },
            {
                "name": "path_traversal_signal",
                "regex": r"\b(open|send_file|readFile|fs\.readFile)\b.*(\.\./|filename|path)",
                "severity_hint": "medium"
            },
            {
                "name": "unsafe_deserialization",
                "regex": r"\b(pickle\.loads|yaml\.load|marshal\.loads|unserialize\s*\()",
                "severity_hint": "high"
            }
        ]

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
                    for pattern in self.patterns:
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