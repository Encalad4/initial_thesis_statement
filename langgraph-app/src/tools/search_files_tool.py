#langgraph-app/src/tools/search_files_tool.py

from pathlib import Path
from typing import Dict, Any, List
import re


IGNORED_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build"
}


class SearchFilesTool:
    def search(
        self,
        repo_path: str,
        patterns: List[str],
        max_results: int = 100,
        case_sensitive: bool = False,
    ) -> Dict[str, Any]:
        root = Path(repo_path)

        if not root.exists() or not root.is_dir():
            return {
                "success": False,
                "error": f"Repository path does not exist or is not a directory: {repo_path}"
            }

        flags = 0 if case_sensitive else re.IGNORECASE
        compiled_patterns = [re.compile(p, flags) for p in patterns]
        matches = []

        try:
            for path in root.rglob("*"):
                relative_parts = path.relative_to(root).parts

                if any(part in IGNORED_DIRS for part in relative_parts):
                    continue

                if not path.is_file():
                    continue

                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue

                for line_no, line in enumerate(text.splitlines(), start=1):
                    for pattern in compiled_patterns:
                        if pattern.search(line):
                            matches.append({
                                "file_path": str(path.relative_to(root)),
                                "line_number": line_no,
                                "pattern": pattern.pattern,
                                "line": line.strip()
                            })

                            if len(matches) >= max_results:
                                return {
                                    "success": True,
                                    "data": {
                                        "repo_path": str(root),
                                        "patterns": patterns,
                                        "matches": matches,
                                        "truncated": True
                                    }
                                }

            return {
                "success": True,
                "data": {
                    "repo_path": str(root),
                    "patterns": patterns,
                    "matches": matches,
                    "truncated": False
                }
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }