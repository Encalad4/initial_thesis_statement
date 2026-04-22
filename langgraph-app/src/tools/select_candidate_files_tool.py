# langgraph-app/src/tools/select_candidate_files_tool.py

from typing import Dict, Any, List


class SelectCandidateFilesTool:
    def select(self, repo_summary: Dict[str, Any], project_stack: Dict[str, Any]) -> Dict[str, Any]:
        sample_files = repo_summary.get("sample_files", [])
        languages = project_stack.get("languages", [])

        candidates: List[Dict[str, Any]] = []

        for file_path in sample_files:
            lower = file_path.lower()
            priority = 1
            reason = "general source file"

            if lower.endswith((".html", ".js", ".ts", ".tsx", ".jsx", ".php", ".py", ".java", ".go", ".rb")):
                priority = 3
                reason = "source file likely to contain executable application logic"
            else:
                continue

            if any(name in lower for name in ["auth", "login", "admin", "user", "account", "session", "token"]):
                priority = 5
                reason = "authentication or account-related file"

            elif any(name in lower for name in ["api", "route", "controller", "handler", "view"]):
                priority = 4
                reason = "request handling or application entrypoint file"

            elif "frontend-static" in languages and lower.endswith(".html"):
                priority = max(priority, 4)
                reason = "static frontend page with embedded client-side logic"

            candidates.append({
                "file_path": file_path,
                "reason": reason,
                "priority": priority
            })

        candidates.sort(key=lambda x: (-x["priority"], x["file_path"]))

        return {
            "success": True,
            "data": {
                "candidate_files": candidates
            }
        }