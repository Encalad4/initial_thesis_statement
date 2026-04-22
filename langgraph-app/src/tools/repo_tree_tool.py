#langgraph-app/src/tools/repo_tree_tool.py

from pathlib import Path
from collections import Counter
from typing import Dict, Any


IGNORED_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build"
}


class RepoTreeTool:
    def inspect_repository(self, repo_path: str, max_files: int = 2000) -> Dict[str, Any]:
        root = Path(repo_path)

        if not root.exists() or not root.is_dir():
            return {
                "success": False,
                "error": f"Repository path does not exist or is not a directory: {repo_path}"
            }

        files = []
        extensions = Counter()
        top_level_items = []
        total_files = 0

        try:
            for item in sorted(root.iterdir()):
                top_level_items.append(item.name)

            for path in root.rglob("*"):
                relative_parts = path.relative_to(root).parts

                if any(part in IGNORED_DIRS for part in relative_parts):
                    continue

                if path.is_file():
                    total_files += 1
                    ext = path.suffix.lower() if path.suffix else "[no_extension]"
                    extensions[ext] += 1

                    if len(files) < max_files:
                        files.append(str(path.relative_to(root)))

            return {
                "success": True,
                "data": {
                    "repo_path": str(root),
                    "top_level_items": top_level_items,
                    "total_files": total_files,
                    "extensions": dict(extensions.most_common()),
                    "sample_files": files[:100]
                }
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }