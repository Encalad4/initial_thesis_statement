#langgraph-app/src/tools/detect_stack_tool.py

from pathlib import Path
from collections import Counter
from typing import Dict, Any


class DetectStackTool:
    def detect(self, repo_path: str) -> Dict[str, Any]:
        root = Path(repo_path)

        if not root.exists() or not root.is_dir():
            return {
                "success": False,
                "error": f"Repository path does not exist or is not a directory: {repo_path}"
            }

        extensions = Counter()
        filenames = set()

        try:
            for path in root.rglob("*"):
                rel_parts = path.relative_to(root).parts
                if any(part in {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"} for part in rel_parts):
                    continue

                if path.is_file():
                    filenames.add(path.name.lower())
                    ext = path.suffix.lower() if path.suffix else "[no_extension]"
                    extensions[ext] += 1

            languages = []
            frameworks = []
            manifests = []

            if extensions[".py"] > 0:
                languages.append("python")
            if extensions[".js"] > 0:
                languages.append("javascript")
            if extensions[".ts"] > 0:
                languages.append("typescript")
            if extensions[".java"] > 0:
                languages.append("java")
            if extensions[".php"] > 0:
                languages.append("php")
            if extensions[".go"] > 0:
                languages.append("go")
            if extensions[".rb"] > 0:
                languages.append("ruby")
            if extensions[".cs"] > 0:
                languages.append("csharp")
            if extensions[".html"] > 0 and not languages:
                languages.append("frontend-static")

            if "requirements.txt" in filenames or "pyproject.toml" in filenames:
                manifests.append("python")
            if "package.json" in filenames:
                manifests.append("node")
            if "pom.xml" in filenames:
                manifests.append("maven")
            if "build.gradle" in filenames or "build.gradle.kts" in filenames:
                manifests.append("gradle")
            if "composer.json" in filenames:
                manifests.append("composer")
            if "go.mod" in filenames:
                manifests.append("go")
            if "gemfile" in filenames:
                manifests.append("bundler")

            if "package.json" in filenames and extensions[".tsx"] > 0:
                frameworks.append("react")
            if "package.json" in filenames and extensions[".vue"] > 0:
                frameworks.append("vue")
            if "package.json" in filenames and extensions[".svelte"] > 0:
                frameworks.append("svelte")
            if "requirements.txt" in filenames and "manage.py" in filenames:
                frameworks.append("django")
            if "requirements.txt" in filenames and ("app.py" in filenames or "wsgi.py" in filenames):
                frameworks.append("flask")
            if "pom.xml" in filenames:
                frameworks.append("java-ecosystem")
            if "composer.json" in filenames:
                frameworks.append("php-ecosystem")

            return {
                "success": True,
                "data": {
                    "languages": languages,
                    "frameworks": frameworks,
                    "manifests": manifests,
                    "extension_counts": dict(extensions.most_common())
                }
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }