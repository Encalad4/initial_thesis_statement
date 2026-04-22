#langgraph-app/src/tools/read_file_tool.py

from pathlib import Path
from typing import Dict, Any


class ReadFileTool:
    def read_file(
        self,
        file_path: str,
        max_chars: int = 12000,
        start_line: int = 1,
        end_line: int | None = None,
    ) -> Dict[str, Any]:
        path = Path(file_path)

        if not path.exists() or not path.is_file():
            return {
                "success": False,
                "error": f"File does not exist or is not a file: {file_path}"
            }

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()

            total_lines = len(lines)

            if start_line < 1:
                start_line = 1

            if end_line is None or end_line > total_lines:
                end_line = total_lines

            selected = lines[start_line - 1:end_line]

            numbered_lines = [
                f"{idx}: {line}"
                for idx, line in enumerate(selected, start=start_line)
            ]

            content = "\n".join(numbered_lines)

            truncated = False
            if len(content) > max_chars:
                content = content[:max_chars]
                truncated = True

            return {
                "success": True,
                "data": {
                    "file_path": str(path),
                    "start_line": start_line,
                    "end_line": end_line,
                    "total_lines": total_lines,
                    "truncated": truncated,
                    "content": content
                }
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }