#langgraph-app/src/tools/sandbox_clone_tool.py

import os
from typing import Dict, Any
import requests


class SandboxCloneTool:
    def __init__(self):
        self.base_url = os.getenv("SANDBOX_API_URL", "http://sandbox-tesis-3:8001")

    def clone_repository(self, github_url: str) -> Dict[str, Any]:
        try:
            response = requests.post(
                f"{self.base_url}/clone",
                json={"github_url": github_url},
                timeout=300
            )

            if response.status_code != 200:
                return {
                    "success": False,
                    "error": f"Sandbox clone failed with status {response.status_code}: {response.text}"
                }

            data = response.json()
            return {
                "success": True,
                "data": data
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }