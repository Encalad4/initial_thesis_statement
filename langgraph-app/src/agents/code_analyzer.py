# langgraph-app/src/agents/code_analyzer.py

from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from typing import Dict, Any
import json


class CodeAnalyzerAgent:
    """
    Agent responsible for analyzing code snippets and identifying vulnerabilities.
    Outputs structured data including vulnerability type and CWE when possible.
    """

    def __init__(self, model_name: str = "deepseek-coder:6.7b"):
        self.llm = ChatOllama(
            model=model_name,
            temperature=0.2,  # lower = more deterministic for analysis
            base_url="http://localhost:11434"
        )

        # --- ANALYSIS PROMPT ---
        self.analysis_prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a senior secure code auditor.

Your task is to analyze code snippets and identify security vulnerabilities.

Instructions:
- Identify any vulnerabilities present in the code
- Classify them using CWE IDs when possible (e.g., CWE-89 for SQL Injection)
- Be precise and technical
- If no vulnerability is found, explicitly say so

Output STRICTLY in JSON format:
{
  "vulnerabilities": [
    {
      "type": "Vulnerability name",
      "cwe": "CWE-XXX",
      "explanation": "Technical explanation"
    }
  ]
}

Rules:
- Do NOT include any text outside JSON
- Do NOT hallucinate vulnerabilities
- If unsure, return an empty list

Example:
{
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "cwe": "CWE-89",
      "explanation": "User input is directly concatenated into a SQL query without sanitization."
    }
  ]
}"""),
            ("human", "Analyze this code:\n\n{code}")
        ])

    # -------------------------------
    # MAIN ANALYSIS METHOD
    # -------------------------------
    def analyze_code(self, code: str) -> Dict[str, Any]:
        """
        Analyze code and return structured vulnerability data
        """

        try:
            response = (self.analysis_prompt | self.llm).invoke({
                "code": code
            })

            raw_output = response.content.strip()

            # Attempt to parse JSON safely
            parsed_output = self._safe_json_parse(raw_output)

            return {
                "success": True,
                "data": parsed_output
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "data": {}
            }

    # -------------------------------
    # SAFE JSON PARSER
    # -------------------------------
    def _safe_json_parse(self, text: str) -> Dict[str, Any]:
        """
        Handles cases where the model slightly breaks JSON format
        """

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Attempt basic cleanup
            cleaned = text.strip()

            # Remove markdown code fences if present
            if cleaned.startswith("```"):
                cleaned = cleaned.split("```")[1]

            if cleaned.endswith("```"):
                cleaned = cleaned.rsplit("```", 1)[0]

            try:
                return json.loads(cleaned)
            except Exception:
                # Fallback: return empty structure
                return {"vulnerabilities": []}