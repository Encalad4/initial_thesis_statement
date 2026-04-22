#langgraph-app/src/agents/cwe_validator.py

from typing import Dict, Any, List
import json

from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate


class CWEValidatorAgent:
    """
    Validates a suspected hypothesis against code context and candidate CWE contexts.
    This is the first true AI validation layer in the pipeline.
    """

    def __init__(self, model_name: str = "qwen2.5:7b"):
        self.llm = ChatOllama(
            model=model_name,
            temperature=0.1,
            base_url="http://localhost:11434"
        )

        self.prompt = ChatPromptTemplate.from_messages([
        ("system", """You are a secure code analysis agent.

        Your task is to validate or reject a suspected weakness hypothesis using:
        1. repository stack context
        2. local code context
        3. a suspected hypothesis
        4. retrieved candidate CWE knowledge

        Be conservative. Many scanner signals are only suspicious indicators, not real weaknesses.

        Validation rules:
        - Only return "validated" if the local code context provides direct evidence supporting the weakness.
        - For client-side security enforcement, do not treat generic application state, UI state, game state, preferences, or cached values as security-critical. Only validate if the code context clearly shows authentication, authorization, access control, privileged functionality, session enforcement, role checks, or similar security-relevant control.
        - If the code only shows a sink or storage mechanism, but not attacker-controlled input or security-critical use, do NOT validate.
        - For DOM XSS, do not validate unless the context shows that attacker-controlled or untrusted input can realistically reach the sink.
        - For client-side security enforcement, do not validate unless the stored or checked client-side state is clearly security-relevant, such as authentication, authorization, session state, privileged actions, or access control.
        - If the evidence is ambiguous, return "needs_review".
        - If the evidence does not support the weakness, return "rejected".

        Choose the single best outcome:
        - validated
        - rejected
        - needs_review

        Output STRICTLY as JSON in this format:
        {{
        "decision": "validated|rejected|needs_review",
        "final_cwe_id": "CWE-XXX or null",
        "final_cwe_name": "name or null",
        "confidence": 0.0,
        "rationale": "short technical explanation grounded only in the provided code context",
        "mitigation": "short mitigation guidance or null"
        }}

        Rules:
        - Return only JSON
        - confidence must be between 0 and 1
        - final_cwe_id must be null if rejected
        - final_cwe_id may be null for needs_review
        - prefer the most specific well-supported CWE among the candidates
        - do not invent nonexistent CWE IDs
        - do not assume user input exists unless it is visible in the provided context
        - do not assume a value is security-critical unless the provided context clearly ties it to authentication, authorization, session control, privilege checks, or access control
        """),
            ("human", """Project stack:
        {project_stack}

        Hypothesis:
        {hypothesis}

        Code context:
        {code_context}

        Candidate CWE contexts:
        {candidate_cwe_contexts}
        """)
        ])

        self.chain = self.prompt | self.llm

    def validate(
        self,
        project_stack: Dict[str, Any],
        hypothesis: Dict[str, Any],
        code_context: str,
        candidate_cwe_contexts: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        try:
            compact_candidates = []

            for ctx in candidate_cwe_contexts:
                cwe = ctx.get("cwe", {})
                mitigations = ctx.get("mitigations", [])[:2]
                detection_methods = ctx.get("detection_methods", [])[:2]

                compact_candidates.append({
                    "id": cwe.get("id"),
                    "name": cwe.get("name"),
                    "description": cwe.get("description"),
                    "extended_description": cwe.get("extended_description"),
                    "abstraction": cwe.get("abstraction"),
                    "status": cwe.get("status"),
                    "mitigations": mitigations,
                    "detection_methods": detection_methods,
                })

            response = self.chain.invoke({
                "project_stack": json.dumps(project_stack, indent=2),
                "hypothesis": json.dumps(hypothesis, indent=2),
                "code_context": code_context,
                "candidate_cwe_contexts": json.dumps(compact_candidates, indent=2)
            })

            raw_output = response.content.strip()
            parsed = self._safe_json_parse(raw_output)

            return {
                "success": True,
                "data": parsed,
                "raw_output": raw_output
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def _safe_json_parse(self, text: str) -> Dict[str, Any]:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            cleaned = text.strip()

            if cleaned.startswith("```"):
                parts = cleaned.split("```")
                if len(parts) >= 2:
                    cleaned = parts[1]

            if cleaned.endswith("```"):
                cleaned = cleaned.rsplit("```", 1)[0]

            cleaned = cleaned.replace("```json", "").replace("```", "").strip()

            try:
                return json.loads(cleaned)
            except Exception:
                return {
                    "decision": "needs_review",
                    "final_cwe_id": None,
                    "final_cwe_name": None,
                    "confidence": 0.0,
                    "rationale": "Model output could not be parsed as valid JSON.",
                    "mitigation": None
                }