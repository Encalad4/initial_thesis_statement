# langgraph/src/agents/cwe_validator.py

from typing import Dict, Any, List
import json
import requests


class CWEValidatorAgent:
    """
    Minimal benchmark-oriented classifier.
    Uses Ollama structured output directly instead of freeform chat parsing.
    """

    def __init__(self, model_name: str = "qwen2.5:7b"):
        self.model_name = model_name
        self.ollama_url = "http://localhost:11434/api/generate"

        self.output_schema = {
            "type": "object",
            "properties": {
                "decision": {
                    "type": "string",
                    "enum": ["validated", "rejected", "needs_review"]
                },
                "final_cwe_id": {
                    "type": ["string", "null"]
                },
                "confidence": {
                    "type": "number"
                },
                "reason": {
                    "type": "string"
                }
            },
            "required": ["decision", "final_cwe_id", "confidence", "reason"]
        }

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
                compact_candidates.append({
                    "id": cwe.get("id"),
                    "name": cwe.get("name"),
                    "description": cwe.get("description"),
                })

            system_prompt = """You are a secure code classification agent.

Your only job is to classify ONE suspected weakness in ONE code snippet.

Return exactly one JSON object with:
- decision: validated, rejected, or needs_review
- final_cwe_id: one CWE from the candidate list, or null
- confidence: number between 0 and 1
- reason: short explanation for your choice

Global rules:
- Use only the provided hypothesis, code context, and candidate CWEs.
- Do not summarize the candidate CWEs.
- Do not explain vulnerability classes in general.
- If the evidence supports the weakness, return validated.
- If the evidence does not support the weakness, return rejected.
- If the evidence is ambiguous, return needs_review.
- final_cwe_id must be null if decision is rejected.
- final_cwe_id may be null if decision is needs_review.
- Prefer the most specific supported CWE from the candidate list.

Family-specific rules:

For sql_injection_signal:
- Validate only if SQL structure appears dynamically influenced by variables, concatenation, interpolation, or similar construction.
- Reject if PreparedStatement with placeholders and parameter binding appears to be used safely.
- Reject if only fixed SQL is visible.

For command_injection_signal:
- Validate only if command content or command arguments appear influenced by variables, concatenation, request data, parameters, or other external input.
- Reject if the command appears fixed and literal-only.
- Reject if only a command sink is visible without evidence of untrusted influence.

For path_traversal_signal:
- Validate only if a filesystem sink is visible and the path or filename appears influenced by variable or external input in a way that could alter file location.
- Reject if the visible context shows fixed safe directory handling plus normalization, canonicalization, or validation cues.
- Reject if only a sink is visible but there is no indication of unsafe path influence.

Return only the JSON object.
"""

            user_prompt = f"""Project stack:
{json.dumps(project_stack, indent=2)}

Hypothesis:
{json.dumps(hypothesis, indent=2)}

Code context:
{code_context}

Candidate CWEs:
{json.dumps(compact_candidates, indent=2)}
"""

            response = requests.post(
                self.ollama_url,
                json={
                    "model": self.model_name,
                    "system": system_prompt,
                    "prompt": user_prompt,
                    "stream": False,
                    "format": self.output_schema,
                    "options": {
                        "temperature": 0
                    }
                },
                timeout=600
            )
            response.raise_for_status()

            payload = response.json()
            raw_output = payload.get("response", "").strip()
            parsed = json.loads(raw_output)

            decision = parsed.get("decision")
            final_cwe_id = parsed.get("final_cwe_id")
            confidence = parsed.get("confidence", 0.0)
            reason = parsed.get("reason", "")

            if decision not in {"validated", "rejected", "needs_review"}:
                raise ValueError(f"Unexpected decision: {decision!r}")

            if decision == "rejected":
                final_cwe_id = None

            return {
                "success": True,
                "data": {
                    "decision": decision,
                    "final_cwe_id": final_cwe_id,
                    "final_cwe_name": None,
                    "confidence": float(confidence),
                    "rationale": reason,
                    "mitigation": None
                },
                "raw_output": raw_output
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }