# langgraph-app/src/agents/worker.py

from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from typing import Dict, Any
from src.tools.semantic_search_tool import SemanticSearchTool


class Worker:
    def __init__(self, model_name: str = "qwen2.5:7b"):
        self.llm = ChatOllama(
            model=model_name,
            temperature=0.4,  # lower for more controlled reasoning
            base_url="http://localhost:11434"
        )

        # --- ANALYSIS PROMPT (core of Phase 2) ---
        self.analysis_prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a cybersecurity analyst.

You are given:
1. A user query
2. A set of relevant CVEs retrieved via semantic search

Your task:
- Identify the type of vulnerability
- Explain the security risk
- Provide a technical interpretation of the issue

Be precise, structured, and technical.
Do not invent CVEs. Use only the provided data."""),
            ("human", "Query: {query}\n\nRelevant CVEs:\n{data}")
        ])

        # --- DIRECT RESPONSE (fallback) ---
        self.direct_prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a cybersecurity assistant.

Answer clearly and concisely.
If the question is conceptual, provide a technical explanation."""),
            ("human", "{query}")
        ])
        self.semantic_tool = SemanticSearchTool()

    # -------------------------------
    # TOOL EXECUTION (semantic search)
    # -------------------------------
    def execute_tool(self, tool_name: str, query: str) -> Dict[str, Any]:
        """Execute the specified tool"""
        if tool_name == "semantic_search":
            return self.semantic_tool.execute_query(query)

        return {
            "success": False,
            "error": f"Unknown tool: {tool_name}",
            "data": []
        }

    # -------------------------------
    # ANALYSIS (core logic)
    # -------------------------------
    def generate_response(self, user_query: str, data: Dict[str, Any]) -> str:
        """Generate vulnerability analysis from retrieved CVEs"""

        if not data.get("success", False):
            return f"Error during retrieval: {data.get('error', 'Unknown error')}"

        if not data.get("data"):
            return "No relevant vulnerabilities were found for this query."

        response = (self.analysis_prompt | self.llm).invoke({
            "query": user_query,
            "data": str(data["data"])
        })

        return response.content

    # -------------------------------
    # DIRECT RESPONSE (no retrieval)
    # -------------------------------
    def generate_direct_response(self, user_query: str) -> str:
        """Handle non-retrieval queries"""
        response = (self.direct_prompt | self.llm).invoke({
            "query": user_query
        })
        return response.content