# langgraph-app/src/agents/tool_recognizer.py

from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate


class ToolRecognizer:
    def __init__(self, model_name: str = "qwen2.5:7b"):
        self.llm = ChatOllama(
            model=model_name,
            temperature=0,  # deterministic classification
            base_url="http://localhost:11434"
        )

        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a tool recognizer agent in a cybersecurity system.

Your job is to determine whether a user query requires retrieving vulnerability data (CVE-based semantic search).

Available tools:
- semantic_search: Use for queries involving vulnerabilities, exploits, CVEs, security risks, or code security analysis
- none: Use if the query can be answered directly without retrieving external vulnerability data

Respond with ONLY one of the following:
- semantic_search
- none

Do not explain your answer.

Examples:

User: "Find vulnerabilities in Linux privilege escalation"
Response: semantic_search

User: "Show me recent CVEs related to buffer overflow"
Response: semantic_search

User: "Analyze this code for security issues"
Response: semantic_search

User: "What is SQL injection?"
Response: none

User: "Explain what a vulnerability is"
Response: none
"""),
            ("human", "{query}")
        ])

        self.chain = self.prompt | self.llm

    def recognize(self, query: str) -> str:
        """Return tool name or 'none'"""
        response = self.chain.invoke({"query": query})
        tool_name = response.content.strip().lower()

        # Strict validation
        if tool_name not in ["semantic_search", "none"]:
            return "none"

        return tool_name