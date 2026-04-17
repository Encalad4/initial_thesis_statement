# langgraph-app/src/agents/orchestrator.py

from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate


class Orchestrator:
    def __init__(self, model_name: str = "qwen2.5:7b"):
        self.llm = ChatOllama(
            model=model_name,
            temperature=0.3,  # lower = more deterministic normalization
            base_url="http://localhost:11434"
        )

        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """You are an orchestrator agent in a multi-agent system.

Your ONLY responsibility is to understand and reformulate the user's query clearly.

Do NOT:
- answer the question
- decide which tools to use
- mention databases or retrieval

DO:
- rewrite the query to be clear, precise, and well-structured
- preserve the original intent
- expand slightly if needed for clarity

Output ONLY the refined query, nothing else.
"""),
            ("human", "{query}")
        ])

        self.chain = self.prompt | self.llm

    def process(self, query: str) -> str:
        """
        Normalize and clarify the user query before passing it to the system.
        """
        response = self.chain.invoke({"query": query})
        refined_query = response.content.strip()

        # Fallback: if model returns empty or weird output
        if not refined_query:
            return query

        return refined_query