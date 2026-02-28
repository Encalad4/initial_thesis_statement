# langgraph-app/src/agents/tool_recognizer.py
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from typing import Optional

class ToolRecognizer:
    def __init__(self, model_name: str = "qwen2.5:1.5b"):
        self.llm = ChatOllama(
            model=model_name,
            temperature=0,
            base_url="http://localhost:11434"
        )
        
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a tool recognizer agent. Your job is to analyze if a user query requires 
            database access and if so, which tool should be used.

            Available tools:
            - query_tool: Use this for any question that requires data from the company database.
              This includes queries about employees, accounts, departments, etc.

            If the query requires database access, respond ONLY with the tool name: "query_tool"
            If the query does NOT require database access, respond with: "none"

            Examples:
            User: "Show me all IT employees"
            Response: query_tool

            User: "What accounts does John Smith have?"
            Response: query_tool

            User: "What is the capital of France?"
            Response: none

            User: "Tell me a joke"
            Response: none
            """),
            ("human", "{query}")
        ])
        
        self.chain = self.prompt | self.llm
    
    def recognize(self, query: str) -> str:
        """Return tool name or 'none'"""
        response = self.chain.invoke({"query": query})
        tool_name = response.content.strip().lower()
        
        # Validate response
        if tool_name not in ["query_tool", "none"]:
            return "none"
        
        return tool_name