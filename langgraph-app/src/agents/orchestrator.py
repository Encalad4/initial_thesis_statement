# langgraph-app/src/agents/orchestrator.py
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate

class Orchestrator:
    def __init__(self, model_name: str = "phi3:3.8b"):
        self.llm = ChatOllama(
            model=model_name,
            temperature=0.7,
            base_url="http://localhost:11434"
        )
        
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """You are an orchestrator agent. Your job is to analyze user queries and 
            determine if they need database access. Be conversational and helpful.

            If you can answer directly without database access, do so.
            If you need database access, politely explain that you'll look up the information."""),
            ("human", "{query}")
        ])
        
        self.chain = self.prompt | self.llm
    
    def process(self, query: str) -> str:
        """Initial processing of user query"""
        response = self.chain.invoke({"query": query})
        return response.content