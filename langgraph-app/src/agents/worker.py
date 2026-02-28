# langgraph-app/src/agents/worker.py
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from typing import Dict, Any
from src.tools.query_tool import QueryTool

class Worker:
    def __init__(self, model_name: str = "phi3:3.8b"):
        self.llm = ChatOllama(
            model=model_name,
            temperature=0.7,
            base_url="http://localhost:11434"
        )
        self.query_tool = QueryTool()
        
        self.sql_prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a worker agent that generates SQL queries based on user questions.
            Database schema:
            - it_department.employees: employee_id, first_name, last_name, email, department, hire_date
            - it_department.employee_accounts: account_id, employee_id, service_name, email, username, password
            - finance_department.employees: employee_id, first_name, last_name, email, department, hire_date
            - finance_department.employee_accounts: account_id, employee_id, service_name, email, username, password

            Generate ONLY the SQL query, nothing else. Do NOT include markdown formatting, backticks, or the word 'sql'.
            Just output the raw SQL query.
            Make sure to use the correct schema prefix (it_department or finance_department).
            """),
            ("human", "{query}")
        ])
        
        self.response_prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a helpful assistant. Based on the user's question and the data retrieved,
            provide a clear and helpful response. Explain the data in a natural way.
            If there are no results, explain that politely."""),
            ("human", "Question: {query}\n\nData retrieved: {data}\n\nProvide a helpful response:")
        ])
        
        self.direct_prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a helpful assistant. Respond to the user's message in a friendly and helpful way."""),
            ("human", "{query}")
        ])
    
    def generate_query(self, user_query: str) -> str:
        """Generate SQL query from user question"""
        response = (self.sql_prompt | self.llm).invoke({"query": user_query})
        
        # Clean the response - remove any markdown or extra text
        sql = response.content.strip()
        
        # Remove common markdown artifacts
        sql = sql.replace("```sql", "").replace("```", "").strip()
        
        # If the response contains multiple lines, take the first line that looks like SQL
        lines = sql.split('\n')
        for line in lines:
            line = line.strip()
            if line and (line.upper().startswith("SELECT") or 
                        line.upper().startswith("INSERT") or 
                        line.upper().startswith("UPDATE") or 
                        line.upper().startswith("DELETE")):
                return line
        
        return sql
    
    def execute_tool(self, tool_name: str, query: str) -> Dict[str, Any]:
        """Execute the specified tool with the query"""
        if tool_name == "query_tool":
            return self.query_tool.execute_query(query)
        else:
            return {"success": False, "error": f"Unknown tool: {tool_name}"}
    
    def generate_response(self, user_query: str, data: Dict[str, Any]) -> str:
        """Generate natural language response from query results"""
        if not data.get('success', False):
            return f"I encountered an error: {data.get('error', 'Unknown error')}"
        
        if not data.get('data'):
            return "I didn't find any data matching your query."
        
        response = (self.response_prompt | self.llm).invoke({
            "query": user_query,
            "data": str(data['data'])
        })
        return response.content
    
    def generate_direct_response(self, user_query: str) -> str:
        """Generate direct response for non-tool queries"""
        response = (self.direct_prompt | self.llm).invoke({"query": user_query})
        return response.content