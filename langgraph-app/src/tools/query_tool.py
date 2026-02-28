# langgraph-app/src/tools/query_tool.py
import psycopg2
import os
from typing import Dict, Any

class QueryTool:
    def __init__(self):
        # Mock database connection
        self.conn_params = {
            'host': os.getenv('MOCK_DB_HOST', 'mock-db-tesis-1'),
            'port': os.getenv('MOCK_DB_PORT', '5432'),
            'database': os.getenv('MOCK_DB_NAME', 'mock_database'),
            'user': os.getenv('MOCK_DB_USER', 'mock_user'),
            'password': os.getenv('MOCK_DB_PASSWORD', 'mock_password')
        }
    
    def execute_query(self, query: str) -> Dict[str, Any]:
        """
        Execute SQL query and return results
        """
        try:
            conn = psycopg2.connect(**self.conn_params)
            cur = conn.cursor()
            cur.execute(query)
            
            # Check if query returns results
            if cur.description:
                columns = [desc[0] for desc in cur.description]
                results = cur.fetchall()
                
                # Format results
                formatted_results = []
                for row in results:
                    formatted_results.append(dict(zip(columns, row)))
                
                result = {
                    'success': True,
                    'data': formatted_results,
                    'row_count': len(formatted_results)
                }
            else:
                # For INSERT, UPDATE, DELETE queries
                conn.commit()
                result = {
                    'success': True,
                    'data': [],
                    'row_count': cur.rowcount
                }
            
            cur.close()
            conn.close()
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'data': []
            }
    
    def get_tool_description(self) -> str:
        return """query_tool: Executes SQL queries on the company database.
Available schemas: it_department, finance_department
Tables: employees, employee_accounts
Use this tool when you need to retrieve employee information, accounts, or any data from the database.
Example: "SELECT * FROM it_department.employees WHERE department = 'IT'"
"""