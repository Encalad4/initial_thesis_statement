# langgraph-app/src/tools/semantic_search_tool.py

import psycopg2
from typing import Dict, Any, List
import os
import requests


class SemanticSearchTool:
    def __init__(self):
        self.db_config = {
            "host": os.getenv("DB_HOST", "cve-db-tesis-1"),
            "port": os.getenv("DB_PORT", 5432),
            "dbname": os.getenv("DB_NAME", "cve_database"),
            "user": os.getenv("DB_USER", "cve_user"),
            "password": os.getenv("DB_PASSWORD", "cve_password"),
        }

        # Ollama embedding endpoint
        self.ollama_url = "http://localhost:11434/api/embeddings"
        self.embedding_model = "mxbai-embed-large"

    def _get_connection(self):
        return psycopg2.connect(**self.db_config)

    def _get_embedding(self, text: str) -> List[float]:
        """
        Generate embedding using Ollama
        """
        response = requests.post(
            self.ollama_url,
            json={
                "model": self.embedding_model,
                "prompt": text
            }
        )

        if response.status_code != 200:
            raise Exception(f"Ollama embedding error: {response.text}")

        return response.json()["embedding"]

    def execute_query(self, query: str) -> Dict[str, Any]:
        """
        Perform semantic search using pgvector similarity
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            # 1. Generate embedding for the query
            query_embedding = self._get_embedding(query)

            # 2. Perform vector similarity search
            sql = """
                SELECT 
                    c.id,
                    c.description,
                    c.severity,
                    c.published_date,
                    (e.embedding <-> %s::vector) AS distance
                FROM cve_embeddings e
                JOIN cves c ON c.id = e.cve_id
                ORDER BY e.embedding <-> %s::vector
                LIMIT 5;
            """

            cursor.execute(sql, (query_embedding, query_embedding))
            rows = cursor.fetchall()

            # Column names
            colnames = [desc[0] for desc in cursor.description]

            # Convert to dict
            results = [dict(zip(colnames, row)) for row in rows]

            cursor.close()
            conn.close()

            return {
                "success": True,
                "data": results
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }