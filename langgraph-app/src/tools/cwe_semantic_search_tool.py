#langgraph-app/src/tools/cwe_semantic_search_tool.py

import os
from typing import Dict, Any, List
import psycopg2
import requests


class CWESemanticSearchTool:
    def __init__(self):
        self.db_config = {
            "host": os.getenv("CVE_DB_HOST", "cve-db-tesis-3"),
            "port": int(os.getenv("CVE_DB_PORT", 5432)),
            "dbname": os.getenv("CVE_DB_NAME", "cve_database"),
            "user": os.getenv("CVE_DB_USER", "cve_user"),
            "password": os.getenv("CVE_DB_PASSWORD", "cve_password"),
        }
        self.ollama_url = "http://localhost:11434/api/embeddings"
        self.embedding_model = "mxbai-embed-large"

    def _get_connection(self):
        return psycopg2.connect(**self.db_config)

    def _get_embedding(self, text: str) -> List[float]:
        response = requests.post(
            self.ollama_url,
            json={
                "model": self.embedding_model,
                "prompt": text
            },
            timeout=60
        )

        if response.status_code != 200:
            raise Exception(f"Ollama embedding error: {response.text}")

        return response.json()["embedding"]

    def search(self, query: str, top_k: int = 5) -> Dict[str, Any]:
        try:
            conn = self._get_connection()
            cur = conn.cursor()

            query_embedding = self._get_embedding(query)

            sql = """
                SELECT
                    e.cwe_id,
                    c.name,
                    c.description,
                    c.extended_description,
                    c.abstraction,
                    c.status,
                    e.chunk_type,
                    e.chunk_index,
                    e.content,
                    (e.embedding <-> %s::vector) AS distance
                FROM cwe_embeddings e
                JOIN cwe c ON c.id = e.cwe_id
                ORDER BY e.embedding <-> %s::vector
                LIMIT %s;
            """

            cur.execute(sql, (query_embedding, query_embedding, top_k))
            rows = cur.fetchall()
            columns = [desc[0] for desc in cur.description]

            results = [dict(zip(columns, row)) for row in rows]

            cur.close()
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