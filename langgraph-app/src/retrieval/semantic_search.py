import psycopg2
import requests

DB_CONFIG = {
    "host": "localhost",
    "port": 5433,
    "dbname": "cve_database",
    "user": "cve_user",
    "password": "cve_password",
}

OLLAMA_URL = "http://localhost:11434/api/embeddings"
MODEL = "mxbai-embed-large"


def get_embedding(text):
    response = requests.post(
        OLLAMA_URL,
        json={"model": MODEL, "prompt": text},
    )

    if response.status_code != 200:
        raise Exception(f"Ollama error: {response.text}")

    return response.json()["embedding"]


def format_embedding(embedding):
    return "[" + ",".join(map(str, embedding)) + "]"


def semantic_search(query, top_k=5):
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    print(f"Generating embedding for query: {query}")
    query_embedding = get_embedding(query)
    query_embedding_str = format_embedding(query_embedding)

    print("Searching similar CVEs...")

    cur.execute(
        """
        SELECT 
            c.id, 
            c.description, 
            c.severity,
            e.embedding <-> %s::vector AS distance
        FROM cve_embeddings e
        JOIN cves c ON c.id = e.cve_id
        ORDER BY distance
        LIMIT %s;
        """,
        (query_embedding_str, top_k),
    )

    results = cur.fetchall()

    cur.close()
    conn.close()

    return results


def main():
    query = "privilege escalation linux"

    results = semantic_search(query)

    print("\nTop results:\n")

    for r in results:
        cve_id, desc, severity, distance = r

        print(f"CVE: {cve_id}")
        print(f"Severity: {severity}")
        print(f"Distance: {distance:.4f}")
        print(f"Description: {desc[:200]}")
        print("-" * 50)


if __name__ == "__main__":
    main()