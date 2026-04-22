import requests
import psycopg2

DB_CONFIG = {
    "host": "localhost",
    "port": 5433,
    "dbname": "cve_database",
    "user": "cve_user",
    "password": "cve_password",
}

OLLAMA_URL = "http://localhost:11434/api/embeddings"
MODEL = "mxbai-embed-large"


def format_embedding(embedding):
    return "[" + ",".join(map(str, embedding)) + "]"


def get_embedding(text):
    response = requests.post(
        OLLAMA_URL,
        json={"model": MODEL, "prompt": text},
        timeout=120,
    )
    response.raise_for_status()
    return response.json()["embedding"]


def run_query(cur, query_text):
    embedding = get_embedding(query_text)
    embedding_str = format_embedding(embedding)

    cur.execute(
        """
        SELECT
            e.cwe_id,
            c.name,
            (e.embedding <=> %s::vector) AS distance
        FROM cwe_embeddings e
        JOIN cwe c ON c.id = e.cwe_id
        ORDER BY e.embedding <=> %s::vector
        LIMIT 10
        """,
        (embedding_str, embedding_str),
    )

    print("=" * 100)
    print("QUERY:", query_text)
    print()

    for cwe_id, name, distance in cur.fetchall():
        print(f"{cwe_id:10} | {distance:.6f} | {name}")


def main():
    queries = [
        "cross site scripting xss untrusted input in html output",
        "sql injection unsanitized user input in database query",
        "path traversal using ../ to access files outside intended directory",
        "command injection shell command built from user input",
    ]

    conn = psycopg2.connect(**DB_CONFIG)

    try:
        with conn:
            with conn.cursor() as cur:
                for query in queries:
                    run_query(cur, query)
                    print()
    finally:
        conn.close()


if __name__ == "__main__":
    main()