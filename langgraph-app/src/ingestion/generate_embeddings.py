import psycopg2
import requests
import time
from psycopg2.extras import execute_batch
from concurrent.futures import ThreadPoolExecutor, as_completed

DB_CONFIG = {
    "host": "localhost",
    "port": 5433,
    "dbname": "cve_database",
    "user": "cve_user",
    "password": "cve_password",
}

OLLAMA_URL = "http://localhost:11434/api/embeddings"
MODEL = "mxbai-embed-large"

BATCH_SIZE = 100
MAX_RETRIES = 3
MAX_WORKERS = 5

# 🔧 Safe truncation limits
MAX_DESC_CHARS = 1500
MAX_CWE_CHARS = 200


def build_text(cwe_text, description):
    cwe_part = (cwe_text or "Unknown CWE")[:MAX_CWE_CHARS]
    desc_part = (description or "")[:MAX_DESC_CHARS]
    return f"{cwe_part}. {desc_part}"


def get_embedding(text):
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(
                OLLAMA_URL,
                json={"model": MODEL, "prompt": text},
                timeout=30,
            )

            if response.status_code == 200:
                return response.json()["embedding"]

            error_text = response.text

            # ❌ Do NOT retry deterministic errors
            if "context length" in error_text.lower():
                raise Exception("INPUT_TOO_LONG")

            raise Exception(error_text)

        except Exception as e:
            if str(e) == "INPUT_TOO_LONG":
                raise e  # propagate immediately

            print(f"[RETRY] Attempt {attempt+1}/{MAX_RETRIES} failed: {e}")
            time.sleep(1)

    raise Exception("Max retries exceeded")


def format_embedding(embedding):
    return "[" + ",".join(map(str, embedding)) + "]"


def process_row(row):
    cve_id, description, cwe_list = row

    try:
        text = build_text(cwe_list, description)

        start = time.time()
        embedding = get_embedding(text)
        elapsed = time.time() - start

        embedding_str = format_embedding(embedding)

        return (cve_id, embedding_str, elapsed, None)

    except Exception as e:
        return (cve_id, None, None, str(e))


def main():
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    cur.execute("""
        SELECT c.id, c.description,
               COALESCE(string_agg(cc.cwe_id, ', '), '') as cwe_list
        FROM cves c
        LEFT JOIN cve_cwe cc ON c.id = cc.cve_id
        WHERE NOT EXISTS (
            SELECT 1 FROM cve_embeddings e WHERE e.cve_id = c.id
        )
        AND LENGTH(c.description) <= 1500
        GROUP BY c.id, c.description
    """)

    rows = cur.fetchall()
    print(f"Loaded {len(rows)} CVEs to process\n")

    batch = []
    total = 0
    batch_start_time = time.time()
    overall_start = time.time()

    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(process_row, row): row for row in rows}

            for future in as_completed(futures):
                cve_id, embedding_str, elapsed, error = future.result()

                if error:
                    print(f"[ERROR] {cve_id}: {error}")
                    continue  # ✅ do NOT stop pipeline

                batch.append((cve_id, embedding_str))

                print(f"[EMBEDDED] {cve_id} ({elapsed:.2f}s) | Batch: {len(batch)}/{BATCH_SIZE}")

                if len(batch) >= BATCH_SIZE:
                    print(f"\n[COMMIT] Writing batch of {len(batch)} embeddings to DB...")

                    execute_batch(
                        conn.cursor(),
                        """
                        INSERT INTO cve_embeddings (cve_id, embedding)
                        VALUES (%s, %s::vector)
                        ON CONFLICT (cve_id) DO NOTHING
                        """,
                        batch,
                    )
                    conn.commit()

                    batch_time = time.time() - batch_start_time
                    total += len(batch)

                    print(f"[COMMITTED] Total: {total} | Batch time: {batch_time:.2f}s\n")

                    batch.clear()
                    batch_start_time = time.time()

        # Final flush
        if batch:
            print(f"\n[FINAL COMMIT] Writing remaining {len(batch)} embeddings...")

            execute_batch(
                conn.cursor(),
                """
                INSERT INTO cve_embeddings (cve_id, embedding)
                VALUES (%s, %s::vector)
                ON CONFLICT (cve_id) DO NOTHING
                """,
                batch,
            )
            conn.commit()

            total += len(batch)

    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Committing current batch before exit...")

        if batch:
            execute_batch(
                conn.cursor(),
                """
                INSERT INTO cve_embeddings (cve_id, embedding)
                VALUES (%s, %s::vector)
                ON CONFLICT (cve_id) DO NOTHING
                """,
                batch,
            )
            conn.commit()
            total += len(batch)

    finally:
        cur.close()
        conn.close()

    total_time = time.time() - overall_start
    print(f"\n[DONE] Total embeddings stored: {total}")
    print(f"[STATS] Total time: {total_time:.2f}s | Avg: {total_time/max(total,1):.2f}s per CVE")


if __name__ == "__main__":
    main()