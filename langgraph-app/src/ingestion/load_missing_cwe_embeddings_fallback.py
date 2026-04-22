# /langgraph-app/src/ingestion/load_missing_cwe_embeddings_fallback.py

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import psycopg2
import requests
from psycopg2.extras import execute_batch

DB_CONFIG = {
    "host": "localhost",
    "port": 5433,
    "dbname": "cve_database",
    "user": "cve_user",
    "password": "cve_password",
}

OLLAMA_URL = "http://localhost:11434/api/embeddings"
MODEL = "mxbai-embed-large"

BATCH_SIZE = 25
MAX_RETRIES = 5
MAX_WORKERS = 3
MAX_EMBED_TEXT_CHARS = 1800


def get_embedding(text):
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(
                OLLAMA_URL,
                json={"model": MODEL, "prompt": text},
                timeout=180,
            )

            if response.status_code == 200:
                data = response.json()
                return data["embedding"]

            error_text = response.text

            if "context length" in error_text.lower():
                raise RuntimeError(f"CONTEXT_LENGTH_ERROR: {error_text}")

            raise Exception(error_text)

        except RuntimeError:
            raise
        except Exception as e:
            print(f"[RETRY] Attempt {attempt + 1}/{MAX_RETRIES} failed: {e}")
            time.sleep(2)

    raise Exception("Max retries exceeded")


def format_embedding(embedding):
    return "[" + ",".join(map(str, embedding)) + "]"


def truncate_text(text, max_chars=MAX_EMBED_TEXT_CHARS):
    if not text:
        return text
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rsplit(" ", 1)[0] + " ..."


def build_fallback_cwe_text(row):
    cwe_id = row["cwe_id"]
    name = row["name"]
    description = row["description"]
    extended_description = row["extended_description"]

    parts = [f"{cwe_id}: {name}"]

    if description:
        parts.append(f"Description: {description}")

    if extended_description:
        parts.append(f"Extended: {extended_description}")

    return truncate_text("\n".join(parts), MAX_EMBED_TEXT_CHARS)


def load_missing_cwe_rows(cur):
    cur.execute(
        """
        SELECT c.id, c.name, c.description, c.extended_description
        FROM cwe c
        LEFT JOIN cwe_embeddings e
          ON e.cwe_id = c.id
         AND e.chunk_type = 'combined'
         AND e.chunk_index = 0
        WHERE e.cwe_id IS NULL
        ORDER BY c.id
        """
    )

    rows = []
    for cwe_id, name, description, extended_description in cur.fetchall():
        rows.append(
            {
                "cwe_id": cwe_id,
                "name": name,
                "description": description,
                "extended_description": extended_description,
            }
        )
    return rows


def process_row(row):
    cwe_id = row["cwe_id"]

    try:
        content = build_fallback_cwe_text(row)

        if not content or not content.strip():
            return (cwe_id, None, None, None, None, None, "Empty content")

        start = time.time()
        embedding = get_embedding(content)
        elapsed = time.time() - start

        embedding_str = format_embedding(embedding)
        return (cwe_id, "combined", 0, content, embedding_str, elapsed, None)

    except Exception as e:
        return (cwe_id, None, None, None, None, None, str(e))


def flush_batch(conn, batch):
    if not batch:
        return 0

    cur = conn.cursor()
    try:
        execute_batch(
            cur,
            """
            INSERT INTO cwe_embeddings (
                cwe_id,
                chunk_type,
                chunk_index,
                content,
                embedding
            )
            VALUES (%s, %s, %s, %s, %s::vector)
            ON CONFLICT (cwe_id, chunk_type, chunk_index)
            DO UPDATE SET
                content = EXCLUDED.content,
                embedding = EXCLUDED.embedding
            """,
            batch,
            page_size=len(batch),
        )
        conn.commit()
        return len(batch)
    finally:
        cur.close()


def main():
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    missing_rows = load_missing_cwe_rows(cur)
    print(f"Missing CWEs to embed: {len(missing_rows)}")
    print(f"Fallback max text chars: {MAX_EMBED_TEXT_CHARS}\n")

    batch = []
    total = 0
    errors = []
    batch_start_time = time.time()
    overall_start = time.time()

    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(process_row, row): row for row in missing_rows}

            for future in as_completed(futures):
                cwe_id, chunk_type, chunk_index, content, embedding_str, elapsed, error = future.result()

                if error:
                    print(f"[ERROR] {cwe_id}: {error}")
                    errors.append((cwe_id, error))
                    continue

                batch.append((cwe_id, chunk_type, chunk_index, content, embedding_str))
                print(f"[EMBEDDED] {cwe_id} ({elapsed:.2f}s) | Batch: {len(batch)}/{BATCH_SIZE}")

                if len(batch) >= BATCH_SIZE:
                    print(f"\n[COMMIT] Writing batch of {len(batch)} embeddings to DB...")
                    written = flush_batch(conn, batch)
                    batch_time = time.time() - batch_start_time
                    total += written
                    print(f"[COMMITTED] Total written in fallback pass: {total} | Batch time: {batch_time:.2f}s\n")
                    batch.clear()
                    batch_start_time = time.time()

        if batch:
            print(f"\n[FINAL COMMIT] Writing remaining {len(batch)} embeddings...")
            written = flush_batch(conn, batch)
            total += written

    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Committing current batch before exit...")
        if batch:
            written = flush_batch(conn, batch)
            total += written

    finally:
        cur.close()
        conn.close()

    total_time = time.time() - overall_start
    print(f"\n[DONE] Fallback embeddings stored: {total}")
    print(f"[ERRORS] Total failed CWEs in fallback pass: {len(errors)}")
    print(f"[STATS] Total time: {total_time:.2f}s")

    if errors:
        print("\nFirst 20 fallback errors:")
        for cwe_id, error in errors[:20]:
            print(f"- {cwe_id}: {error}")


if __name__ == "__main__":
    main()