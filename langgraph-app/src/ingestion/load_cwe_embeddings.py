# /langgraph-app/src/ingestion/load_cwe_embeddings.py

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

BATCH_SIZE = 50
MAX_RETRIES = 3
MAX_WORKERS = 5

MAX_EMBED_TEXT_CHARS = 7000
MAX_MITIGATIONS = 3
MAX_DETECTIONS = 3


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

            raise Exception(response.text)

        except Exception as e:
            print(f"[RETRY] Attempt {attempt + 1}/{MAX_RETRIES} failed: {e}")
            time.sleep(1)

    raise Exception("Max retries exceeded")


def format_embedding(embedding):
    return "[" + ",".join(map(str, embedding)) + "]"


def truncate_text(text, max_chars=MAX_EMBED_TEXT_CHARS):
    if not text:
        return text
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rsplit(" ", 1)[0] + " ..."


def build_cwe_text_from_row(row):
    cwe_id = row["cwe_id"]
    name = row["name"]
    description = row["description"]
    extended_description = row["extended_description"]
    mitigations = row["mitigations"]
    detections = row["detections"]

    parts = [f"{cwe_id}: {name}"]

    if description:
        parts.append(f"Description: {description}")

    if extended_description:
        parts.append(f"Extended: {extended_description}")

    if mitigations:
        parts.append("Mitigations:")
        for item in mitigations[:MAX_MITIGATIONS]:
            phase = item["phase"]
            strategy = item["strategy"]
            desc = item["description"]

            line = "- "
            if phase:
                line += f"[{phase}] "
            if strategy:
                line += f"({strategy}) "
            line += desc
            parts.append(line)

    if detections:
        parts.append("Detection:")
        for item in detections[:MAX_DETECTIONS]:
            method_name = item["method_name"]
            desc = item["description"]

            line = "- "
            if method_name:
                line += f"{method_name}: "
            if desc:
                line += desc
            parts.append(line)

    content = "\n".join(parts)
    return truncate_text(content, MAX_EMBED_TEXT_CHARS)


def load_cwe_rows(cur):
    cur.execute(
        """
        SELECT id, name, description, extended_description
        FROM cwe
        ORDER BY id
        """
    )
    base_rows = cur.fetchall()

    cwe_rows = []

    for cwe_id, name, description, extended_description in base_rows:
        cur.execute(
            """
            SELECT phase, strategy, description
            FROM cwe_mitigations
            WHERE cwe_id = %s
            ORDER BY id
            LIMIT %s
            """,
            (cwe_id, MAX_MITIGATIONS),
        )
        mitigation_rows = cur.fetchall()

        mitigations = [
            {
                "phase": phase,
                "strategy": strategy,
                "description": desc,
            }
            for phase, strategy, desc in mitigation_rows
        ]

        cur.execute(
            """
            SELECT method_name, description
            FROM cwe_detection_methods
            WHERE cwe_id = %s
            ORDER BY id
            LIMIT %s
            """,
            (cwe_id, MAX_DETECTIONS),
        )
        detection_rows = cur.fetchall()

        detections = [
            {
                "method_name": method_name,
                "description": desc,
            }
            for method_name, desc in detection_rows
        ]

        cwe_rows.append(
            {
                "cwe_id": cwe_id,
                "name": name,
                "description": description,
                "extended_description": extended_description,
                "mitigations": mitigations,
                "detections": detections,
            }
        )

    return cwe_rows


def process_row(row):
    cwe_id = row["cwe_id"]

    try:
        content = build_cwe_text_from_row(row)

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

    cur.execute("TRUNCATE TABLE cwe_embeddings RESTART IDENTITY;")
    conn.commit()

    cwe_rows = load_cwe_rows(cur)
    print(f"Loaded {len(cwe_rows)} CWEs to process")
    print(f"Max text chars: {MAX_EMBED_TEXT_CHARS}")
    print(f"Max mitigations per CWE: {MAX_MITIGATIONS}")
    print(f"Max detections per CWE: {MAX_DETECTIONS}\n")
    print("Starting embedding generation...\n")

    batch = []
    total = 0
    errors = []
    batch_start_time = time.time()
    overall_start = time.time()

    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(process_row, row): row for row in cwe_rows}

            for i, future in enumerate(as_completed(futures), start=1):
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

                    print(f"[COMMITTED] Total: {total} | Batch time: {batch_time:.2f}s\n")

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
    print(f"\n[DONE] Total embeddings stored: {total}")
    print(f"[ERRORS] Total failed CWEs: {len(errors)}")
    print(f"[STATS] Total time: {total_time:.2f}s | Avg: {total_time / max(total, 1):.2f}s per stored embedding")

    if errors:
        print("\nFirst 20 errors:")
        for cwe_id, error in errors[:20]:
            print(f"- {cwe_id}: {error}")


if __name__ == "__main__":
    main()