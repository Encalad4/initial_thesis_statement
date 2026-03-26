# langgraph-app/src/ingestion/cve_ingestion.py

import json
import psycopg2
import os

DB_CONFIG = {
    "host": "localhost",
    "port": 5433,
    "dbname": "cve_database",
    "user": "cve_user",
    "password": "cve_password",
}

BATCH_SIZE = 500  # commit every N CVEs


def extract_cve_data(item):
    try:
        cve_id = item["id"]

        # Description (English)
        descriptions = item.get("descriptions", [])
        description = ""
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value", "")
                break

        # Severity
        severity = None
        metrics = item.get("metrics", {})
        if "cvssMetricV31" in metrics:
            severity = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

        # Published date
        published_date = item.get("published", None)

        # CWE extraction
        cwe_list = []
        weaknesses = item.get("weaknesses", [])

        for w in weaknesses:
            for desc in w.get("description", []):
                value = desc.get("value")
                if value and value.startswith("CWE-"):
                    cwe_list.append(value)

        return {
            "cve": (cve_id, description, severity, published_date),
            "cwes": list(set(cwe_list))
        }

    except Exception as e:
        print(f"Error extracting CVE: {e}")
        return None


def main():
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.abspath(os.path.join(
        BASE_DIR,
        "../../../datasets/nvd/nvdcve-2.0-2025.json"
    ))

    print("Resolved path:", file_path)
    print("File exists:", os.path.exists(file_path))

    print("Loading JSON file...")
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    print("Connecting to database...")
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    inserted = 0

    print("Processing CVEs...")

    for vuln in data["vulnerabilities"]:
        item = vuln["cve"]

        extracted = extract_cve_data(item)
        if not extracted:
            continue

        cve_data = extracted["cve"]
        cwe_list = extracted["cwes"]

        try:
            # Insert CVE
            cur.execute(
                """
                INSERT INTO cves (id, description, severity, published_date)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
                """,
                cve_data,
            )

            # Insert CWE and relationships
            for cwe_id in cwe_list:
                cur.execute(
                    """
                    INSERT INTO cwe (id, name)
                    VALUES (%s, %s)
                    ON CONFLICT (id) DO NOTHING
                    """,
                    (cwe_id, cwe_id),
                )

                cur.execute(
                    """
                    INSERT INTO cve_cwe (cve_id, cwe_id)
                    VALUES (%s, %s)
                    ON CONFLICT DO NOTHING
                    """,
                    (cve_data[0], cwe_id),
                )

            inserted += 1

            # ✅ Batch commit
            if inserted % BATCH_SIZE == 0:
                conn.commit()
                print(f"Inserted {inserted} CVEs...")

        except Exception as e:
            print(f"Error inserting {cve_data[0]}: {e}")

    # Final commit
    conn.commit()

    cur.close()
    conn.close()

    print(f"Finished. Total CVEs inserted: {inserted}")


if __name__ == "__main__":
    main()