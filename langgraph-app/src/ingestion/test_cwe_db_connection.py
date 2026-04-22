#langgraph-app\src\ingestion\test_cwe_db_connection.py

import psycopg2

conn = psycopg2.connect(
    host="localhost",
    port=5433,
    dbname="cve_database",
    user="cve_user",
    password="cve_password",
)

with conn:
    with conn.cursor() as cur:
        cur.execute("SELECT current_database(), current_user, version();")
        row = cur.fetchone()
        print("DATABASE:", row[0])
        print("USER:", row[1])
        print("POSTGRES VERSION:", row[2])

        cur.execute("SELECT COUNT(*) FROM cwe;")
        count = cur.fetchone()[0]
        print("CURRENT cwe ROW COUNT:", count)

conn.close()