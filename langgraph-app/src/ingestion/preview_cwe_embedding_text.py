import psycopg2

DB_CONFIG = {
    "host": "localhost",
    "port": 5433,
    "dbname": "cve_database",
    "user": "cve_user",
    "password": "cve_password",
}


def build_cwe_text(cur, cwe_id):
    cur.execute(
        """
        SELECT name, description, extended_description
        FROM cwe
        WHERE id = %s
        """,
        (cwe_id,),
    )
    row = cur.fetchone()
    if not row:
        return None

    name, description, extended = row

    parts = []
    parts.append(f"{cwe_id}: {name}")

    if description:
        parts.append(f"Description: {description}")

    if extended:
        parts.append(f"Extended: {extended}")

    # Mitigations
    cur.execute(
        """
        SELECT phase, strategy, description
        FROM cwe_mitigations
        WHERE cwe_id = %s
        LIMIT 5
        """,
        (cwe_id,),
    )

    mitigations = cur.fetchall()
    if mitigations:
        parts.append("Mitigations:")
        for phase, strategy, desc in mitigations:
            line = "- "
            if phase:
                line += f"[{phase}] "
            if strategy:
                line += f"({strategy}) "
            line += desc
            parts.append(line)

    # Detection methods
    cur.execute(
        """
        SELECT method_name, description
        FROM cwe_detection_methods
        WHERE cwe_id = %s
        LIMIT 5
        """,
        (cwe_id,),
    )

    detections = cur.fetchall()
    if detections:
        parts.append("Detection:")
        for name, desc in detections:
            line = "- "
            if name:
                line += f"{name}: "
            if desc:
                line += desc
            parts.append(line)

    return "\n".join(parts)


def main():
    conn = psycopg2.connect(**DB_CONFIG)

    try:
        with conn:
            with conn.cursor() as cur:
                test_ids = ["CWE-79", "CWE-89", "CWE-22"]

                for cwe_id in test_ids:
                    print("=" * 80)
                    print(build_cwe_text(cur, cwe_id))
                    print()

    finally:
        conn.close()


if __name__ == "__main__":
    main()