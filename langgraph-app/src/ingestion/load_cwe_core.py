# /langgraph-app/src/ingestion/load_cwe_core.py

import xml.etree.ElementTree as ET
from pathlib import Path

import psycopg2
from psycopg2.extras import execute_batch

XML_PATH = Path("datasets/cwec_v4.19.1.xml")

DB_CONFIG = {
    "host": "localhost",
    "port": 5433,
    "dbname": "cve_database",
    "user": "cve_user",
    "password": "cve_password",
}


def clean_text(value: str | None) -> str | None:
    if value is None:
        return None
    value = " ".join(value.split())
    return value if value else None


def get_text(elem, tag, ns):
    child = elem.find(f"cwe:{tag}", ns)
    if child is None:
        return None
    return clean_text("".join(child.itertext()))


def parse_ordinal(raw_value: str | None) -> int | None:
    if raw_value is None:
        return None
    raw_value = raw_value.strip()
    if raw_value.isdigit():
        return int(raw_value)
    return None


def build_relationship_note(rel) -> str | None:
    note_parts = []

    raw_ordinal = rel.attrib.get("Ordinal")
    if raw_ordinal and not raw_ordinal.strip().isdigit():
        note_parts.append(f"raw_ordinal={raw_ordinal}")

    chain = rel.attrib.get("Chain_ID")
    if chain:
        note_parts.append(f"chain_id={chain}")

    return "; ".join(note_parts) if note_parts else None


def parse_relationships(ns, weaknesses):
    rows = []
    seen = set()

    for weakness in weaknesses.findall("cwe:Weakness", ns):
        source_id = f"CWE-{weakness.attrib['ID']}"

        rels = weakness.find("cwe:Related_Weaknesses", ns)
        if rels is None:
            continue

        for rel in rels.findall("cwe:Related_Weakness", ns):
            target_id_raw = rel.attrib.get("CWE_ID")
            if not target_id_raw:
                continue

            relationship_type = clean_text(rel.attrib.get("Nature"))
            view_id = clean_text(rel.attrib.get("View_ID"))
            ordinal = parse_ordinal(rel.attrib.get("Ordinal"))
            note = build_relationship_note(rel)

            row = (
                source_id,
                f"CWE-{target_id_raw}",
                relationship_type,
                view_id,
                ordinal,
                note,
            )

            dedupe_key = (
                row[0],
                row[1],
                row[2] if row[2] is not None else "",
                row[3] if row[3] is not None else "",
                row[4] if row[4] is not None else -1,
            )

            if dedupe_key not in seen:
                seen.add(dedupe_key)
                rows.append(row)

    return rows


def parse_mitigations(ns, weaknesses):
    rows = []
    seen = set()

    for weakness in weaknesses.findall("cwe:Weakness", ns):
        cwe_id = f"CWE-{weakness.attrib['ID']}"
        mitigations = weakness.find("cwe:Potential_Mitigations", ns)
        if mitigations is None:
            continue

        for mitigation in mitigations.findall("cwe:Mitigation", ns):
            phase_values = []

            for phase in mitigation.findall("cwe:Phase", ns):
                phase_text = clean_text("".join(phase.itertext()))
                if phase_text:
                    phase_values.append(phase_text)

            phase = " | ".join(phase_values) if phase_values else None
            strategy = get_text(mitigation, "Strategy", ns)
            description = get_text(mitigation, "Description", ns)

            if not description:
                continue

            row = (
                cwe_id,
                phase,
                strategy,
                description,
            )

            dedupe_key = (
                row[0],
                row[1] if row[1] is not None else "",
                row[2] if row[2] is not None else "",
                row[3],
            )

            if dedupe_key not in seen:
                seen.add(dedupe_key)
                rows.append(row)

    return rows


def parse_detection_methods(ns, weaknesses):
    rows = []
    seen = set()

    for weakness in weaknesses.findall("cwe:Weakness", ns):
        cwe_id = f"CWE-{weakness.attrib['ID']}"
        methods = weakness.find("cwe:Detection_Methods", ns)
        if methods is None:
            continue

        for method in methods.findall("cwe:Detection_Method", ns):
            method_id = clean_text(method.attrib.get("Detection_Method_ID"))
            method_name = get_text(method, "Method", ns)
            description = get_text(method, "Description", ns)
            effectiveness = get_text(method, "Effectiveness", ns)

            if not method_name and not description:
                continue

            row = (
                cwe_id,
                method_name,
                method_id,
                description,
                effectiveness,
            )

            dedupe_key = (
                row[0],
                row[1] if row[1] is not None else "",
                row[2] if row[2] is not None else "",
                row[3] if row[3] is not None else "",
                row[4] if row[4] is not None else "",
            )

            if dedupe_key not in seen:
                seen.add(dedupe_key)
                rows.append(row)

    return rows


def parse_all():
    tree = ET.parse(XML_PATH)
    root = tree.getroot()

    ns_uri = root.tag[root.tag.find("{") + 1 : root.tag.find("}")]
    ns = {"cwe": ns_uri}

    weaknesses = root.find("cwe:Weaknesses", ns)
    if weaknesses is None:
        raise RuntimeError("Could not find <Weaknesses> section in XML.")

    cwe_rows = []
    for weakness in weaknesses.findall("cwe:Weakness", ns):
        cwe_rows.append(
            (
                f"CWE-{weakness.attrib['ID']}",
                clean_text(weakness.attrib.get("Name")),
                get_text(weakness, "Description", ns),
                get_text(weakness, "Extended_Description", ns),
                clean_text(weakness.attrib.get("Abstraction")),
                clean_text(weakness.attrib.get("Status")),
            )
        )

    relationship_rows = parse_relationships(ns, weaknesses)
    mitigation_rows = parse_mitigations(ns, weaknesses)
    detection_rows = parse_detection_methods(ns, weaknesses)

    return cwe_rows, relationship_rows, mitigation_rows, detection_rows


def main():
    cwe_rows, relationship_rows, mitigation_rows, detection_rows = parse_all()
    print(f"CWE rows: {len(cwe_rows)}")
    print(f"Relationship rows: {len(relationship_rows)}")
    print(f"Mitigation rows: {len(mitigation_rows)}")
    print(f"Detection rows: {len(detection_rows)}")

    conn = psycopg2.connect(**DB_CONFIG)

    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("TRUNCATE TABLE cwe CASCADE;")

                execute_batch(
                    cur,
                    """
                    INSERT INTO cwe (
                        id,
                        name,
                        description,
                        extended_description,
                        abstraction,
                        status
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    cwe_rows,
                    page_size=200,
                )

                execute_batch(
                    cur,
                    """
                    INSERT INTO cwe_relationships (
                        source_cwe_id,
                        target_cwe_id,
                        relationship_type,
                        view_id,
                        ordinal,
                        note
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    relationship_rows,
                    page_size=500,
                )

                execute_batch(
                    cur,
                    """
                    INSERT INTO cwe_mitigations (
                        cwe_id,
                        phase,
                        strategy,
                        description
                    )
                    VALUES (%s, %s, %s, %s)
                    """,
                    mitigation_rows,
                    page_size=500,
                )

                execute_batch(
                    cur,
                    """
                    INSERT INTO cwe_detection_methods (
                        cwe_id,
                        method_name,
                        method_id,
                        description,
                        effectiveness
                    )
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    detection_rows,
                    page_size=500,
                )

                cur.execute("SELECT COUNT(*) FROM cwe;")
                cwe_count = cur.fetchone()[0]
                print(f"Inserted rows in cwe: {cwe_count}")

                cur.execute("SELECT COUNT(*) FROM cwe_relationships;")
                rel_count = cur.fetchone()[0]
                print(f"Inserted relationships: {rel_count}")

                cur.execute("SELECT COUNT(*) FROM cwe_mitigations;")
                mit_count = cur.fetchone()[0]
                print(f"Inserted mitigations: {mit_count}")

                cur.execute("SELECT COUNT(*) FROM cwe_detection_methods;")
                det_count = cur.fetchone()[0]
                print(f"Inserted detection methods: {det_count}")

    finally:
        conn.close()


if __name__ == "__main__":
    main()