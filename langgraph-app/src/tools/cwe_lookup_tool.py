import os
from typing import Dict, Any, List
import psycopg2


class CWELookupTool:
    def __init__(self):
        self.db_config = {
            "host": os.getenv("CVE_DB_HOST", "cve-db-tesis-3"),
            "port": int(os.getenv("CVE_DB_PORT", 5432)),
            "dbname": os.getenv("CVE_DB_NAME", "cve_database"),
            "user": os.getenv("CVE_DB_USER", "cve_user"),
            "password": os.getenv("CVE_DB_PASSWORD", "cve_password"),
        }

    def _get_connection(self):
        return psycopg2.connect(**self.db_config)

    def get_cwe_context(self, cwe_id: str) -> Dict[str, Any]:
        try:
            conn = self._get_connection()
            cur = conn.cursor()

            cur.execute(
                """
                SELECT id, name, description, extended_description, abstraction, status
                FROM cwe
                WHERE id = %s
                """,
                (cwe_id,)
            )
            row = cur.fetchone()

            if not row:
                cur.close()
                conn.close()
                return {
                    "success": False,
                    "error": f"CWE not found: {cwe_id}"
                }

            cwe_data = {
                "id": row[0],
                "name": row[1],
                "description": row[2],
                "extended_description": row[3],
                "abstraction": row[4],
                "status": row[5],
            }

            cur.execute(
                """
                SELECT target_cwe_id, relationship_type, view_id, ordinal, note
                FROM cwe_relationships
                WHERE source_cwe_id = %s
                ORDER BY relationship_type, target_cwe_id
                """,
                (cwe_id,)
            )
            outgoing_relationships = [
                {
                    "target_cwe_id": r[0],
                    "relationship_type": r[1],
                    "view_id": r[2],
                    "ordinal": r[3],
                    "note": r[4],
                }
                for r in cur.fetchall()
            ]

            cur.execute(
                """
                SELECT source_cwe_id, relationship_type, view_id, ordinal, note
                FROM cwe_relationships
                WHERE target_cwe_id = %s
                ORDER BY relationship_type, source_cwe_id
                """,
                (cwe_id,)
            )
            incoming_relationships = [
                {
                    "source_cwe_id": r[0],
                    "relationship_type": r[1],
                    "view_id": r[2],
                    "ordinal": r[3],
                    "note": r[4],
                }
                for r in cur.fetchall()
            ]

            cur.execute(
                """
                SELECT phase, strategy, description
                FROM cwe_mitigations
                WHERE cwe_id = %s
                ORDER BY id
                LIMIT 10
                """,
                (cwe_id,)
            )
            mitigations = [
                {
                    "phase": r[0],
                    "strategy": r[1],
                    "description": r[2],
                }
                for r in cur.fetchall()
            ]

            cur.execute(
                """
                SELECT method_name, method_id, description, effectiveness
                FROM cwe_detection_methods
                WHERE cwe_id = %s
                ORDER BY id
                LIMIT 10
                """,
                (cwe_id,)
            )
            detection_methods = [
                {
                    "method_name": r[0],
                    "method_id": r[1],
                    "description": r[2],
                    "effectiveness": r[3],
                }
                for r in cur.fetchall()
            ]

            cur.close()
            conn.close()

            return {
                "success": True,
                "data": {
                    "cwe": cwe_data,
                    "outgoing_relationships": outgoing_relationships,
                    "incoming_relationships": incoming_relationships,
                    "mitigations": mitigations,
                    "detection_methods": detection_methods,
                }
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }