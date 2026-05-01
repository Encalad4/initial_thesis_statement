# langgraph-app/src/evaluation/export_misclassified_cases.py

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

import psycopg2


def get_db_connection():
    return psycopg2.connect(
        host=os.getenv("CVE_DB_HOST", "cve-db-tesis-3"),
        port=os.getenv("CVE_DB_PORT", "5432"),
        dbname=os.getenv("CVE_DB_NAME", "cve_database"),
        user=os.getenv("CVE_DB_USER", "cve_user"),
        password=os.getenv("CVE_DB_PASSWORD", "cve_password"),
    )


def parse_run_labels(values: list[str]) -> list[str]:
    labels: list[str] = []
    for value in values:
        parts = [part.strip() for part in value.split(",") if part.strip()]
        labels.extend(parts)

    unique_labels: list[str] = []
    seen = set()
    for label in labels:
        if label not in seen:
            seen.add(label)
            unique_labels.append(label)

    if not unique_labels:
        raise ValueError("At least one run label must be provided.")

    return unique_labels


def normalize_optional_str(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    if stripped.lower() == "none":
        return None
    return stripped


def build_where_clause(
    run_labels: list[str],
    category: str | None,
    benchmark_name: str | None,
    error_type: str,
) -> tuple[str, list[Any]]:
    clauses = ["status = 'completed'"]
    params: list[Any] = []

    clauses.append("run_label = ANY(%s)")
    params.append(run_labels)

    if category is not None:
        clauses.append("category = %s")
        params.append(category)

    if benchmark_name is not None:
        clauses.append("benchmark_name = %s")
        params.append(benchmark_name)

    if error_type == "fp":
        clauses.append("real_vulnerability = FALSE")
        clauses.append("exact_cwe_match IS NOT TRUE")
    elif error_type == "fn":
        clauses.append("real_vulnerability = TRUE")
        clauses.append("exact_cwe_match IS NOT TRUE")
    elif error_type == "both":
        clauses.append("exact_cwe_match IS NOT TRUE")
    else:
        raise ValueError("error_type must be fp, fn, or both")

    return " AND ".join(clauses), params


def fetch_misclassified_rows(
    conn,
    run_labels: list[str],
    category: str | None,
    benchmark_name: str | None,
    error_type: str,
    limit: int | None,
) -> list[dict[str, Any]]:
    where_sql, params = build_where_clause(run_labels, category, benchmark_name, error_type)

    sql = f"""
    SELECT
        run_label,
        benchmark_name,
        benchmark_version,
        repo_url,
        test_name,
        category,
        real_vulnerability,
        expected_cwe_id,
        source_file,
        predicted_cwes,
        has_prediction,
        exact_cwe_match,
        status,
        duration_seconds,
        error,
        raw_result,
        created_at
    FROM benchmark_case_results
    WHERE {where_sql}
    ORDER BY test_name
    """

    if limit is not None:
        sql += " LIMIT %s"
        params.append(limit)

    with conn.cursor() as cur:
        cur.execute(sql, params)
        colnames = [desc[0] for desc in cur.description]
        rows = [dict(zip(colnames, row)) for row in cur.fetchall()]

    return rows


def classify_row(row: dict[str, Any]) -> str:
    if row["real_vulnerability"] is True and row["exact_cwe_match"] is not True:
        return "false_negative"
    if row["real_vulnerability"] is False and row["exact_cwe_match"] is not True:
        return "false_positive"
    return "other"


def simplify_row(row: dict[str, Any], include_raw_result: bool) -> dict[str, Any]:
    raw_result = row.get("raw_result") or {}

    item = {
        "error_type": classify_row(row),
        "run_label": row["run_label"],
        "test_name": row["test_name"],
        "category": row["category"],
        "real_vulnerability": row["real_vulnerability"],
        "expected_cwe_id": row["expected_cwe_id"],
        "predicted_cwes": row["predicted_cwes"],
        "source_file": row["source_file"],
        "duration_seconds": row["duration_seconds"],
        "has_prediction": row["has_prediction"],
    }

    if include_raw_result:
        item["raw_findings"] = raw_result.get("raw_findings", [])
        item["assessment_results"] = raw_result.get("assessment_results", [])
        item["validated_findings"] = raw_result.get("validated_findings", [])
        item["consolidated_findings"] = raw_result.get("consolidated_findings", [])
        item["trace"] = raw_result.get("trace", [])

    return item


def build_summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    fp_count = sum(1 for item in items if item["error_type"] == "false_positive")
    fn_count = sum(1 for item in items if item["error_type"] == "false_negative")

    return {
        "count": len(items),
        "false_positive_count": fp_count,
        "false_negative_count": fn_count,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Export misclassified benchmark cases from the DB.")
    parser.add_argument(
        "--run-labels",
        nargs="+",
        required=True,
        help="One or more run labels. You can pass multiple labels separated by spaces or commas.",
    )
    parser.add_argument(
        "--error-type",
        default="both",
        choices=["fp", "fn", "both"],
        help="Export false positives, false negatives, or both.",
    )
    parser.add_argument(
        "--category",
        default=None,
        help="Optional category filter, e.g. pathtraver. Use none to disable.",
    )
    parser.add_argument(
        "--benchmark-name",
        default=None,
        help="Optional benchmark_name filter. Use none to disable.",
    )
    parser.add_argument(
        "--limit",
        default="20",
        help="Maximum number of cases to export. Use none for all.",
    )
    parser.add_argument(
        "--include-raw-result",
        action="store_true",
        help="Include raw_result-derived fields like raw_findings, assessment_results, and trace.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional JSON output file path.",
    )

    args = parser.parse_args()

    run_labels = parse_run_labels(args.run_labels)
    category = normalize_optional_str(args.category)
    benchmark_name = normalize_optional_str(args.benchmark_name)

    if args.limit.strip().lower() == "none":
        limit = None
    else:
        limit = int(args.limit)

    conn = get_db_connection()
    try:
        rows = fetch_misclassified_rows(
            conn=conn,
            run_labels=run_labels,
            category=category,
            benchmark_name=benchmark_name,
            error_type=args.error_type,
            limit=limit,
        )

        items = [simplify_row(row, include_raw_result=args.include_raw_result) for row in rows]

        output = {
            "run_labels": run_labels,
            "error_type": args.error_type,
            "category": category,
            "benchmark_name": benchmark_name,
            "summary": build_summary(items),
            "cases": items,
        }

        print(json.dumps(output, indent=2, default=str))

        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("w", encoding="utf-8") as f:
                json.dump(output, f, indent=2, default=str)
            print(f"\nSaved to {output_path}")

    finally:
        conn.close()


if __name__ == "__main__":
    main()