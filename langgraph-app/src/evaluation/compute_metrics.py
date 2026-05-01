# langgraph-app/src/evaluation/compute_metrics.py

from __future__ import annotations

import argparse
import json
import os
from typing import Any

import psycopg2

CWE_EQUIVALENTS = {
    "CWE-22": {"CWE-22", "CWE-23", "CWE-24", "CWE-25", "CWE-26", "CWE-27", "CWE-28", "CWE-31", "CWE-36"}
}

def is_family_match(expected_cwe_id: str | None, predicted_cwes: list[str] | None) -> bool:
    if not expected_cwe_id or not predicted_cwes:
        return False

    allowed = CWE_EQUIVALENTS.get(expected_cwe_id, {expected_cwe_id})
    return any(pred in allowed for pred in predicted_cwes)

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


def build_where_clause(
    run_labels: list[str],
    category: str | None,
    benchmark_name: str | None,
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

    where_sql = " AND ".join(clauses)
    return where_sql, params


def fetch_rows(
    conn,
    run_labels: list[str],
    category: str | None,
    benchmark_name: str | None,
) -> list[dict[str, Any]]:
    where_sql, params = build_where_clause(run_labels, category, benchmark_name)

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
        created_at
    FROM benchmark_case_results
    WHERE {where_sql}
    ORDER BY run_label, test_name;
    """

    with conn.cursor() as cur:
        cur.execute(sql, params)
        colnames = [desc[0] for desc in cur.description]
        rows = [dict(zip(colnames, row)) for row in cur.fetchall()]

    return rows


def compute_confusion(rows: list[dict[str, Any]], family_aware: bool = False) -> dict[str, int]:
    tp = fp = fn = tn = 0

    for row in rows:
        is_positive = row["real_vulnerability"] is True

        if family_aware:
            match = is_family_match(row["expected_cwe_id"], row["predicted_cwes"])
            if row["real_vulnerability"] is False:
                match = not bool(row["predicted_cwes"])
        else:
            match = row["exact_cwe_match"] is True

        if is_positive and match:
            tp += 1
        elif is_positive and not match:
            fn += 1
        elif (row["real_vulnerability"] is False) and match:
            tn += 1
        elif (row["real_vulnerability"] is False) and not match:
            fp += 1

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
    }

def safe_div(numerator: float, denominator: float) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


def compute_metrics(rows: list[dict[str, Any]], family_aware: bool = False) -> dict[str, Any]:
    confusion = compute_confusion(rows, family_aware=family_aware)
    tp = confusion["tp"]
    fp = confusion["fp"]
    fn = confusion["fn"]
    tn = confusion["tn"]

    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    accuracy = safe_div(tp + tn, tp + fp + fn + tn)
    specificity = safe_div(tn, tn + fp)

    if precision is None or recall is None or (precision + recall) == 0:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall)

    total_completed = len(rows)
    positive_cases = sum(1 for r in rows if r["real_vulnerability"] is True)
    negative_cases = sum(1 for r in rows if r["real_vulnerability"] is False)

    avg_duration = safe_div(
        sum((r["duration_seconds"] or 0.0) for r in rows),
        total_completed,
    )

    return {
        "completed_cases": total_completed,
        "positive_cases": positive_cases,
        "negative_cases": negative_cases,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "specificity": specificity,
        "avg_duration_seconds": avg_duration,
    }


def get_false_positives(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for row in rows:
        if row["real_vulnerability"] is False and row["exact_cwe_match"] is not True:
            out.append({
                "run_label": row["run_label"],
                "test_name": row["test_name"],
                "category": row["category"],
                "expected_cwe_id": row["expected_cwe_id"],
                "predicted_cwes": row["predicted_cwes"],
                "source_file": row["source_file"],
                "duration_seconds": row["duration_seconds"],
            })
    return out


def get_false_negatives(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for row in rows:
        if row["real_vulnerability"] is True and row["exact_cwe_match"] is not True:
            out.append({
                "run_label": row["run_label"],
                "test_name": row["test_name"],
                "category": row["category"],
                "expected_cwe_id": row["expected_cwe_id"],
                "predicted_cwes": row["predicted_cwes"],
                "source_file": row["source_file"],
                "duration_seconds": row["duration_seconds"],
            })
    return out


def print_detail_block(title: str, items: list[dict[str, Any]], limit: int | None) -> None:
    print(f"\n=== {title} ===")
    print(f"count: {len(items)}")

    if limit == 0:
        return

    to_show = items if limit is None else items[:limit]
    print(json.dumps(to_show, indent=2, default=str))


def compute_per_run(rows: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row["run_label"], []).append(row)

    output: dict[str, Any] = {}
    for run_label, group_rows in grouped.items():
        output[run_label] = compute_metrics(group_rows)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Compute benchmark metrics from stored benchmark_case_results.")
    parser.add_argument(
        "--run-labels",
        nargs="+",
        required=True,
        help="One or more run labels. You can pass multiple labels separated by spaces or commas.",
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
        "--show-fp",
        action="store_true",
        help="Show false positives.",
    )
    parser.add_argument(
        "--show-fn",
        action="store_true",
        help="Show false negatives.",
    )
    parser.add_argument(
        "--detail-limit",
        default="20",
        help="How many FP/FN rows to print. Use none for all, 0 for counts only.",
    )
    parser.add_argument(
        "--per-run",
        action="store_true",
        help="Also print metrics broken down by run label.",
    )

    args = parser.parse_args()

    run_labels = parse_run_labels(args.run_labels)

    category = None if args.category is None or args.category.strip().lower() == "none" else args.category.strip()
    benchmark_name = None if args.benchmark_name is None or args.benchmark_name.strip().lower() == "none" else args.benchmark_name.strip()

    if args.detail_limit.strip().lower() == "none":
        detail_limit = None
    else:
        detail_limit = int(args.detail_limit)

    conn = get_db_connection()
    try:
        rows = fetch_rows(
            conn=conn,
            run_labels=run_labels,
            category=category,
            benchmark_name=benchmark_name,
        )

        if not rows:
            print(json.dumps({
                "run_labels": run_labels,
                "category": category,
                "benchmark_name": benchmark_name,
                "message": "No completed rows found."
            }, indent=2))
            return

        summary = {
            "run_labels": run_labels,
            "category": category,
            "benchmark_name": benchmark_name,
            "strict_metrics": compute_metrics(rows, family_aware=False),
            "family_aware_metrics": compute_metrics(rows, family_aware=True),
        }   

        print(json.dumps(summary, indent=2, default=str))

        if args.per_run:
            print("\n=== PER-RUN METRICS ===")
            print(json.dumps(compute_per_run(rows), indent=2, default=str))

        false_positives = get_false_positives(rows)
        false_negatives = get_false_negatives(rows)

        if args.show_fp:
            print_detail_block("FALSE POSITIVES", false_positives, detail_limit)

        if args.show_fn:
            print_detail_block("FALSE NEGATIVES", false_negatives, detail_limit)

    finally:
        conn.close()


if __name__ == "__main__":
    main()