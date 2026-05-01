# langgraph-app/src/evaluation/run_benchmark_subset.py

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any

import psycopg2
from psycopg2.extras import Json

from src.graph.workflow import MultiAgentWorkflow


DEFAULT_BENCHMARK_JSON = "/app/src/evaluation/owasp_benchmark_java_v1_2.json"
DEFAULT_REPO_URL = "https://github.com/OWASP-Benchmark/BenchmarkJava.git"


def parse_optional_int(value: str | None) -> int | None:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered == "none":
        return None
    return int(lowered)


def parse_optional_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered == "none":
        return None
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    raise ValueError("real-vulnerability must be true, false, or none")


def parse_optional_str(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    if stripped.lower() == "none":
        return None
    return stripped


def get_db_connection():
    return psycopg2.connect(
        host=os.getenv("CVE_DB_HOST", "cve-db-tesis-3"),
        port=os.getenv("CVE_DB_PORT", "5432"),
        dbname=os.getenv("CVE_DB_NAME", "cve_database"),
        user=os.getenv("CVE_DB_USER", "cve_user"),
        password=os.getenv("CVE_DB_PASSWORD", "cve_password"),
    )


def ensure_tables(conn) -> None:
    with conn.cursor() as cur:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS benchmark_runs (
            id BIGSERIAL PRIMARY KEY,
            run_label TEXT NOT NULL,
            benchmark_name TEXT NOT NULL,
            benchmark_version TEXT NOT NULL DEFAULT '',
            repo_url TEXT NOT NULL,
            filters JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (run_label, benchmark_name, benchmark_version, repo_url)
        );
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS benchmark_case_results (
            id BIGSERIAL PRIMARY KEY,
            run_label TEXT NOT NULL,
            benchmark_name TEXT NOT NULL,
            benchmark_version TEXT NOT NULL DEFAULT '',
            repo_url TEXT NOT NULL,
            test_name TEXT NOT NULL,
            category TEXT,
            real_vulnerability BOOLEAN,
            expected_cwe_id TEXT,
            source_file TEXT NOT NULL,
            predicted_cwes JSONB NOT NULL DEFAULT '[]'::jsonb,
            has_prediction BOOLEAN NOT NULL DEFAULT FALSE,
            exact_cwe_match BOOLEAN,
            status TEXT NOT NULL,
            duration_seconds DOUBLE PRECISION,
            error TEXT,
            raw_result JSONB,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (run_label, benchmark_name, benchmark_version, repo_url, test_name)
        );
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_benchmark_case_results_run_label
        ON benchmark_case_results(run_label);
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_benchmark_case_results_category
        ON benchmark_case_results(category);
        """)

        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_benchmark_case_results_real_vulnerability
        ON benchmark_case_results(real_vulnerability);
        """)

    conn.commit()

def load_benchmark_cases(json_path: Path) -> dict[str, Any]:
    with json_path.open("r", encoding="utf-8") as f:
        return json.load(f)

def normalize_optional_cwe(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    if stripped.lower() == "none":
        return None
    upper = stripped.upper()
    if upper.startswith("CWE-"):
        return upper
    return f"CWE-{upper}"

def filter_cases(
    benchmark_data: dict[str, Any],
    category: str | None,
    real_vulnerability: bool | None,
    cwe_id: str | None,
    limit: int | None,
) -> list[dict[str, Any]]:
    cases = benchmark_data.get("cases", [])

    filtered: list[dict[str, Any]] = []
    for case in cases:
        if category is not None and case.get("category") != category:
            continue
        if real_vulnerability is not None and case.get("real_vulnerability") is not real_vulnerability:
            continue
        if cwe_id is not None and case.get("cwe_id") != cwe_id:
            continue
        filtered.append(case)

    if limit is not None:
        filtered = filtered[:limit]

    return filtered


def ensure_run_row(
    conn,
    run_label: str,
    benchmark_name: str,
    benchmark_version: str | None,
    repo_url: str,
    filters: dict[str, Any],
) -> None:
    with conn.cursor() as cur:
        cur.execute("""
        INSERT INTO benchmark_runs (
            run_label, benchmark_name, benchmark_version, repo_url, filters
        )
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (run_label, benchmark_name, benchmark_version, repo_url)
        DO NOTHING;
        """, (
            run_label,
            benchmark_name,
            benchmark_version,
            repo_url,
            Json(filters),
        ))
    conn.commit()


def result_exists(
    conn,
    run_label: str,
    benchmark_name: str,
    benchmark_version: str | None,
    repo_url: str,
    test_name: str,
) -> bool:
    with conn.cursor() as cur:
        cur.execute("""
        SELECT 1
        FROM benchmark_case_results
        WHERE run_label = %s
          AND benchmark_name = %s
          AND benchmark_version = %s
          AND repo_url = %s
          AND test_name = %s
        LIMIT 1;
        """, (
            run_label,
            benchmark_name,
            benchmark_version,
            repo_url,
            test_name,
        ))
        return cur.fetchone() is not None


def store_case_result(
    conn,
    run_label: str,
    benchmark_name: str,
    benchmark_version: str | None,
    repo_url: str,
    case: dict[str, Any],
    predicted_cwes: list[str],
    status: str,
    duration_seconds: float,
    raw_result: dict[str, Any] | None,
    error: str | None,
) -> None:
    expected_cwe_id = case.get("cwe_id")
    has_prediction = len(predicted_cwes) > 0

    if case.get("real_vulnerability") is True:
        exact_cwe_match = expected_cwe_id in predicted_cwes
    elif case.get("real_vulnerability") is False:
        exact_cwe_match = not has_prediction
    else:
        exact_cwe_match = None

    with conn.cursor() as cur:
        cur.execute("""
        INSERT INTO benchmark_case_results (
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
            raw_result
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (run_label, benchmark_name, benchmark_version, repo_url, test_name)
        DO UPDATE SET
            category = EXCLUDED.category,
            real_vulnerability = EXCLUDED.real_vulnerability,
            expected_cwe_id = EXCLUDED.expected_cwe_id,
            source_file = EXCLUDED.source_file,
            predicted_cwes = EXCLUDED.predicted_cwes,
            has_prediction = EXCLUDED.has_prediction,
            exact_cwe_match = EXCLUDED.exact_cwe_match,
            status = EXCLUDED.status,
            duration_seconds = EXCLUDED.duration_seconds,
            error = EXCLUDED.error,
            raw_result = EXCLUDED.raw_result,
            created_at = NOW();
        """, (
            run_label,
            benchmark_name,
            benchmark_version,
            repo_url,
            case.get("test_name"),
            case.get("category"),
            case.get("real_vulnerability"),
            expected_cwe_id,
            case.get("source_file"),
            Json(predicted_cwes),
            has_prediction,
            exact_cwe_match,
            status,
            duration_seconds,
            error,
            Json(raw_result) if raw_result is not None else None,
        ))
    conn.commit()


def summarize_execution(rows: list[dict[str, Any]]) -> dict[str, Any]:
    executed = [r for r in rows if r["status"] == "completed"]
    errors = [r for r in rows if r["status"] == "error"]
    skipped = [r for r in rows if r["status"] == "skipped_existing"]
    interrupted = [r for r in rows if r["status"] == "interrupted"]

    positives = [r for r in executed if r["real_vulnerability"] is True]
    negatives = [r for r in executed if r["real_vulnerability"] is False]

    positive_matches = sum(1 for r in positives if r["exact_cwe_match"] is True)
    negative_clean = sum(1 for r in negatives if r["exact_cwe_match"] is True)

    recall_on_positives = (
        positive_matches / len(positives) if positives else None
    )
    accuracy_on_executed = (
        (positive_matches + negative_clean) / len(executed) if executed else None
    )

    return {
        "executed_cases": len(executed),
        "error_cases": len(errors),
        "interrupted_cases": len(interrupted),
        "skipped_existing_cases": len(skipped),
        "positive_cases_executed": len(positives),
        "negative_cases_executed": len(negatives),
        "positive_exact_matches": positive_matches,
        "negative_clean_cases": negative_clean,
        "recall_on_positives": recall_on_positives,
        "accuracy_on_executed": accuracy_on_executed,
    }

def main() -> None:
    parser = argparse.ArgumentParser(description="Run OWASP Benchmark subset through the workflow and store results.")
    parser.add_argument("--benchmark-json", default=DEFAULT_BENCHMARK_JSON)
    parser.add_argument("--repo-url", default=DEFAULT_REPO_URL)
    parser.add_argument("--category", default="pathtraver")
    parser.add_argument("--real-vulnerability", default="true")
    parser.add_argument("--limit", default="10")
    parser.add_argument("--run-label", required=True)
    parser.add_argument("--force-rerun", action="store_true")
    parser.add_argument("--cwe-id", default="none")

    args = parser.parse_args()

    benchmark_json_path = Path(args.benchmark_json)
    if not benchmark_json_path.exists():
        raise FileNotFoundError(f"Benchmark JSON not found: {benchmark_json_path}")

    category = parse_optional_str(args.category)
    real_vulnerability = parse_optional_bool(args.real_vulnerability)
    limit = parse_optional_int(args.limit)
    cwe_id = normalize_optional_cwe(args.cwe_id)

    benchmark_data = load_benchmark_cases(benchmark_json_path)
    benchmark_name = benchmark_data.get("benchmark_name", "unknown_benchmark")
    benchmark_version = benchmark_data.get("benchmark_version") or ""

    selected_cases = filter_cases(
        benchmark_data=benchmark_data,
        category=category,
        real_vulnerability=real_vulnerability,
        cwe_id=cwe_id,
        limit=limit,
    )

    filters = {
        "category": category,
        "real_vulnerability": real_vulnerability,
        "cwe_id": cwe_id,
        "limit": limit,
    }

    conn = get_db_connection()
    ensure_tables(conn)
    ensure_run_row(
        conn=conn,
        run_label=args.run_label,
        benchmark_name=benchmark_name,
        benchmark_version=benchmark_version,
        repo_url=args.repo_url,
        filters=filters,
    )

    workflow = MultiAgentWorkflow()
    execution_rows: list[dict[str, Any]] = []

    print(f"Selected {len(selected_cases)} benchmark cases")
    print(f"Run label: {args.run_label}")
    print(f"Filters: {json.dumps(filters)}")

    interrupted = False
    current_case: dict[str, Any] | None = None
    current_index: int | None = None
    current_started: float | None = None

    try:
        for idx, case in enumerate(selected_cases, start=1):
            current_case = case
            current_index = idx
            current_started = None

            test_name = case["test_name"]

            if not args.force_rerun and result_exists(
                conn=conn,
                run_label=args.run_label,
                benchmark_name=benchmark_name,
                benchmark_version=benchmark_version,
                repo_url=args.repo_url,
                test_name=test_name,
            ):
                print(f"[{idx}/{len(selected_cases)}] SKIP existing {test_name}")
                execution_rows.append({
                    "test_name": test_name,
                    "status": "skipped_existing",
                    "real_vulnerability": case.get("real_vulnerability"),
                    "exact_cwe_match": None,
                })
                continue

            print(f"[{idx}/{len(selected_cases)}] RUN {test_name} -> {case['source_file']}")
            current_started = time.perf_counter()

            try:
                result = workflow.run(
                    github_url=args.repo_url,
                    target_files=[case["source_file"]],
                )

                consolidated_findings = result.get("consolidated_findings", [])
                predicted_cwes = sorted({
                    finding["final_cwe_id"]
                    for finding in consolidated_findings
                    if finding.get("final_cwe_id")
                })

                duration = time.perf_counter() - current_started

                store_case_result(
                    conn=conn,
                    run_label=args.run_label,
                    benchmark_name=benchmark_name,
                    benchmark_version=benchmark_version,
                    repo_url=args.repo_url,
                    case=case,
                    predicted_cwes=predicted_cwes,
                    status="completed",
                    duration_seconds=duration,
                    raw_result=result,
                    error=None,
                )

                exact_cwe_match = (
                    case.get("cwe_id") in predicted_cwes
                    if case.get("real_vulnerability") is True
                    else len(predicted_cwes) == 0
                )

                execution_rows.append({
                    "test_name": test_name,
                    "status": "completed",
                    "real_vulnerability": case.get("real_vulnerability"),
                    "exact_cwe_match": exact_cwe_match,
                })

                print(
                    f"[{idx}/{len(selected_cases)}] DONE {test_name} "
                    f"expected={case.get('cwe_id')} predicted={predicted_cwes} "
                    f"seconds={duration:.2f}"
                )

            except KeyboardInterrupt:
                interrupted = True
                duration = (
                    time.perf_counter() - current_started
                    if current_started is not None
                    else 0.0
                )

                print(f"\n[{idx}/{len(selected_cases)}] INTERRUPTED {test_name}")

                store_case_result(
                    conn=conn,
                    run_label=args.run_label,
                    benchmark_name=benchmark_name,
                    benchmark_version=benchmark_version,
                    repo_url=args.repo_url,
                    case=case,
                    predicted_cwes=[],
                    status="interrupted",
                    duration_seconds=duration,
                    raw_result=None,
                    error="Interrupted by user",
                )

                execution_rows.append({
                    "test_name": test_name,
                    "status": "interrupted",
                    "real_vulnerability": case.get("real_vulnerability"),
                    "exact_cwe_match": None,
                })

                break

            except Exception as e:
                duration = (
                    time.perf_counter() - current_started
                    if current_started is not None
                    else 0.0
                )

                store_case_result(
                    conn=conn,
                    run_label=args.run_label,
                    benchmark_name=benchmark_name,
                    benchmark_version=benchmark_version,
                    repo_url=args.repo_url,
                    case=case,
                    predicted_cwes=[],
                    status="error",
                    duration_seconds=duration,
                    raw_result=None,
                    error=str(e),
                )

                execution_rows.append({
                    "test_name": test_name,
                    "status": "error",
                    "real_vulnerability": case.get("real_vulnerability"),
                    "exact_cwe_match": None,
                })

                print(f"[{idx}/{len(selected_cases)}] ERROR {test_name}: {e}")

    finally:
        summary = summarize_execution(execution_rows)
        summary["interrupted"] = interrupted
        print("\n=== RUN SUMMARY ===")
        print(json.dumps(summary, indent=2))
        conn.close()

    summary = summarize_execution(execution_rows)
    print(json.dumps(summary, indent=2))

    conn.close()


if __name__ == "__main__":
    main()