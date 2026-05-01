from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


INPUT_CSV = Path("evaluation/expectedresults-1.2.csv")
OUTPUT_JSON = Path("evaluation/owasp_benchmark_java_v1_2.json")


def normalize_bool(value: str) -> bool:
    lowered = value.strip().lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    raise ValueError(f"Unexpected boolean value: {value!r}")


def normalize_cwe(value: str) -> str | None:
    cleaned = value.strip()
    if not cleaned:
        return None

    if cleaned.upper().startswith("CWE-"):
        return cleaned.upper()

    return f"CWE-{cleaned}"


def load_cases(csv_path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)

        if reader.fieldnames is None:
            raise ValueError("CSV file has no header row.")

        # Normalize header names by stripping whitespace
        reader.fieldnames = [name.strip() if name is not None else "" for name in reader.fieldnames]

        cases: list[dict[str, Any]] = []
        skipped_rows: list[dict[str, Any]] = []

        for row_index, row in enumerate(reader, start=2):
            test_name = (row.get("# test name") or "").strip()
            category = (row.get("category") or "").strip()
            real_vulnerability_raw = (row.get("real vulnerability") or "").strip()
            cwe_raw = (row.get("cwe") or "").strip()

            # Skip rows that are clearly not real benchmark case rows
            if not test_name:
                skipped_rows.append({
                    "row_index": row_index,
                    "reason": "missing test_name",
                    "row": row
                })
                continue

            if not real_vulnerability_raw:
                skipped_rows.append({
                    "row_index": row_index,
                    "reason": "missing real_vulnerability",
                    "row": row
                })
                continue

            try:
                case = {
                    "test_name": test_name,
                    "category": category,
                    "real_vulnerability": normalize_bool(real_vulnerability_raw),
                    "cwe_id": normalize_cwe(cwe_raw),
                    "source_file": f"src/main/java/org/owasp/benchmark/testcode/{test_name}.java"
                }
                cases.append(case)

            except Exception as exc:
                skipped_rows.append({
                    "row_index": row_index,
                    "reason": str(exc),
                    "row": row
                })

    return cases, skipped_rows


def build_output(
    cases: list[dict[str, Any]],
    skipped_rows: list[dict[str, Any]],
    source_file: str
) -> dict[str, Any]:
    vulnerable_cases = sum(1 for case in cases if case["real_vulnerability"])
    non_vulnerable_cases = len(cases) - vulnerable_cases

    return {
        "benchmark_name": "OWASP Benchmark Java",
        "benchmark_version": "1.2",
        "source_file": source_file,
        "case_count": len(cases),
        "vulnerable_case_count": vulnerable_cases,
        "non_vulnerable_case_count": non_vulnerable_cases,
        "skipped_row_count": len(skipped_rows),
        "cases": cases,
        "skipped_rows": skipped_rows[:20],  # only keep first 20 for inspection
    }


def main() -> None:
    if not INPUT_CSV.exists():
        raise FileNotFoundError(f"Input CSV not found: {INPUT_CSV}")

    cases, skipped_rows = load_cases(INPUT_CSV)
    output = build_output(cases, skipped_rows, INPUT_CSV.name)

    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_JSON.open("w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"Converted {len(cases)} cases")
    print(f"Skipped {len(skipped_rows)} rows")
    print(f"Output written to: {OUTPUT_JSON}")


if __name__ == "__main__":
    main()