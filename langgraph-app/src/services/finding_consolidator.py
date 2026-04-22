# langgraph-app/src/services/finding_consolidator.py

from typing import Dict, Any, List, Tuple


class FindingConsolidator:
    """
    Consolidates validated findings into issue-level findings.
    Current deterministic strategy:
    - group by (final_cwe_id, file_path)
    - merge evidence and line ranges
    """

    def consolidate(self, validated_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}

        for finding in validated_findings:
            cwe_id = finding.get("final_cwe_id")
            file_path = finding.get("file_path")

            if not cwe_id or not file_path:
                continue

            key = (cwe_id, file_path)
            grouped.setdefault(key, []).append(finding)

        consolidated = []

        for (cwe_id, file_path), items in grouped.items():
            items = sorted(items, key=lambda x: x.get("line_start", 0))

            line_start = min(item.get("line_start", 0) for item in items)
            line_end = max(item.get("line_end", 0) for item in items)

            evidence_items = []
            for item in items:
                evidence_items.append({
                    "line_start": item.get("line_start"),
                    "line_end": item.get("line_end"),
                    "evidence": item.get("evidence")
                })

            representative = items[0]

            consolidated.append({
                "final_cwe_id": cwe_id,
                "final_cwe_name": representative.get("final_cwe_name"),
                "file_path": file_path,
                "line_start": line_start,
                "line_end": line_end,
                "confidence": max(item.get("confidence", 0.0) for item in items),
                "rationale": representative.get("rationale"),
                "mitigation": representative.get("mitigation"),
                "hypothesis_types": sorted(set(item.get("hypothesis_type") for item in items if item.get("hypothesis_type"))),
                "evidence_items": evidence_items,
                "merged_count": len(items)
            })

        consolidated.sort(key=lambda x: (x["file_path"], x["line_start"], x["final_cwe_id"]))

        return {
            "success": True,
            "data": {
                "consolidated_findings": consolidated
            }
        }