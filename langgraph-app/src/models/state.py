# langgraph-app/src/models/state.py

from typing import TypedDict, List, Optional, Dict, Any, Literal


class TraceStep(TypedDict):
    step: str
    detail: str


class RepoSummary(TypedDict, total=False):
    repo_path: str
    top_level_items: List[str]
    total_files: int
    extensions: Dict[str, int]
    sample_files: List[str]


class CandidateFile(TypedDict, total=False):
    file_path: str
    reason: str
    priority: int


class Finding(TypedDict, total=False):
    title: str
    vulnerability_type: str
    cwe_id: Optional[str]
    file_path: str
    line_start: Optional[int]
    line_end: Optional[int]
    evidence: str
    description: str
    confidence: float
    semantic_query: str
    mitigation: str
    related_cves: List[Dict[str, Any]]
    status: Literal["suspected", "validated", "rejected"]


class AnalysisPlan(TypedDict, total=False):
    status: Literal["pending", "running", "completed", "failed"]
    current_stage: str


class AgentState(TypedDict, total=False):
    github_url: str
    repo_id: Optional[str]
    repo_path: Optional[str]

    plan: AnalysisPlan
    current_agent: str

    repo_summary: Optional[RepoSummary]
    project_stack: Dict[str, Any]
    candidate_files: List[CandidateFile]
    target_files: List[str]

    raw_findings: List[Finding]
    validated_findings: List[Finding]
    assessment_results: List[Finding]
    consolidated_findings: List[Finding]

    final_report: Optional[Dict[str, Any]]
    errors: List[str]
    trace: List[TraceStep]

    debug_max_hypotheses: Optional[int]