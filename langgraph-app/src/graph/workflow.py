# langgraph-app/src/graph/workflow.py

from langgraph.graph import StateGraph, END
from src.tools.sandbox_clone_tool import SandboxCloneTool
from src.tools.repo_tree_tool import RepoTreeTool
from src.models.state import AgentState
from src.tools.detect_stack_tool import DetectStackTool
from src.tools.select_candidate_files_tool import SelectCandidateFilesTool
from src.tools.suspicious_pattern_tool import SuspiciousPatternTool
from src.services.hypothesis_builder import HypothesisBuilder
from src.tools.read_file_tool import ReadFileTool
from src.tools.cwe_semantic_search_tool import CWESemanticSearchTool
from src.tools.cwe_lookup_tool import CWELookupTool
from src.agents.cwe_validator import CWEValidatorAgent
from src.services.hypothesis_pre_filter import HypothesisPreFilter
from src.services.finding_consolidator import FindingConsolidator

class MultiAgentWorkflow:
    def __init__(self):
        self.graph = self._build_graph()
        self.sandbox_clone_tool = SandboxCloneTool()
        self.repo_tree_tool = RepoTreeTool()
        self.detect_stack_tool = DetectStackTool()
        self.select_candidate_files_tool = SelectCandidateFilesTool()
        self.suspicious_pattern_tool = SuspiciousPatternTool()
        self.hypothesis_builder = HypothesisBuilder()
        self.read_file_tool = ReadFileTool()
        self.cwe_semantic_search_tool = CWESemanticSearchTool()
        self.cwe_lookup_tool = CWELookupTool()
        self.cwe_validator_agent = CWEValidatorAgent()
        self.hypothesis_pre_filter = HypothesisPreFilter()
        self.finding_consolidator = FindingConsolidator()


    def _build_graph(self):
        workflow = StateGraph(AgentState)

        workflow.add_node("intake", self.intake_node)
        workflow.add_node("clone_repo", self.clone_repo_node)
        workflow.add_node("repo_scout", self.repo_scout_node)
        workflow.add_node("reporter", self.reporter_node)
        workflow.add_node("security_scan", self.security_scan_node)
        workflow.add_node("cwe_validate", self.cwe_validate_node)
        workflow.add_node("consolidate_findings", self.consolidate_findings_node)

        workflow.set_entry_point("intake")

        workflow.add_edge("intake", "clone_repo")
        workflow.add_edge("clone_repo", "repo_scout")
        workflow.add_edge("repo_scout", "security_scan")
        workflow.add_edge("security_scan", "cwe_validate")
        workflow.add_edge("cwe_validate", "consolidate_findings")
        workflow.add_edge("consolidate_findings", "reporter")
        workflow.add_edge("reporter", END)

        return workflow.compile()

    def intake_node(self, state: AgentState) -> AgentState:
        self._log("[intake] starting")
        state["current_agent"] = "intake"
        state["plan"] = {
            "status": "running",
            "current_stage": "intake"
        }
        state.setdefault("trace", []).append({
            "step": "intake",
            "detail": f"Initialized analysis for URL: {state.get('github_url', '')}"
        })
        return state

    def clone_repo_node(self, state: AgentState) -> AgentState:
        self._log("[clone_repo] starting")
        state["current_agent"] = "clone_repo"
        state["plan"]["current_stage"] = "clone_repo"

        self._log(f"[clone_repo] cloning {state['github_url']}")
        result = self.sandbox_clone_tool.clone_repository(state["github_url"])
        self._log(f"[clone_repo] done success={result.get('success')}")

        if not result.get("success"):
            state.setdefault("errors", []).append(result.get("error", "Unknown clone error"))
            state.setdefault("trace", []).append({
                "step": "clone_repo",
                "detail": f"Clone failed: {result.get('error', 'Unknown error')}"
            })
            state["plan"]["status"] = "failed"
            return state

        data = result["data"]
        state["repo_id"] = data.get("repo_id")
        state["repo_path"] = data.get("repo_path")

        state.setdefault("trace", []).append({
            "step": "clone_repo",
            "detail": f"Repository cloned successfully. repo_id={state['repo_id']}, repo_path={state['repo_path']}"
        })

        return state

    def repo_scout_node(self, state: AgentState) -> AgentState:
        self._log("[repo_scout] starting")
        state["current_agent"] = "repo_scout"
        state["plan"]["current_stage"] = "repo_scout"

        repo_path = state.get("repo_path")
        if not repo_path:
            state.setdefault("errors", []).append("Repository path is missing before repo_scout step.")
            state.setdefault("trace", []).append({
                "step": "repo_scout",
                "detail": "Repository scouting failed because repo_path was missing."
            })
            state["plan"]["status"] = "failed"
            return state

        self._log("[repo_scout] inspecting repo tree")
        repo_result = self.repo_tree_tool.inspect_repository(repo_path)
        if not repo_result.get("success"):
            state.setdefault("errors", []).append(repo_result.get("error", "Unknown repo inspection error"))
            state.setdefault("trace", []).append({
                "step": "repo_scout",
                "detail": f"Repository scouting failed: {repo_result.get('error', 'Unknown error')}"
            })
            state["plan"]["status"] = "failed"
            return state

        self._log("[repo_scout] detecting stack")
        stack_result = self.detect_stack_tool.detect(repo_path)
        if not stack_result.get("success"):
            state.setdefault("errors", []).append(stack_result.get("error", "Unknown stack detection error"))
            state.setdefault("trace", []).append({
                "step": "repo_scout",
                "detail": f"Stack detection failed: {stack_result.get('error', 'Unknown error')}"
            })
            state["plan"]["status"] = "failed"
            return state

        self._log("[repo_scout] selecting candidate files")
        candidate_result = self.select_candidate_files_tool.select(
            repo_result["data"],
            stack_result["data"]
        )
        if not candidate_result.get("success"):
            state.setdefault("errors", []).append(candidate_result.get("error", "Unknown candidate selection error"))
            state.setdefault("trace", []).append({
                "step": "repo_scout",
                "detail": f"Candidate selection failed: {candidate_result.get('error', 'Unknown error')}"
            })
            state["plan"]["status"] = "failed"
            return state

        state["repo_summary"] = repo_result["data"]
        state["project_stack"] = stack_result["data"]
        state["candidate_files"] = candidate_result["data"]["candidate_files"]

        state.setdefault("trace", []).append({
            "step": "repo_scout",
            "detail": (
                f"Repository inspected successfully. "
                f"total_files={repo_result['data'].get('total_files', 0)}, "
                f"languages={stack_result['data'].get('languages', [])}, "
                f"candidate_files={len(candidate_result['data'].get('candidate_files', []))}"
            )
        })

        return state

    def reporter_node(self, state: AgentState) -> AgentState:
        self._log("[reporter] starting")
        self._log(f"[reporter] raw_findings={len(state.get('raw_findings', []))} validated_findings={len(state.get('validated_findings', []))}")
        
        state["current_agent"] = "reporter"
        state["plan"]["current_stage"] = "reporter"
        state["plan"]["status"] = "completed"

        state["final_report"] = {
            "github_url": state.get("github_url"),
            "repo_id": state.get("repo_id"),
            "repo_path": state.get("repo_path"),
            "repo_summary": state.get("repo_summary"),
            "project_stack": state.get("project_stack", {}),
            "candidate_files": state.get("candidate_files", []),
            "raw_findings": state.get("raw_findings", []),
            "validated_findings": state.get("validated_findings", []),
            "assessment_results" : state.get("assessment_results", []),
            "consolidated_findings": state.get("consolidated_findings", []),
            "errors": state.get("errors", []),
            "trace": state.get("trace", [])
        }

        state.setdefault("trace", []).append({
            "step": "reporter",
            "detail": "Generated placeholder final report."
        })

        return state
    
    def security_scan_node(self, state: AgentState) -> AgentState:
        self._log("[security_scan] starting")
        self._log(f"[security_scan] candidate_files={len(state.get('candidate_files', []))}")
        state["current_agent"] = "security_scan"
        state["plan"]["current_stage"] = "security_scan"

        repo_path = state.get("repo_path")
        candidate_files = state.get("candidate_files", [])

        if not repo_path:
            state.setdefault("errors", []).append("Repository path is missing before security_scan step.")
            state.setdefault("trace", []).append({
                "step": "security_scan",
                "detail": "Security scan failed because repo_path was missing."
            })
            state["plan"]["status"] = "failed"
            return state

        result = self.suspicious_pattern_tool.scan_files(repo_path, candidate_files)

        if not result.get("success"):
            state.setdefault("errors", []).append(result.get("error", "Unknown security scan error"))
            state.setdefault("trace", []).append({
                "step": "security_scan",
                "detail": f"Security scan failed: {result.get('error', 'Unknown error')}"
            })
            state["plan"]["status"] = "failed"
            return state

        state["raw_findings"] = result["data"]["matches"]

        state.setdefault("trace", []).append({
            "step": "security_scan",
            "detail": f"Security scan completed. raw_matches={len(result['data'].get('matches', []))}"
        })

        return state

    def cwe_validate_node(self, state: AgentState) -> AgentState:
        self._log("[cwe_validate] starting")
        state["current_agent"] = "cwe_validate"
        state["plan"]["current_stage"] = "cwe_validate"

        raw_findings = state.get("raw_findings", [])
        repo_id = state.get("repo_id")
        project_stack = state.get("project_stack", {})

        self._log(f"[cwe_validate] raw_findings={len(raw_findings)}")
        self._log(f"[cwe_validate] repo_id={repo_id}")

        if not repo_id:
            self._log("[cwe_validate] failed: repo_id missing")
            state.setdefault("errors", []).append("repo_id is missing before cwe_validate step.")
            state.setdefault("trace", []).append({
                "step": "cwe_validate",
                "detail": "Validation failed because repo_id was missing."
            })
            state["plan"]["status"] = "failed"
            return state

        self._log("[cwe_validate] building hypotheses")
        hypotheses_result = self.hypothesis_builder.build(raw_findings)

        if not hypotheses_result.get("success"):
            self._log("[cwe_validate] failed: hypothesis building failed")
            state.setdefault("errors", []).append("Hypothesis building failed.")
            state.setdefault("trace", []).append({
                "step": "cwe_validate",
                "detail": "Hypothesis building failed."
            })
            state["plan"]["status"] = "failed"
            return state

        hypotheses = hypotheses_result["data"]["hypotheses"]
        validated_findings = []
        assessment_results = []

        ######################## TEST PURPOSES ONLY ########################
        debug_max = state.get("debug_max_hypotheses")
        if debug_max is not None:
            self._log(f"[cwe_validate] debug_max_hypotheses={debug_max}")
            hypotheses = hypotheses[:debug_max]
        ######################## TEST PURPOSES ONLY ########################

        self._log(f"[cwe_validate] hypotheses={len(hypotheses)}")

        for i, hypothesis in enumerate(hypotheses, start=1):
            file_path = hypothesis["file_path"]
            line_start = hypothesis["line_start"]
            line_end = hypothesis["line_end"]

            self._log(
                f"[cwe_validate] hypothesis {i}/{len(hypotheses)} "
                f"type={hypothesis['hypothesis_type']} "
                f"file={file_path} line={line_start}"
            )

            self._log("[cwe_validate] reading local code context")
            context_result = self.read_file_tool.read_file(
                f"/repos/{repo_id}/{file_path}",
                start_line=max(1, line_start - 8),
                end_line=line_end + 8
            )

            if not context_result.get("success"):
                self._log(f"[cwe_validate] skipped: failed reading context for {file_path}:{line_start}")
                continue

            code_context = context_result["data"]["content"]
            self._log(
                f"[cwe_validate] context loaded "
                f"lines={context_result['data'].get('start_line')}-{context_result['data'].get('end_line')}"
            )

            # ========================
            # PRE-FILTER GOES HERE
            # ========================
            self._log("[cwe_validate] running hypothesis pre-filter")
            prefilter_result = self.hypothesis_pre_filter.should_validate(hypothesis, code_context)
            self._log(
                f"[cwe_validate] prefilter should_validate={prefilter_result.get('should_validate')} "
                f"reason={prefilter_result.get('reason')}"
            )

            if not prefilter_result.get("should_validate"):
                prefiltered = {
                    "decision": "rejected",
                    "final_cwe_id": None,
                    "final_cwe_name": None,
                    "confidence": 0.95,
                    "rationale": prefilter_result.get("reason"),
                    "mitigation": None,
                    "decision_source": "pre_filter",
                    "file_path": file_path,
                    "line_start": line_start,
                    "line_end": line_end,
                    "evidence": hypothesis["evidence"],
                    "hypothesis_type": hypothesis["hypothesis_type"]
                }

                assessment_results.append(prefiltered)
                self._log("[cwe_validate] skipped: blocked by pre-filter")
                continue

            query = f"{hypothesis['hypothesis_type']}. {hypothesis['reasoning']} Evidence: {hypothesis['evidence']}"
            self._log("[cwe_validate] retrieving semantic CWE candidates")
            search_result = self.cwe_semantic_search_tool.search(query, top_k=5)

            if not search_result.get("success"):
                self._log("[cwe_validate] skipped: semantic search failed")
                continue

            self._log(f"[cwe_validate] semantic candidates={len(search_result['data'])}")

            candidate_ids = set(hypothesis.get("candidate_cwes", []))
            for row in search_result["data"]:
                candidate_ids.add(row["cwe_id"])

            candidate_ids = sorted(candidate_ids)
            self._log(f"[cwe_validate] candidate_ids={candidate_ids}")

            candidate_contexts = []
            self._log("[cwe_validate] looking up CWE contexts")
            for cwe_id in candidate_ids:
                ctx = self.cwe_lookup_tool.get_cwe_context(cwe_id)
                if ctx.get("success"):
                    candidate_contexts.append(ctx["data"])

            self._log(f"[cwe_validate] loaded_cwe_contexts={len(candidate_contexts)}")

            self._log("[cwe_validate] invoking validator agent")
            validation_result = self.cwe_validator_agent.validate(
                project_stack=project_stack,
                hypothesis=hypothesis,
                code_context=code_context,
                candidate_cwe_contexts=candidate_contexts
            )

            if not validation_result.get("success"):
                self._log("[cwe_validate] skipped: validator agent failed")
                continue

            validated = validation_result["data"]
            decision = validated.get("decision")

            self._log(
                f"[cwe_validate] validator decision={decision} "
                f"cwe={validated.get('final_cwe_id')} "
                f"confidence={validated.get('confidence')}"
            )

            validated["file_path"] = file_path
            validated["line_start"] = line_start
            validated["line_end"] = line_end
            validated["evidence"] = hypothesis["evidence"]
            validated["hypothesis_type"] = hypothesis["hypothesis_type"]

            assessment_results.append(validated)

            if decision == "validated":
                validated_findings.append(validated)

        state["validated_findings"] = validated_findings
        state["assessment_results"] = assessment_results

        self._log(f"[cwe_validate] completed accepted_validated_findings={len(validated_findings)}")

        state.setdefault("trace", []).append({
            "step": "cwe_validate",
            "detail": f"CWE validation completed. accepted_validated_findings={len(validated_findings)}"
        })

        return state

    def consolidate_findings_node(self, state: AgentState) -> AgentState:
        self._log("[consolidate_findings] starting")
        state["current_agent"] = "consolidate_findings"
        state["plan"]["current_stage"] = "consolidate_findings"

        validated_findings = state.get("validated_findings", [])
        self._log(f"[consolidate_findings] validated_findings={len(validated_findings)}")

        result = self.finding_consolidator.consolidate(validated_findings)

        if not result.get("success"):
            self._log("[consolidate_findings] failed")
            state.setdefault("errors", []).append(result.get("error", "Finding consolidation failed."))
            state.setdefault("trace", []).append({
                "step": "consolidate_findings",
                "detail": f"Finding consolidation failed: {result.get('error', 'Unknown error')}"
            })
            state["plan"]["status"] = "failed"
            return state

        consolidated = result["data"]["consolidated_findings"]
        state["consolidated_findings"] = consolidated

        self._log(f"[consolidate_findings] consolidated_findings={len(consolidated)}")

        state.setdefault("trace", []).append({
            "step": "consolidate_findings",
            "detail": f"Finding consolidation completed. consolidated_findings={len(consolidated)}"
        })

        return state
    
    def run(self, github_url: str):
        initial_state: AgentState = {
            "github_url": github_url,
            "repo_id": None,
            "repo_path": None,
            "plan": {
                "status": "pending",
                "current_stage": "not_started"
            },
            "current_agent": "none",
            "repo_summary": None,
            "project_stack": {},
            "candidate_files": [],
            "raw_findings": [],
            "validated_findings": [],
            "final_report": None,
            "errors": [],
            "trace": [],
            "debug_max_hypotheses": None, #############CHANGE TO NONE WHEN YOU WANT TO RUN THE WHOLE THING!!###############
            "assessment_results": [],
            "consolidated_findings": []
        }

        return self.graph.invoke(initial_state)
    
    def _log(self, message: str) -> None:
        print(message, flush=True)