# langgraph-app/src/graph/workflow.py

from langgraph.graph import StateGraph, END
from typing import Literal
from src.models.state import AgentState
from src.agents.orchestrator import Orchestrator
from src.agents.worker import Worker
from src.agents.tool_recognizer import ToolRecognizer
from src.agents.code_analyzer import CodeAnalyzerAgent

class MultiAgentWorkflow:
    def __init__(self):
        self.orchestrator = Orchestrator()
        self.worker = Worker()
        self.tool_recognizer = ToolRecognizer()
        self.code_analyzer = CodeAnalyzerAgent()

        self.graph = self._build_graph()

    def _build_graph(self):
        workflow = StateGraph(AgentState)

        # Nodes
        workflow.add_node("orchestrator", self.orchestrator_node)
        workflow.add_node("planner", self.planner_node)
        workflow.add_node("executor", self.executor_node)
        workflow.add_node("responder", self.responder_node)

        # Entry
        workflow.set_entry_point("orchestrator")

        # Edges
        workflow.add_edge("orchestrator", "planner")

        workflow.add_conditional_edges(
            "planner",
            self.route_from_planner,
            {
                "execute": "executor",
                "respond": "responder"
            }
        )

        workflow.add_edge("executor", "responder")
        workflow.add_edge("responder", END)

        return workflow.compile()

    # =========================
    # NODES
    # =========================

    def orchestrator_node(self, state: AgentState) -> AgentState:
        print("\n=== ORCHESTRATOR ===")

        state["current_agent"] = "orchestrator"

        # Initialize plan
        state["plan"] = {
            "intent": None,
            "tool": None,
            "status": "pending"
        }

        # Initialize trace
        state.setdefault("trace", []).append({
            "step": "orchestrator",
            "detail": "Initialized plan structure"
        })

        return state

    def planner_node(self, state: AgentState) -> AgentState:
        print("\n=== PLANNER ===")

        query = state["messages"][-1]["content"]

        # --- SIMPLE CODE DETECTION ---
        is_code = any(token in query for token in [";", "{", "}", "(", ")", "SELECT", "def ", "function ", "<?php"])

        if is_code:
            state["plan"]["intent"] = "code_analysis"
            state["plan"]["tool"] = "semantic_search"  # still reuse same tool

        else:
            tool_name = self.tool_recognizer.recognize(query)

            if tool_name != "none":
                state["plan"]["intent"] = "query_db"
                state["plan"]["tool"] = tool_name
            else:
                state["plan"]["intent"] = "chat"
                state["plan"]["tool"] = None

        state["current_agent"] = "planner"

        state.setdefault("trace", []).append({
            "step": "planner",
            "detail": f"Intent={state['plan']['intent']}, Tool={state['plan']['tool']}"
        })

        return state


    def executor_node(self, state: AgentState) -> AgentState:
        print("\n=== EXECUTOR ===")

        query = state["messages"][-1]["content"]
        tool_name = state["plan"]["tool"]
        intent = state["plan"]["intent"]

        state["plan"]["status"] = "executing"

        # =========================
        # CASE 1: CODE ANALYSIS
        # =========================
        if intent == "code_analysis":
            print("-> Running Code Analyzer")

            analysis_result = self.code_analyzer.analyze_code(query)

            if not analysis_result["success"]:
                state["tool_result"] = {
                    "success": False,
                    "error": analysis_result["error"]
                }
            else:
                vulnerabilities = analysis_result["data"].get("vulnerabilities", [])

                if not vulnerabilities:
                    state["tool_result"] = {
                        "success": True,
                        "data": [],
                    }
                else:
                    # Take first detected vulnerability (MVP)
                    vuln = vulnerabilities[0]

                    # Build semantic query
                    semantic_query = vuln.get("type", "")

                    print(f"-> Detected vulnerability: {semantic_query}")

                    result = self.worker.execute_tool(tool_name, semantic_query)

                    state["tool_query"] = semantic_query
                    state["tool_result"] = result

        # =========================
        # CASE 2: NORMAL QUERY
        # =========================
        else:
            result = self.worker.execute_tool(tool_name, query)

            state["tool_query"] = query
            state["tool_result"] = result

        state["plan"]["status"] = "done"

        state["messages"].append({
            "role": "tool",
            "content": f"Executed {tool_name}",
            "tool_name": tool_name,
            "tool_result": str(state["tool_result"])
        })

        state["current_agent"] = "executor"

        state.setdefault("trace", []).append({
            "step": "executor",
            "detail": f"Executed {tool_name} with query: {state.get('tool_query')}"
        })

        return state

    def responder_node(self, state: AgentState) -> AgentState:
        print("\n=== RESPONDER ===")

        query = state["messages"][0]["content"]  # original query

        if state.get("tool_result"):
            response = self.worker.generate_response(
                query,
                state["tool_result"]
            )
        else:
            response = self.worker.generate_direct_response(query)

        state["final_response"] = response

        state["messages"].append({
            "role": "assistant",
            "content": response,
            "tool_name": None,
            "tool_result": None
        })

        state["current_agent"] = "responder"

        state.setdefault("trace", []).append({
            "step": "responder",
            "detail": "Generated final response"
        })

        return state

    # =========================
    # ROUTING
    # =========================

    def route_from_planner(self, state: AgentState) -> Literal["execute", "respond"]:
        print("\n=== ROUTING FROM PLANNER ===")

        if state["plan"]["tool"]:
            return "execute"
        return "respond"

    # =========================
    # RUN
    # =========================

    def run(self, user_input: str) -> str:
        print(f"\n{'='*50}")
        print(f"STARTING WORKFLOW FOR: {user_input}")
        print('='*50)

        initial_state = {
            "messages": [{
                "role": "user",
                "content": user_input,
                "tool_name": None,
                "tool_result": None
            }],
            "current_agent": "orchestrator",
            "plan": None,
            "tool_query": None,
            "tool_result": None,
            "final_response": None,
            "trace": []
        }

        final_state = self.graph.invoke(initial_state)

        print("\n=== EXECUTION TRACE ===")
        for step in final_state.get("trace", []):
            print(f"{step['step']}: {step['detail']}")

        return final_state.get("final_response", "No response generated")