# langgraph-app/src/graph/workflow.py
from langgraph.graph import StateGraph, END
from typing import Literal
from src.models.state import AgentState, Message
from src.agents.orchestrator import Orchestrator
from src.agents.worker import Worker
from src.agents.tool_recognizer import ToolRecognizer

class MultiAgentWorkflow:
    def __init__(self):
        self.orchestrator = Orchestrator()
        self.worker = Worker()
        self.tool_recognizer = ToolRecognizer()
        
        # Build the graph
        self.graph = self._build_graph()
    
    def _build_graph(self):
        workflow = StateGraph(AgentState)
        
        # Add nodes
        workflow.add_node("orchestrator", self.orchestrator_node)
        workflow.add_node("worker", self.worker_node)
        workflow.add_node("tool_recognizer", self.tool_recognizer_node)
        
        # Add edges
        workflow.set_entry_point("orchestrator")
        workflow.add_conditional_edges(
            "orchestrator",
            self.route_from_orchestrator,
            {
                "needs_tool": "worker",
                "direct_response": END
            }
        )
        
        workflow.add_conditional_edges(
            "worker",
            self.route_from_worker,
            {
                "needs_tool_recognition": "tool_recognizer",
                "has_tool_result": "worker",  # Go back to worker to generate response
                "final_response": END
            }
        )
        
        workflow.add_edge("tool_recognizer", "worker")
        
        return workflow.compile()
    
    def orchestrator_node(self, state: AgentState) -> AgentState:
        """Orchestrator processes the query"""
        print("\n=== ORCHESTRATOR NODE ===")
        last_message = state["messages"][-1]["content"]
        print(f"Query: {last_message}")
        
        state["current_agent"] = "orchestrator"
        return state
    
    def worker_node(self, state: AgentState) -> AgentState:
        """Worker handles the main logic"""
        print("\n=== WORKER NODE ===")
        print(f"State at worker entry: need_tool={state.get('need_tool')}")
        print(f"tool_name={state.get('tool_name')}")
        print(f"tool_result={state.get('tool_result')}")
        print(f"final_response={state.get('final_response')}")
        
        last_message = state["messages"][-1]
        query = last_message["content"]
        print(f"Query: {query}")
        
        # If we have a tool name from tool recognizer, execute it
        if state.get("tool_name") and not state.get("tool_result"):
            print("PATH A: Executing tool")
            # Generate SQL query
            sql_query = self.worker.generate_query(query)
            print(f"Generated SQL: {sql_query}")
            state["tool_query"] = sql_query
            
            # Execute tool
            result = self.worker.execute_tool(state["tool_name"], sql_query)
            print(f"Tool result: {result}")
            state["tool_result"] = str(result)
            state["need_tool"] = False
            
            # Add tool message
            state["messages"].append({
                "role": "tool",
                "content": f"Executed {state['tool_name']} with query: {sql_query}",
                "tool_name": state["tool_name"],
                "tool_result": str(result)
            })
        
        # If we have tool result but no final response, generate response
        elif state.get("tool_result") and not state.get("final_response"):
            print("PATH B: Generating response from tool result")
            # Parse tool result
            import ast
            try:
                result_dict = ast.literal_eval(state["tool_result"])
            except:
                result_dict = {"success": False, "error": "Could not parse result"}
            
            # Generate natural language response
            response = self.worker.generate_response(query, result_dict)
            print(f"Generated response: {response}")
            state["final_response"] = response
            
            # Add assistant message
            state["messages"].append({
                "role": "assistant",
                "content": response,
                "tool_name": None,
                "tool_result": None
            })
        
        # If no tool needed but we need to respond directly
        elif state.get("need_tool") is False and not state.get("final_response"):
            print("PATH C: Direct response (no tool needed)")
            # Simple direct response for non-tool queries
            response = f"I understand you're asking: {query}. Let me help you with that."
            state["final_response"] = response
            state["messages"].append({
                "role": "assistant",
                "content": response,
                "tool_name": None,
                "tool_result": None
            })
        
        else:
            print(f"PATH D: No condition met - need_tool={state.get('need_tool')}, final_response={state.get('final_response')}")
        
        state["current_agent"] = "worker"
        return state
    
    def tool_recognizer_node(self, state: AgentState) -> AgentState:
        """Tool recognizer determines which tool to use"""
        print("\n=== TOOL RECOGNIZER NODE ===")
        last_message = state["messages"][-1]["content"]
        print(f"Analyzing query: {last_message}")
        
        # Recognize tool
        tool_name = self.tool_recognizer.recognize(last_message)
        print(f"Tool recognizer result: {tool_name}")
        
        if tool_name != "none":
            state["tool_name"] = tool_name
            state["need_tool"] = True
            print(f"Tool needed: {tool_name}")
            
            # Add system message about tool recognition
            state["messages"].append({
                "role": "system",
                "content": f"Tool recognizer selected: {tool_name}",
                "tool_name": None,
                "tool_result": None
            })
        else:
            state["need_tool"] = False
            print("No tool needed")
            
            state["messages"].append({
                "role": "system",
                "content": "Tool recognizer determined no tool needed",
                "tool_name": None,
                "tool_result": None
            })
        
        state["current_agent"] = "tool_recognizer"
        return state
    
    def route_from_orchestrator(self, state: AgentState) -> Literal["needs_tool", "direct_response"]:
        """Route from orchestrator based on query"""
        print("\n=== ROUTING FROM ORCHESTRATOR ===")
        # For now, always go to worker
        print("Routing to: needs_tool")
        return "needs_tool"
    
    def route_from_worker(self, state: AgentState) -> Literal["needs_tool_recognition", "has_tool_result", "final_response"]:
        """Route from worker based on state"""
        print("\n=== ROUTING FROM WORKER ===")
        print(f"need_tool: {state.get('need_tool')}")
        print(f"tool_name: {state.get('tool_name')}")
        print(f"tool_result: {state.get('tool_result')}")
        print(f"final_response: {state.get('final_response')}")
        
        # If we haven't determined if tool is needed yet
        if state.get("need_tool") is None:
            print("Routing to: needs_tool_recognition")
            return "needs_tool_recognition"
        
        # If we need a tool but don't have a tool name yet
        elif state.get("need_tool") is True and not state.get("tool_name"):
            print("Routing to: needs_tool_recognition")
            return "needs_tool_recognition"
        
        # If we have a tool name but no result yet
        elif state.get("tool_name") and not state.get("tool_result"):
            print("Routing to: has_tool_result (to execute tool)")
            return "has_tool_result"
        
        # If we have tool result but no final response
        elif state.get("tool_result") and not state.get("final_response"):
            print("Routing to: has_tool_result (to generate response)")
            return "has_tool_result"
        
        # If we have final response
        elif state.get("final_response"):
            print("Routing to: final_response")
            return "final_response"
        
        # Default case
        else:
            print("Default routing to: needs_tool_recognition")
            return "needs_tool_recognition"
    
    def run(self, user_input: str) -> str:
        """Run the workflow with user input"""
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
            "need_tool": None,
            "tool_name": None,
            "tool_query": None,
            "tool_result": None,
            "final_response": None
        }
        
        final_state = self.graph.invoke(initial_state)
        print(f"\nFINAL RESPONSE: {final_state.get('final_response', 'No response generated')}")
        return final_state.get("final_response", "No response generated")