# langgraph-app/src/models/state.py

from typing import List, Optional, TypedDict, Literal, Dict, Any


class Message(TypedDict):
    role: Literal["user", "assistant", "system", "tool"]
    content: str
    tool_name: Optional[str]
    tool_result: Optional[str]


class Plan(TypedDict):
    intent: Literal["query_db", "chat"]
    tool: Optional[str]
    status: Literal["pending", "executing", "done"]


class TraceStep(TypedDict):
    step: str
    detail: str


class AgentState(TypedDict):
    # Conversation history
    messages: List[Message]

    # Current active agent
    current_agent: str

    # Structured execution plan
    plan: Optional[Plan]

    # Tool execution
    tool_query: Optional[str]
    tool_result: Optional[Dict[str, Any]]

    # Final output
    final_response: Optional[str]

    # Execution trace (observability)
    trace: Optional[List[TraceStep]]