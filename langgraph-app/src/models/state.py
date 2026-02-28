# langgraph-app/src/models/state.py
from typing import List, Dict, Any, Optional, TypedDict, Literal
from pydantic import BaseModel

class Message(TypedDict):
    role: Literal["user", "assistant", "system", "tool"]
    content: str
    tool_name: Optional[str]
    tool_result: Optional[str]

class AgentState(TypedDict):
    messages: List[Message]
    current_agent: str
    need_tool: bool
    tool_name: Optional[str]
    tool_query: Optional[str]
    tool_result: Optional[str]
    final_response: Optional[str]