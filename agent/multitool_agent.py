from __future__ import annotations

from typing import Literal, Optional, TypedDict, Any, Callable
from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, END


class AgentState(TypedDict):
    user_query: str
    tool_choice: Optional[Literal["execute_splunk_search", "run_velociraptor_query"]]
    spl_query: Optional[str]
    vql_query: Optional[str]
    results: Any


def build_router_node(model_name: str):
    prompt = ChatPromptTemplate.from_messages([
        (
            "system",
            """
You are a tool router. Decide which single tool is best for answering the user's question.
Tools:
- execute_splunk_search: Use this for broad SIEM log analysis, trends, alerts, time-windowed log queries.
- run_velociraptor_query: Use this for deep endpoint forensics and local machine state (e.g., list processes, files, registry).

Output EXACTLY one token: execute_splunk_search OR run_velociraptor_query. No punctuation. No extra words.
""",
        ),
        ("human", "{question}"),
    ])
    llm = ChatOllama(model=model_name)

    def router(state: AgentState) -> AgentState:
        messages = prompt.format_messages(question=state["user_query"])
        msg = llm.invoke(messages)
        choice = (msg.content or "").strip()
        if choice not in {"execute_splunk_search", "run_velociraptor_query"}:
            # Fallback to splunk if ambiguous
            choice = "execute_splunk_search"
        return {"tool_choice": choice}

    return router


def build_query_generator_node(spl_model: str, vql_model: Optional[str] = None):
    spl_prompt = ChatPromptTemplate.from_messages([
        (
            "system",
            """
You convert a user's intent into a valid, single-line Splunk SPL. Output ONLY the SPL. No backticks. No prose.
- Default to index=main when no index specified.
- Use earliest=/latest= for time ranges when given.
- Windows Security logs: sourcetype=WinEventLog:Security
- Use proper fields like Account_Name, host or ComputerName (never Computer).
""",
        ),
        ("human", "{question}"),
    ])
    vql_prompt = ChatPromptTemplate.from_messages([
        (
            "system",
            """
You convert a user's endpoint forensics intent into a Velociraptor VQL query. Output ONLY the VQL. No prose.
Examples:
- List processes: SELECT * FROM pslist();
- Find file details: SELECT * FROM stat(filename="C:/Windows/System32/calc.exe");
- List recent prefetch: SELECT * FROM prefetch();
""",
        ),
        ("human", "{question}"),
    ])
    spl_llm = ChatOllama(model=spl_model)
    vql_llm = ChatOllama(model=vql_model or spl_model)

    def generate(state: AgentState) -> AgentState:
        tool = state.get("tool_choice") or "execute_splunk_search"
        q = state["user_query"]
        if tool == "run_velociraptor_query":
            msg = vql_llm.invoke(vql_prompt.format_messages(question=q))
            vql = (msg.content or "").strip().strip("`\"")
            return {"vql_query": vql}
        else:
            msg = spl_llm.invoke(spl_prompt.format_messages(question=q))
            spl = (msg.content or "").strip().replace("`", "").strip("\"'")
            return {"spl_query": spl}

    return generate


def build_executor_node(
    splunk_execute_fn: Callable[[str], list[dict]],
    velociraptor_fn: Callable[[str], str],
):
    import json

    def execute(state: AgentState) -> AgentState:
        tool = state.get("tool_choice") or "execute_splunk_search"
        if tool == "run_velociraptor_query":
            vql = state.get("vql_query") or "SELECT * FROM pslist();"
            raw = velociraptor_fn(vql)
            try:
                results = json.loads(raw)
            except Exception:
                results = [{"raw": raw}]
            return {"results": results}
        else:
            spl = state.get("spl_query") or "index=main | head 5"
            results = splunk_execute_fn(spl)
            return {"results": results}

    return execute


def build_multitool_graph(
    splunk_execute_fn: Callable[[str], list[dict]],
    velociraptor_fn: Callable[[str], str],
    router_model: str,
    spl_model: str,
    vql_model: Optional[str] = None,
):
    graph = StateGraph(AgentState)
    router = build_router_node(router_model)
    generator = build_query_generator_node(spl_model, vql_model)
    executor = build_executor_node(splunk_execute_fn, velociraptor_fn)

    graph.add_node("tool_router", router)
    graph.add_node("generate_query", generator)
    graph.add_node("execute_tool", executor)

    graph.set_entry_point("tool_router")
    graph.add_edge("tool_router", "generate_query")
    graph.add_edge("generate_query", "execute_tool")
    graph.add_edge("execute_tool", END)

    return graph.compile()
