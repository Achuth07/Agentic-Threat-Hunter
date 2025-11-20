from __future__ import annotations

from typing import Literal, Optional, TypedDict, Any, Callable, List
from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, END
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage

from tools.web_tools import web_search, visit_page
from tools.atomic_red_team import AtomicRedTeamTool
from tools.sigma_tool import SigmaTool

class AgentState(TypedDict):
    user_query: str
    tool_choice: Optional[Literal["execute_splunk_search", "run_velociraptor_query", "web_search", "visit_page", "atomic_red_team", "sigma_rule"]]
    spl_query: Optional[str]
    vql_query: Optional[str]
    web_query: Optional[str]
    vql_query: Optional[str]
    web_query: Optional[str]
    web_url: Optional[str]
    atomic_query: Optional[str]
    sigma_query: Optional[str]
    results: Any
    error: Optional[str]
    retry_count: int
    messages: List[BaseMessage]


def build_router_node(model_name: str):
    prompt = ChatPromptTemplate.from_messages([
        (
            "system",
            """
You are a strict Tool Router. Choose exactly ONE tool.

Tools (choose one):
- execute_splunk_search
  Purpose: SIEM/log analytics across historical events. Use for EventID/sourcetype/index queries, dashboards, tstats/mstats, trends over time.

- run_velociraptor_query
  Purpose: Live endpoint forensics and local system state. Use for processes (pslist), services, netstat, users(), info(), filesystem stat/glob, prefetch, registry, autoruns, memory artifacts.

- web_search
  Purpose: General web search for threat intelligence, IOC research, CVE details, or general knowledge. Use when the user asks "who is...", "what is...", "latest news on...", or for external information not in logs/endpoints.

- visit_page
  Purpose: Visit a specific URL to extract its content. Use when the user provides a URL and asks to summarize, read, or analyze it.

- atomic_red_team
   Purpose: Execute Atomic Red Team tests to simulate attacks. Use when the user asks to "run test Txxxx", "simulate attack", "execute atomic test", or "list atomic tests".

- sigma_rule
   Purpose: Search, parse, and convert Sigma detection rules to SPL or VQL. Use when the user asks about "sigma rules", "detection rules", "convert sigma", "list sigma rules", or mentions specific Sigma rule IDs.

Routing rules:
1) Endpoint/system state (processes, listening ports, basic computer info, local users, files, prefetch, registry) -> run_velociraptor_query.
2) Logs/SIEM analytics (EventID, sourcetype, index=, SPL, dashboards, trends) -> execute_splunk_search.
3) Mentions "on host/computer X" for current state -> run_velociraptor_query.
4) Mentions "in Splunk" or uses SPL tokens (index=, tstats, mstats) -> execute_splunk_search.
5) Research questions (e.g., "Who is the CEO of Splunk?", "What is CVE-2024-1234?") -> web_search.
5) Research questions (e.g., "Who is the CEO of Splunk?", "What is CVE-2024-1234?") -> web_search.
6) Requests to read/summarize a URL -> visit_page.
7) Requests to run/list atomic tests/attacks -> atomic_red_team.
8) Requests about Sigma rules, detection rules, or converting Sigma to SPL/VQL -> sigma_rule.

Output format: EXACTLY one of execute_splunk_search OR run_velociraptor_query OR web_search OR visit_page OR atomic_red_team OR sigma_rule (no punctuation or extra words).
""",
        ),
        ("human", "{question}"),
    ])
    llm = ChatOllama(model=model_name)

    async def router(state: AgentState) -> AgentState:
        messages = prompt.format_messages(question=state["user_query"])
        msg = await llm.ainvoke(messages)
        choice = (msg.content or "").strip()
        if choice not in {"execute_splunk_search", "run_velociraptor_query", "web_search", "visit_page", "atomic_red_team", "sigma_rule"}:
            # Fallback to splunk if ambiguous
            choice = "execute_splunk_search"
        return {"tool_choice": choice, "retry_count": 0, "error": None}

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

If you are retrying due to an error, analyze the previous error and fix the query.
""",
        ),
        ("placeholder", "{messages}"),
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

If you are retrying due to an error, analyze the previous error and fix the query.
""",
        ),
        ("placeholder", "{messages}"),
        ("human", "{question}"),
    ])
    
    # Simple pass-through for web search query optimization if needed, 
    # but for now we just use the user query or simple extraction.
    
    atomic_prompt = ChatPromptTemplate.from_messages([
        (
            "system",
            """
You convert a user's request to run an Atomic Red Team test into a JSON string for the tool.
Output ONLY the JSON.
Format:
{{
  "action": "execute_test" | "list_tests",
  "technique_id": "Txxxx" (optional, required for execute_test),
  "test_number": 1 (optional, default to 1 if not specified but implied)
}}

Examples:
- "List atomic tests" -> {{"action": "list_tests"}}
- "Run T1033" -> {{"action": "execute_test", "technique_id": "T1033"}}
- "Execute test 2 of T1003" -> {{"action": "execute_test", "technique_id": "T1003", "test_number": 2}}
""",
        ),
        ("placeholder", "{messages}"),
        ("human", "{question}"),
    ])
    
    sigma_prompt = ChatPromptTemplate.from_messages([
        (
            "system",
            """
You convert a user's request about Sigma rules into a JSON string for the tool.
Output ONLY the JSON.
Format:
{{
  "action": "list_rules" | "get_rule" | "convert_to_spl" | "convert_to_vql" | "search_rules",
  "rule_id": "rule_id_or_filename" (optional, required for get_rule/convert_*),
  "category": "process_creation" (optional, for list_rules),
  "technique_id": "T1055" (optional, for list_rules),
  "query": "search terms" (optional, required for search_rules)
}}

Examples:
- "List sigma rules" -> {{"action": "list_rules"}}
- "Show sigma rules for lateral movement" -> {{"action": "search_rules", "query": "lateral movement"}}
- "Convert sigma rule proc_creation_win_susp_psexec to SPL" -> {{"action": "convert_to_spl", "rule_id": "proc_creation_win_susp_psexec"}}
- "Get details for rule T1055" -> {{"action": "search_rules", "query": "T1055"}}
""",
        ),
        ("placeholder", "{messages}"),
        ("human", "{question}"),
    ])

    spl_llm = ChatOllama(model=spl_model)
    vql_llm = ChatOllama(model=vql_model or spl_model)
    atomic_llm = ChatOllama(model=vql_model or spl_model) # Use same model as VQL/SPL
    sigma_llm = ChatOllama(model=vql_model or spl_model) # Use same model as VQL/SPL

    async def generate(state: AgentState) -> AgentState:
        tool = state.get("tool_choice") or "execute_splunk_search"
        q = state["user_query"]
        history = state.get("messages") or []
        
        if tool == "run_velociraptor_query":
            msg = await vql_llm.ainvoke(vql_prompt.format_messages(question=q, messages=history))
            vql = (msg.content or "").strip().strip("`\"")
            return {"vql_query": vql}
        elif tool == "web_search":
            # For web search, we can just use the user query directly or clean it up.
            # A simple cleanup is often enough.
            return {"web_query": q}
        elif tool == "visit_page":
            # Extract URL from query. Simple heuristic: find http/https.
            import re
            url_match = re.search(r"https?://[^\s]+", q)
            url = url_match.group(0) if url_match else ""
            return {"web_url": url}
        elif tool == "atomic_red_team":
            msg = await atomic_llm.ainvoke(atomic_prompt.format_messages(question=q, messages=history))
            # Clean up json markdown if present
            content = (msg.content or "").strip()
            if content.startswith("```json"):
                content = content[7:]
            if content.endswith("```"):
                content = content[:-3]
            return {"atomic_query": content.strip()}
        elif tool == "sigma_rule":
            msg = await sigma_llm.ainvoke(sigma_prompt.format_messages(question=q, messages=history))
            # Clean up json markdown if present
            content = (msg.content or "").strip()
            if content.startswith("```json"):
                content = content[7:]
            if content.endswith("```"):
                content = content[:-3]
            return {"sigma_query": content.strip()}
        else:
            msg = await spl_llm.ainvoke(spl_prompt.format_messages(question=q, messages=history))
            spl = (msg.content or "").strip().replace("`", "").strip("\"'")
            return {"spl_query": spl}

    return generate


def build_executor_node(
    splunk_execute_fn: Callable[[str], list[dict]],
    velociraptor_fn: Callable[[str], str],
):
    import json
    import asyncio
    import inspect

    async def execute(state: AgentState) -> AgentState:
        tool = state.get("tool_choice") or "execute_splunk_search"
        
        if tool == "web_search":
            q = state.get("web_query") or state["user_query"]
            try:
                # web_search is blocking, run in thread
                res = await asyncio.to_thread(web_search, q)
                return {"results": res, "error": None}
            except Exception as e:
                return {"results": None, "error": f"Web search error: {str(e)}"}
        
        elif tool == "visit_page":
            url = state.get("web_url")
            if not url:
                 return {"results": None, "error": "No URL found in query for visit_page tool."}
            try:
                # visit_page is blocking, run in thread
                content = await asyncio.to_thread(visit_page, url)
                return {"results": content, "error": None}
            except Exception as e:
                return {"results": None, "error": f"Visit page error: {str(e)}"}

        elif tool == "atomic_red_team":
            query = state.get("atomic_query")
            if not query:
                 return {"results": None, "error": "No query generated for atomic_red_team."}
            try:
                art_tool = AtomicRedTeamTool()
                # Run in thread as it may be blocking
                res = await asyncio.to_thread(art_tool._run, query)
                # If the result starts with "Error:", treat it as an error
                if res.startswith("Error:"):
                    return {"results": None, "error": res}
                return {"results": res, "error": None}
            except Exception as e:
                return {"results": None, "error": f"Atomic Red Team error: {str(e)}"}
        
        elif tool == "sigma_rule":
            query = state.get("sigma_query")
            if not query:
                 return {"results": None, "error": "No query generated for sigma_rule."}
            try:
                sigma_tool = SigmaTool()
                # Run in thread as it may be blocking
                res = await asyncio.to_thread(sigma_tool._run, query)
                # Parse the JSON response to check for errors
                try:
                    res_data = json.loads(res)
                    if "error" in res_data:
                        return {"results": None, "error": res_data["error"]}
                except:
                    pass
                return {"results": res, "error": None}
            except Exception as e:
                return {"results": None, "error": f"Sigma tool error: {str(e)}"}

        elif tool == "run_velociraptor_query":
            vql = state.get("vql_query") or "SELECT * FROM pslist();"
            try:
                # Check if velociraptor_fn is async or sync
                if inspect.iscoroutinefunction(velociraptor_fn):
                    raw = await velociraptor_fn(vql)
                else:
                    raw = await asyncio.to_thread(velociraptor_fn, vql)
                try:
                    results = json.loads(raw)
                    # Check for Velociraptor specific error structure
                    if isinstance(results, dict) and "error" in results:
                         return {"results": results, "error": results["error"]}
                except Exception as e:
                    return {"results": [{"raw": raw}], "error": f"JSON Parse Error: {str(e)}"}
                return {"results": results, "error": None}
            except Exception as e:
                return {"results": [], "error": f"Velociraptor execution error: {str(e)}"}
        else:
            spl = state.get("spl_query") or "index=main | head 5"
            try:
                # Check if splunk_execute_fn is async or sync
                if inspect.iscoroutinefunction(splunk_execute_fn):
                    results = await splunk_execute_fn(spl)
                else:
                    results = await asyncio.to_thread(splunk_execute_fn, spl)
                # Check if it returns a string error
                if isinstance(results, str) and ("Error" in results or "Exception" in results):
                     return {"results": [], "error": results}
                return {"results": results, "error": None}
            except Exception as e:
                # Catch any exception from Splunk (HTTPError, AuthenticationError, etc.)
                error_msg = str(e)
                # Extract more readable error from HTTPError if available
                if hasattr(e, 'body'):
                    try:
                        error_msg = e.body.read().decode('utf-8')
                    except:
                        pass
                return {"results": [], "error": f"Splunk execution error: {error_msg}"}

    return execute


def build_validate_node():
    async def validate(state: AgentState) -> AgentState:
        # This node is a pass-through to allow the conditional edge to check state
        # The executor already sets 'error' if it catches one.
        # We could add more complex validation here (e.g. empty results = error?)
        return state
    return validate


def build_reflect_node(model_name: str):
    prompt = ChatPromptTemplate.from_messages([
        (
            "system",
            """
You are a technical assistant helping to fix a failed query.
Analyze the error and the failed query.
Explain what went wrong and provide a hint to the generator to fix it.
Be concise.
""",
        ),
        ("human", "User Query: {question}\nTool: {tool}\nFailed Query: {query}\nError: {error}"),
    ])
    llm = ChatOllama(model=model_name)

    async def reflect(state: AgentState) -> AgentState:
        tool = state.get("tool_choice")
        
        if tool == "web_search":
            query = state.get("web_query")
        elif tool == "visit_page":
            query = state.get("web_url")
        elif tool == "run_velociraptor_query":
            query = state.get("vql_query")
        elif tool == "atomic_red_team":
            query = state.get("atomic_query")
        elif tool == "sigma_rule":
            query = state.get("sigma_query")
        else:
            query = state.get("spl_query")
            
        error = state.get("error")
        
        messages = prompt.format_messages(
            question=state["user_query"],
            tool=tool,
            query=query,
            error=error
        )
        msg = await llm.ainvoke(messages)
        reflection = msg.content
        
        # Update history with the error and reflection to guide the next generation
        current_messages = state.get("messages") or []
        new_messages = current_messages + [
            AIMessage(content=str(query)),
            HumanMessage(content=f"The query failed with error: {error}. \nReflection: {reflection}\nPlease try again with a corrected query.")
        ]
        
        return {
            "messages": new_messages,
            "retry_count": state.get("retry_count", 0) + 1,
            "error": None # Clear error to allow retry
        }

    return reflect


def build_multitool_graph(
    splunk_execute_fn: Callable[[str], list[dict]],
    velociraptor_fn: Callable[[str], str],
    router_model: str,
    spl_model: str,
    vql_model: Optional[str] = None,
    coder_model: Optional[str] = None,
):
    graph = StateGraph(AgentState)
    
    # Use coder model for reflection if provided, otherwise fallback to router/base model
    reflect_model = coder_model or router_model

    router = build_router_node(router_model)
    generator = build_query_generator_node(spl_model, vql_model)
    executor = build_executor_node(splunk_execute_fn, velociraptor_fn)
    validator = build_validate_node()
    reflector = build_reflect_node(reflect_model)

    graph.add_node("tool_router", router)
    graph.add_node("generate_query", generator)
    graph.add_node("execute_tool", executor)
    graph.add_node("validate_node", validator)
    graph.add_node("reflect_node", reflector)

    graph.set_entry_point("tool_router")
    graph.add_edge("tool_router", "generate_query")
    graph.add_edge("generate_query", "execute_tool")
    graph.add_edge("execute_tool", "validate_node")
    
    def should_retry(state: AgentState):
        if state.get("error") and state.get("retry_count", 0) < 2:
            return "reflect_node"
        return END

    graph.add_conditional_edges(
        "validate_node",
        should_retry,
        {
            "reflect_node": "reflect_node",
            END: END
        }
    )
    
    graph.add_edge("reflect_node", "generate_query")

    return graph.compile()
