import os
import json
import asyncio
from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama import ChatOllama
import splunklib.client as client
import splunklib.results as results
from splunklib.binding import HTTPError, AuthenticationError
from tools.velociraptor_tool import run_velociraptor_query

# Load env
load_dotenv()

# Splunk config
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_PORT = int(os.getenv("SPLUNK_PORT", "8089"))
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD")

# Ollama models
# OLLAMA_MODEL is used for SPL generation. Default to custom 'splunk_hunter'.
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "splunk_hunter")
# SUMMARY_MODEL is used for human-friendly summaries. Default to a fluent base model.
SUMMARY_MODEL = os.getenv("SUMMARY_MODEL", "llama3:8b")
# Default index policy
DEFAULT_INDEX = os.getenv("DEFAULT_INDEX", "main")
# Time policy mode: off | normalize | infer
TIME_POLICY_MODE = os.getenv("TIME_POLICY_MODE", "normalize").lower()

app = FastAPI(title="Agentic-Threat-Hunter UI")

# Serve React build
BUILD_DIR = os.path.join(os.path.dirname(__file__), "web", "dist")
if os.path.exists(BUILD_DIR):
    app.mount("/assets", StaticFiles(directory=os.path.join(BUILD_DIR, "assets")), name="assets")

# Serve favicons from project root's favicon_io directory at /favicons
FAVICON_DIR = os.path.join(os.path.dirname(__file__), "favicon_io")
if os.path.isdir(FAVICON_DIR):
    app.mount("/favicons", StaticFiles(directory=FAVICON_DIR), name="favicons")



def _apply_index_policy(question: str, spl: str):
    """Enforce default index policy and return (new_spl, reason_or_None)."""
    q_lower = (question or "").lower()
    wants_internal = ("internal" in q_lower) or ("_internal" in q_lower)

    s = spl.strip()
    s_lower = s.lower()

    import re
    index_pattern = re.compile(r"\bindex\s*=\s*([\w:\-]+)")
    indexes = index_pattern.findall(s_lower)

    # If explicit _internal but question didn't ask for it, rewrite
    if any(ix == "_internal" for ix in indexes) and not wants_internal:
        new = index_pattern.sub(lambda m: f"index={DEFAULT_INDEX}" if m.group(1).lower() == "_internal" else m.group(0), s)
        return new, f"Rewrote index=_internal to index={DEFAULT_INDEX}"

    # If no index provided and generating command is 'search', inject default index
    starts_with_search = s_lower.startswith("search ") or s_lower.startswith("| search ")
    if not indexes and starts_with_search:
        new = re.sub(r"^(\|\s*)?search\s+", lambda m: f"{m.group(0)}index={DEFAULT_INDEX} ", s, count=1, flags=re.IGNORECASE)
        if new != s:
            return new, f"Inserted index={DEFAULT_INDEX} as default"

    return s, None

@app.get("/")
def index():
    # Serve the React SPA
    return FileResponse(os.path.join(BUILD_DIR, "index.html"))


def _connect_splunk():
    return client.connect(
        host=SPLUNK_HOST,
        port=SPLUNK_PORT,
        username=SPLUNK_USERNAME,
        password=SPLUNK_PASSWORD,
    )


def _execute_splunk_search(spl_query: str):
    """Execute SPL query and return list of result records (dicts)."""
    service = _connect_splunk()
    kwargs = {"output_mode": "json"}
    reader = service.jobs.export(spl_query, **kwargs)
    search_results = []
    for r in results.JSONResultsReader(reader):
        # r can include messages; we only collect dict-like rows
        if isinstance(r, dict):
            search_results.append(r)
    return search_results


@app.get("/health/splunk")
def health_splunk():
    """Quick health check for Splunk connectivity and search execution."""
    try:
        # Try a trivial search; don't depend on specific index content.
        q = f"search index={DEFAULT_INDEX} | head 1"
        rows = _execute_splunk_search(q)
        return {
            "connected": True,
            "rows": len(rows),
            "message": "Splunk reachable and search executed",
        }
    except AuthenticationError as e:
        return {
            "connected": False,
            "message": f"Authentication failed: {e}",
        }
    except Exception as e:
        return {
            "connected": False,
            "message": str(e),
        }


@app.get("/health/velociraptor")
def health_velociraptor():
    """Quick health check for Velociraptor via a lightweight VQL."""
    try:
        cfg = os.getenv("VELOCIRAPTOR_CONFIG") or os.path.join(os.getcwd(), "api.config.yaml")
        exists = os.path.isfile(cfg)
        # Minimal query; LIMIT is accepted in VQL; if not, still likely returns quickly.
        vql = "SELECT * FROM pslist() LIMIT 1"
        # Call the underlying function directly, not through the @tool wrapper
        raw = run_velociraptor_query.func(vql, config_path=cfg)
        import json as _json
        try:
            data = _json.loads(raw)
        except Exception:
            return {
                "connected": False,
                "message": f"Non-JSON response from tool: {str(raw)[:200]}",
                "config": cfg,
                "config_exists": exists,
            }
        if isinstance(data, dict) and data.get("error"):
            return {
                "connected": False,
                "message": f"{data.get('error')}: {data.get('message')}",
                "config": cfg,
                "config_exists": exists,
            }
        return {
            "connected": True,
            "rows": len(data) if isinstance(data, list) else 1,
            "message": "Velociraptor reachable and query executed",
            "config": cfg,
            "config_exists": exists,
        }
    except Exception as e:
        cfg_val = os.getenv("VELOCIRAPTOR_CONFIG") or os.path.join(os.getcwd(), "api.config.yaml")
        exists_val = os.path.isfile(cfg_val)
        return {
            "connected": False,
            "message": str(e),
            "config": cfg_val,
            "config_exists": exists_val,
        }


async def _summarize_results(question: str, spl: str, rows: list[dict]) -> str:
    """Use the local LLM to summarize results into a short human-friendly paragraph."""
    try:
        sample = rows[:10]
        prompt = ChatPromptTemplate.from_messages([
            (
                "system",
                "You are a security analyst. Summarize Splunk results for humans. Be concise (2-5 sentences). Mention counts and notable fields/values. Avoid code blocks. Do not include any preamble like 'Here is', 'Here's', 'Summary:', or 'Overview:'. Write the summary sentences directly.",
            ),
            (
                "human",
                """Summarize this Splunk search:
Query: {spl}
Total rows: {count}
Sample (JSON): {sample}
User question: {question}
Write a short, human-friendly summary.""",
            ),
        ])
        # Use summarization model separate from SPL generator
        llm = ChatOllama(model=SUMMARY_MODEL)
        messages = prompt.format_messages(
            spl=spl, count=len(rows), sample=json.dumps(sample)[:4000], question=question
        )
        from starlette.concurrency import run_in_threadpool
        msg = await run_in_threadpool(llm.invoke, messages)
        text = msg.content if hasattr(msg, "content") else str(msg)
        clean = text.strip()
        # Remove common LLM preambles, we'll add our own consistent label in the UI payload
        import re
        clean = re.sub(r"^\s*(here(?:'s| is)\b[^:\n]*:\s*)", "", clean, flags=re.IGNORECASE)
        clean = re.sub(r"^\s*(summary|overview)\s*:\s*", "", clean, flags=re.IGNORECASE)
        return clean
    except Exception as e:
        return f"Summary unavailable: {e}"


def _build_prompt():
    return ChatPromptTemplate.from_messages([
        (
            "system",
                        """You are a Splunk search assistant.
Your job is to output only a valid Splunk SPL query — no explanations, code blocks, or backticks.
Rules:
    Time windows:
    - Use Splunk relative time with earliest=/latest=. Examples: earliest=-5m, earliest=-24h, earliest=-7d latest=now.
    - Do not output non-SPL tokens like timeframe: or end-1d; always convert to earliest=/latest= forms.
Index policy:
- Default to index=main when the user does not specify an index.
- Use index=_internal only if the user explicitly mentions internal logs or _internal.
Examples:
    User: Find login failures
        You: search index=auth sourcetype=secure action=failure earliest=-24h | stats count""",
        ),
        ("human", "{question}"),
    ])


def _build_vql_prompt():
    return ChatPromptTemplate.from_messages([
        (
            "system",
            """You are a Velociraptor VQL assistant. Output only a single valid VQL statement. No explanations, code blocks, or backticks.
Rules:
- Prefer simple, self-contained queries.
Examples:
  - List processes: SELECT * FROM pslist();
  - File metadata: SELECT * FROM stat(filename="C:/Windows/System32/calc.exe");
  - Recent prefetch: SELECT * FROM prefetch();
""",
        ),
        ("human", "{question}"),
    ])


def _route_tool(question: str) -> str:
    """Choose between 'execute_splunk_search' and 'run_velociraptor_query' using an LLM router."""
    router_prompt = ChatPromptTemplate.from_messages([
        (
            "system",
            """
You are a tool router. Choose exactly one tool for the user's request.
Tools:
- execute_splunk_search: Broad log analysis, SIEM queries, time-windowed SPL.
- run_velociraptor_query: Local endpoint forensics (process list, files, registry, live state).

Output EXACTLY one token: execute_splunk_search OR run_velociraptor_query.
""",
        ),
        ("human", "{q}"),
    ])
    llm = ChatOllama(model=SUMMARY_MODEL)
    msg = llm.invoke(router_prompt.format_messages(q=question))
    choice = (getattr(msg, "content", str(msg)) or "").strip()
    return choice if choice in {"execute_splunk_search", "run_velociraptor_query"} else "execute_splunk_search"


def _apply_time_window_policy(question: str, spl: str):
    """Normalize/insert earliest/latest based on natural language like 'last 24 hours'.
    Returns (new_spl, reason_or_None). Conservative heuristic.
    """
    mode = TIME_POLICY_MODE  # off | normalize | infer
    if mode not in {"off", "normalize", "infer"}:
        mode = "normalize"

    s = spl.strip()
    low = s.lower()

    import re
    # Quick convert of common bad tokens like 'timeframe:end-1d' => 'earliest=-1d'
    converted = re.sub(r"timeframe\s*:\s*end-([0-9]+)([dhm])", r"earliest=-\1\2", low)
    if converted != low:
        s = re.sub(r"timeframe\s*:\s*end-([0-9]+)([dhm])", r"earliest=-\1\2", s, flags=re.IGNORECASE)
        return s, "Converted non-SPL timeframe to earliest= syntax"

    # If earliest/latest already present, leave it
    if " earliest=" in low or " latest=" in low:
        return s, None

    # Respect mode
    if mode == "off":
        return s, None

    if mode == "normalize":
        # Only convert invalid tokens; do not infer a window
        return s, None

    # mode == infer
    q = (question or "").lower()
    reason = None
    if "last 24 hours" in q or "past 24 hours" in q or "last day" in q or "past day" in q:
        s += " earliest=-24h"
        reason = "Inserted earliest=-24h for 'last 24 hours'"
    elif "last 5 minutes" in q or "past 5 minutes" in q or "last five minutes" in q:
        s += " earliest=-5m"
        reason = "Inserted earliest=-5m for 'last 5 minutes'"
    elif "last hour" in q or "past hour" in q:
        s += " earliest=-1h"
        reason = "Inserted earliest=-1h for 'last hour'"

    return (s, reason) if reason else (s, None)


@app.websocket("/ws")
async def ws_chat(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            # Expect plain text with the user's question
            question = await websocket.receive_text()

            # 1) Notify start
            await websocket.send_json({
                "type": "activity",
                "title": "Analyzing question",
                "detail": question,
                "status": "running",
                "icon": "search",
            })

            # 2) Route to best tool
            tool_choice = _route_tool(question)
            await websocket.send_json({
                "type": "activity",
                "title": "Tool selected",
                "detail": tool_choice,
                "status": "done",
                "icon": "robot",
            })

            from starlette.concurrency import run_in_threadpool

            if tool_choice == "run_velociraptor_query":
                # Generate VQL
                await websocket.send_json({
                    "type": "activity",
                    "title": "Generating VQL query",
                    "detail": "Asking local LLM (Ollama)",
                    "status": "running",
                    "icon": "robot",
                })
                vql_llm = ChatOllama(model=SUMMARY_MODEL)
                vql_prompt = _build_vql_prompt()
                vql_msg = await run_in_threadpool(vql_llm.invoke, vql_prompt.format_messages(question=question))
                vql_raw = getattr(vql_msg, "content", str(vql_msg))
                vql_query = vql_raw.strip().strip("`\"")
                await websocket.send_json({
                    "type": "activity",
                    "title": "VQL generated",
                    "detail": vql_query,
                    "status": "done",
                    "icon": "code",
                })

                # Execute Velociraptor query
                await websocket.send_json({
                    "type": "activity",
                    "title": "Executing Velociraptor query",
                    "detail": "Querying endpoint via Velociraptor",
                    "status": "running",
                    "icon": "bolt",
                })
                try:
                    raw = await run_in_threadpool(run_velociraptor_query, vql_query)
                    try:
                        results_list = json.loads(raw)
                    except Exception:
                        results_list = [{"raw": raw}]
                    count = len(results_list) if isinstance(results_list, list) else 1
                    await websocket.send_json({
                        "type": "activity",
                        "title": "Search completed",
                        "detail": f"{count} rows returned",
                        "status": "done",
                        "icon": "check",
                    })

                    # Summarize
                    await websocket.send_json({
                        "type": "activity",
                        "title": "Summarizing results",
                        "detail": "Generating human-readable overview",
                        "status": "running",
                        "icon": "robot",
                    })
                    summary_body = await _summarize_results(question, vql_query, results_list if isinstance(results_list, list) else [])
                    formatted_summary = f"Result Summary: {summary_body}" if summary_body else "Result Summary: (no rows)"
                    await websocket.send_json({
                        "type": "activity",
                        "title": "Summary ready",
                        "detail": formatted_summary[:180] + ("…" if len(formatted_summary) > 180 else ""),
                        "status": "done",
                        "icon": "check",
                    })

                    await websocket.send_json({
                        "type": "final",
                        "spl": None,
                        "count": count,
                        "results": results_list if isinstance(results_list, list) else [results_list],
                        "summary": formatted_summary,
                    })
                except Exception as e:
                    await websocket.send_json({
                        "type": "error",
                        "title": "Velociraptor error",
                        "detail": str(e),
                    })
                continue

            # 3) Splunk path: Generate SPL with LLM
            prompt = _build_prompt()
            llm = ChatOllama(model=OLLAMA_MODEL)
            messages = prompt.format_messages(question=question)
            await websocket.send_json({
                "type": "activity",
                "title": "Generating SPL query",
                "detail": "Asking local LLM (Ollama)",
                "status": "running",
                "icon": "robot",
            })
            ai_message = await run_in_threadpool(llm.invoke, messages)
            raw_spl = ai_message.content if hasattr(ai_message, "content") else str(ai_message)

            # Extract SPL from potential few-shot patterns like "SPL: <query>" and strip backticks
            import re
            def _extract_spl_text(text: str) -> str:
                t = text.strip()
                # If backticked, remove code fences
                if t.startswith("```") and t.endswith("```"):
                    t = t.strip("`").strip()
                # If contains label 'SPL:', capture after it
                m = re.search(r"(?i)\bSPL\s*:\s*(.+)", t, re.DOTALL)
                if m:
                    t = m.group(1).strip()
                # Aggressively remove ALL backticks (single, double, triple) to prevent Splunk macro errors
                t = t.replace("`", "")
                # Remove surrounding quotes
                t = t.strip("\"'")
                return t

            spl = _extract_spl_text(raw_spl)
            await websocket.send_json({
                "type": "activity",
                "title": "SPL generated",
                "detail": spl,
                "status": "done",
                "icon": "code",
            })

            def _normalize_spl(q: str) -> str:
                # Remove triple backtick blocks if present (defensive, already cleaned in extract)
                q = q.strip()
                if q.startswith("```") and q.endswith("```"):
                    q = q.strip("`")
                q = q.strip()
                # Final backtick cleanup to ensure Splunk doesn't see macro syntax artifacts
                q = q.replace("`", "")
                lower = q.lower().lstrip()
                generating = (
                    lower.startswith("search ")
                    or lower.startswith("|")
                    or lower.startswith("from ")
                    or lower.startswith("tstats ")
                    or lower.startswith("mstats ")
                    or lower.startswith("pivot ")
                    or lower.startswith("datamodel ")
                )
                return q if generating else f"search {q}"

            normalized_spl = _normalize_spl(spl)
            if normalized_spl != spl:
                await websocket.send_json({
                    "type": "activity",
                    "title": "SPL normalized for REST API",
                    "detail": normalized_spl,
                    "status": "done",
                    "icon": "code",
                })

            # Apply index policy after normalization
            enforced_spl, policy_reason = _apply_index_policy(question, normalized_spl)
            if policy_reason:
                await websocket.send_json({
                    "type": "activity",
                    "title": "Index policy applied",
                    "detail": policy_reason,
                    "status": "done",
                    "icon": "robot",
                })
                normalized_spl = enforced_spl

            # Apply time-window policy
            time_spl, time_reason = _apply_time_window_policy(question, normalized_spl)
            if time_reason:
                await websocket.send_json({
                    "type": "activity",
                    "title": "Time window applied",
                    "detail": f"{time_reason} (mode={TIME_POLICY_MODE})",
                    "status": "done",
                    "icon": "clock",
                })
                normalized_spl = time_spl

            # Log final SPL for debugging
            await websocket.send_json({
                "type": "activity",
                "title": "Final SPL query to Splunk",
                "detail": normalized_spl,
                "status": "done",
                "icon": "code",
            })

            # 4) Execute Splunk search
            await websocket.send_json({
                "type": "activity",
                "title": "Executing Splunk search",
                "detail": "Running query against Splunk",
                "status": "running",
                "icon": "bolt",
            })
            try:
                results_list = await run_in_threadpool(_execute_splunk_search, normalized_spl)
                count = len(results_list)
                await websocket.send_json({
                    "type": "activity",
                    "title": "Search completed",
                    "detail": f"{count} rows returned",
                    "status": "done",
                    "icon": "check",
                })

                # 5) Summarize
                await websocket.send_json({
                    "type": "activity",
                    "title": "Summarizing results",
                    "detail": "Generating human-readable overview",
                    "status": "running",
                    "icon": "robot",
                })
                summary_body = await _summarize_results(question, normalized_spl, results_list)
                formatted_summary = f"Result Summary: {summary_body}" if summary_body else "Result Summary: (no rows)"
                await websocket.send_json({
                    "type": "activity",
                    "title": "Summary ready",
                    "detail": formatted_summary[:180] + ("…" if len(formatted_summary) > 180 else ""),
                    "status": "done",
                    "icon": "check",
                })

                # 6) Send final payload
                await websocket.send_json({
                    "type": "final",
                    "spl": normalized_spl,
                    "count": count,
                    "results": results_list[:50],  # cap to keep payload small
                    "summary": formatted_summary,
                })
            except AuthenticationError as e:
                await websocket.send_json({
                    "type": "error",
                    "title": "Splunk authentication failed",
                    "detail": str(e),
                })
            except HTTPError as e:
                try:
                    body = e.body.read().decode("utf-8")
                except Exception:
                    body = str(e)
                await websocket.send_json({
                    "type": "error",
                    "title": f"Splunk API Error {e.status} {e.reason}",
                    "detail": body,
                })
            except Exception as e:
                await websocket.send_json({
                    "type": "error",
                    "title": "Unexpected error",
                    "detail": str(e),
                })

    except WebSocketDisconnect:
        return


# Catch-all route for React Router (must be last)
@app.get("/{full_path:path}")
def catch_all(full_path: str):
    # If the requested path doesn't exist as a static file, serve index.html
    # This allows React Router to handle the routing
    file_path = os.path.join(BUILD_DIR, full_path)
    if os.path.isfile(file_path):
        return FileResponse(file_path)
    return FileResponse(os.path.join(BUILD_DIR, "index.html"))


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=True)
