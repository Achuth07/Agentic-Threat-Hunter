import os
import json
import asyncio
from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama import ChatOllama
import splunklib.client as client
import splunklib.results as results
from splunklib.binding import HTTPError, AuthenticationError
from tools.velociraptor_tool import run_velociraptor_query
from tools.virustotal_tool import check_virustotal
from agent.multitool_agent import build_multitool_graph

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
# VQL_MODEL is used for Velociraptor VQL generation.
VQL_MODEL = os.getenv("VQL_MODEL", "velociraptor_hunter")
# CODER_MODEL is used for reflection/correction.
CODER_MODEL = os.getenv("CODER_MODEL", "qwen2.5-coder:7b")
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



def _apply_index_policy(question: str, spl: str, default_index: str | None = None):
    """Enforce default index policy and return (new_spl, reason_or_None).
    Allows per-request override of default index.
    """
    default_index = default_index or DEFAULT_INDEX
    q_lower = (question or "").lower()
    wants_internal = ("internal" in q_lower) or ("_internal" in q_lower)

    s = spl.strip()
    s_lower = s.lower()

    import re
    index_pattern = re.compile(r"\bindex\s*=\s*([\w:\-]+)")
    indexes = index_pattern.findall(s_lower)

    # If explicit _internal but question didn't ask for it, rewrite
    if any(ix == "_internal" for ix in indexes) and not wants_internal:
        new = index_pattern.sub(lambda m: f"index={default_index}" if m.group(1).lower() == "_internal" else m.group(0), s)
        return new, f"Rewrote index=_internal to index={default_index}"

    # If no index provided and generating command is 'search', inject default index
    starts_with_search = s_lower.startswith("search ") or s_lower.startswith("| search ")
    if not indexes and starts_with_search:
        new = re.sub(r"^(\|\s*)?search\s+", lambda m: f"{m.group(0)}index={default_index} ", s, count=1, flags=re.IGNORECASE)
        if new != s:
            return new, f"Inserted index={default_index} as default"

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


async def _summarize_results(question: str, query: str, rows: list[dict] | str, tool_name: str, model: str | None = None) -> str:
    """Use the local LLM to summarize results into a short human-friendly paragraph.
    Handles Splunk (list of dicts), Velociraptor (list of dicts), and Web (string).
    """
    try:
        # For web tools, the result is a string, not a list
        if tool_name in ["web_search", "visit_page"]:
            # Web results are already text content
            content = str(rows)[:4000] if rows else "No content available"
            
            prompt = ChatPromptTemplate.from_messages([
                (
                    "system",
                    f"You are a security analyst. Summarize the web content for humans. Be concise (2-5 sentences). Focus on answering the user's question. Avoid code blocks. Do not include any preamble like 'Here is', 'Here's', 'Summary:', or 'Overview:'. Write the summary sentences directly.",
                ),
                (
                    "human",
                    """Summarize this web content:
Query: {query}
Content: {content}
User question: {question}
Write a short, human-friendly summary that answers the question.""",
                ),
            ])
            
            llm = ChatOllama(model=(model or SUMMARY_MODEL))
            messages = prompt.format_messages(
                query=query, content=content, question=question
            )
        else:
            # Splunk/Velociraptor results are lists of dicts
            if isinstance(rows, list):
                sample = rows[:10]
                count_str = str(len(rows))
            else:
                sample = str(rows)[:4000]
                count_str = "N/A"

            prompt = ChatPromptTemplate.from_messages([
                (
                    "system",
                    f"You are a security analyst. Summarize {tool_name} results for humans. Be concise (2-5 sentences). Mention counts and notable fields/values. Avoid code blocks. Do not include any preamble like 'Here is', 'Here's', 'Summary:', or 'Overview:'. Write the summary sentences directly.",
                ),
                (
                    "human",
                    """Summarize this search result:
Query: {query}
Total rows: {count}
Sample: {sample}
User question: {question}
Write a short, human-friendly summary.""",
                ),
            ])
            
            llm = ChatOllama(model=(model or SUMMARY_MODEL))
            messages = prompt.format_messages(
                query=query, count=count_str, sample=json.dumps(sample, default=str)[:4000], question=question
            )
        
        from starlette.concurrency import run_in_threadpool
        msg = await run_in_threadpool(llm.invoke, messages)
        text = msg.content if hasattr(msg, "content") else str(msg)
        clean = text.strip()
        
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
Windows Event Log field mapping:
- For classic Windows Event Logs (Security, System, Application):
  - Use sourcetype=WinEventLog
  - And source="WinEventLog:<Channel>" (e.g., source="WinEventLog:Security")
  - Do NOT use sourcetype="WinEventLog:Security"; the channel belongs in source.
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
- pslist() takes NO parameters. Never use pslist(hostname=...) or similar.
- Never include host-based filters like WHERE Hostname=... or WHERE ComputerName=.... Hostnames mentioned by the user are context only.
- For process listing, prefer: SELECT Name, Pid, Exe FROM pslist() (unless user asks for full details, then use SELECT *).
- Velociraptor executes queries on the endpoint configured in the API config; hostnames mentioned in the question are for context only.
- Do NOT pass hostname or any parameter to pslist().
 - If the user asks for basic information about the computer/system/host, use: SELECT * FROM info().
 - If the user asks for local users/accounts on the machine, use: SELECT * FROM users().
Examples:
  - List processes: SELECT Name, Pid, Exe FROM pslist()
  - List all process details: SELECT * FROM pslist()
    - Basic system info: SELECT * FROM info()
    - Local user accounts: SELECT * FROM users()
  - File metadata: SELECT * FROM stat(filename="C:/Windows/System32/calc.exe")
  - Recent prefetch: SELECT * FROM prefetch()
""",
        ),
        ("human", "{question}"),
    ])


def _sanitize_vql(question: str, vql: str) -> str:
    """Remove disallowed host filters and parameters from VQL to keep queries portable.
    - Strip pslist(...) params to pslist()
    - Remove WHERE predicates that constrain Hostname/ComputerName, regardless of operator (=, ==, LIKE, ILIKE, =~, IN)
      and regardless of position in the predicate list. Preserve other conditions.
    """
    import re
    q = (vql or "").strip()
    # Normalize pslist arguments away
    q = re.sub(r"(?i)pslist\s*\([^)]*\)", "pslist()", q)

    # If there's no WHERE, nothing more to sanitize
    if re.search(r"(?i)\bWHERE\b", q) is None:
        return q

    # Remove any Hostname/ComputerName predicate regardless of operator or quoting.
    # Match the field name, operator, and value (which may be properly quoted, malformed, or unquoted)
    # Value pattern: match either complete quoted strings OR any non-whitespace until space/AND/OR/semicolon/end
    host_predicate = re.compile(
        r"(?i)\b(Hostname|ComputerName)\s*(?:=|==|=~|LIKE|ILIKE|IN)\s*(?:\"[^\"]*\"|'[^']*'|[^\s;]+)",
        re.IGNORECASE
    )

    # Apply repeatedly until no more host predicates remain
    prev = None
    while prev != q:
        prev = q
        q = host_predicate.sub("", q).strip()

    # Tidy up dangling conjunctions and empty WHERE
    # Remove leading AND/OR after WHERE
    q = re.sub(r"(?i)\bWHERE\s+(?:AND|OR)\b", " WHERE ", q)
    # Remove trailing AND/OR before end or semicolon
    q = re.sub(r"(?i)\s+(?:AND|OR)\s*($|;)", r"\1", q)
    # Remove AND/OR that now have nothing after them (between removal and next clause)
    q = re.sub(r"(?i)\s+(?:AND|OR)\s+(?:AND|OR)\b", " AND ", q)
    # Empty WHERE at end
    q = re.sub(r"(?i)\bWHERE\s*($|;)", r"\1", q)
    # Collapse multiple spaces
    q = re.sub(r"\s{2,}", " ", q).strip()
    return q


async def _route_tool(question: str) -> str:
    """Choose between 'execute_splunk_search', 'run_velociraptor_query', and 'check_virustotal'.
    Apply a fast heuristic first; if inconclusive, fall back to an LLM router.
    """
    q = (question or "").lower()
    
    # Priority 1: VirusTotal indicators for threat intel / reputation checks
    vt_keywords = [
        "virustotal", "virus total", "vt", "malicious", "reputation", "threat intel",
        "check hash", "check ip", "check url", "is this malicious", "ioc", "indicator of compromise"
    ]
    if any(k in q for k in vt_keywords):
        return "check_virustotal"
    
    # Priority 2: Splunk-specific indicators (EventID, sourcetype, etc.)
    splunk_indicators = ["eventid", "eventcode", "sourcetype", "index=", "tstats", "mstats", "search ", "dashboard", "siem"]
    if any(k in q for k in splunk_indicators):
        return "execute_splunk_search"
    
    # Priority 3: Authentication/login/logon events (always Splunk, never Velociraptor)
    auth_keywords = [
        "login", "logon", "logoff", "logout", "authentication", "auth", "failed login", 
        "failed logon", "successful login", "successful logon", "user login", "user logon",
        "account login", "account logon", "credential", "password"
    ]
    if any(k in q for k in auth_keywords):
        return "execute_splunk_search"

    # Priority 4: Process-related keywords (Velociraptor for live endpoint state)
    process_keywords = ["process", "processes", "running", "pslist", "tasklist", "pid", "executable"]
    if any(k in q for k in process_keywords):
        # Only route to Velociraptor if it's NOT about Splunk process events
        if not any(splunk_word in q for splunk_word in ["eventid", "eventcode", "4688", "process creation", "sysmon"]):
            return "run_velociraptor_query"
    
    # Other endpoint/DFIR keywords
    velo_keywords = [
        # Network and services
        "services running", "listening ports", "netstat", "network connections", "open ports",
        # DFIR keywords
        "prefetch", "mft", "registry", "autoruns", "dfir", "endpoint", "memory",
        # System/computer info intents
        "computer info", "system info", "about this computer", "device info", "host info", "os version",
        # Local users/accounts intents
        "local users", "local user accounts", "users()", "user accounts",
        # Generic but endpoint-scoped
        "on this machine", "on host", "on the endpoint", "on the computer", "on the system",
    ]
    if any(k in q for k in velo_keywords):
        return "run_velociraptor_query"

    # Priority 5: Web research keywords
    web_keywords = [
        "who is", "what is", "latest news", "research", "cve-", "vulnerability details",
        "threat actor", "apt group", "campaign", "summarize url", "read url", "visit page",
        "summarize https", "read https", "analyze https"
    ]
    if any(k in q for k in web_keywords):
        # Distinguish between search and visit
        if "http" in q or "url" in q or "visit" in q:
            return "visit_page"
        return "web_search"

    # Fallback to LLM router with stronger guidance and examples
    router_prompt = ChatPromptTemplate.from_messages([
        (
            "system",
            """
You are a strict Tool Router. Select exactly ONE tool that best fits the user's request.

Tools (choose one):
- execute_splunk_search
  Purpose: SIEM/log analytics over historical events across many hosts. Works with Splunk fields like EventCode, sourcetype, index, tstats/mstats, datamodels. Use when the user wants logs, counts, trends, dashboards, searches over time.

- run_velociraptor_query
  Purpose: Live endpoint forensics and local system state on a machine. Use for listing processes (pslist), services, network connections (netstat), local users (users()), basic system info (info()), filesystem metadata (stat, glob), prefetch, registry, autoruns, memory artifacts.

- check_virustotal
  Purpose: Threat intelligence and reputation lookups. Use when the user wants to check if an IP, file hash, or URL is malicious, query VirusTotal, or get IOC reputation.

- web_search
  Purpose: General web search for threat intelligence, IOC research, CVE details, or general knowledge. Use when the user asks "who is...", "what is...", "latest news on...", or for external information not in logs/endpoints.

- visit_page
  Purpose: Visit a specific URL to extract its content. Use when the user provides a URL and asks to summarize, read, or analyze it.

Routing rules (decide with certainty):
1) If the request mentions login, logon, authentication, failed login, successful login, credentials, or password events -> execute_splunk_search. ALWAYS use Splunk for authentication/logon queries, NEVER Velociraptor.
2) If the request mentions Windows Event IDs, EventCode, sourcetype, index=, dashboards, SIEM analytics, trends over time, or searching logs -> execute_splunk_search.
3) If the request mentions processes, running programs, process list, services, or executable files on a system -> run_velociraptor_query.
4) If the request is about the current state of a computer/endpoint (network connections, listening ports, local users, basic system/computer info, prefetch, registry, files on disk) -> run_velociraptor_query.
5) If the user says "on host/computer X", "on this machine", "on the endpoint", "on the system" and wants system state -> run_velociraptor_query (Velociraptor runs on an endpoint).
6) If the user says "in Splunk", "SPL", or includes SPL-like tokens (index=, tstats, mstats) -> execute_splunk_search.
7) If the user asks to check if an IP/hash/URL is malicious, wants VirusTotal data, or mentions threat intel/IOC reputation -> check_virustotal.
8) If the user asks research questions (e.g., "Who is...", "What is CVE-...", "News on...") -> web_search.
9) If the user asks to read, summarize, or visit a URL -> visit_page.

Output format:
- Return EXACTLY one token: execute_splunk_search OR run_velociraptor_query OR check_virustotal OR web_search OR visit_page
- No extra words, punctuation, or quotes.
""",
        ),
        ("human", "{question}"),
    ])
    llm = ChatOllama(model=SUMMARY_MODEL)
    msg = await llm.ainvoke(router_prompt.format_messages(q=question))
    choice = (getattr(msg, "content", str(msg)) or "").strip()
    return choice if choice in {"execute_splunk_search", "run_velociraptor_query", "check_virustotal", "web_search", "visit_page"} else "execute_splunk_search"

def _apply_time_window_policy(question: str, spl: str, mode: str | None = None):
    """Normalize/insert earliest/latest based on natural language like 'last 24 hours'.
    Returns (new_spl, reason_or_None). Conservative heuristic.
    Allows per-request override of TIME_POLICY_MODE.
    """
    mode = (mode or TIME_POLICY_MODE)  # off | normalize | infer
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


def _normalize_windows_eventlog_fields(spl: str):
    """Normalize Windows Event Log searches to this canonical form:
    - sourcetype=WinEventLog
    - source="WinEventLog:<Channel>"  (e.g., Security, System, Application)

    Many environments ingest Windows logs with channel in the source field and a
    generic sourcetype. If we detect sourcetype=WinEventLog:<Channel>, rewrite it.

    Returns (new_spl, reason_or_None).
    """
    import re
    s = spl
    # Regex to capture sourcetype=WinEventLog:<Channel>, with optional quotes and case-insensitive
    pat = re.compile(r"(?i)\bsourcetype\s*=\s*['\"]?WinEventLog:(Security|System|Application)['\"]?")
    # If it's already in canonical form, do nothing
    already_canonical = re.search(r"(?i)\bsourcetype\s*=\s*['\"]?WinEventLog['\"]?\b", s) and \
                        re.search(r"(?i)\bsource\s*=\s*['\"]?WinEventLog:(Security|System|Application)['\"]?\b", s)
    if already_canonical:
        return s, None

    def _repl(m: re.Match):
        channel = m.group(1)
        return f'sourcetype=WinEventLog source="WinEventLog:{channel}"'

    new_s = pat.sub(_repl, s)
    if new_s != s:
        return new_s, "Rewrote sourcetype=WinEventLog:<Channel> to sourcetype=WinEventLog and source=WinEventLog:<Channel>"

    # Also handle odd cases like sourcetype='WinEventLog:security' without quotes or different case
    pat2 = re.compile(r"(?i)\bsourcetype\s*=\s*WinEventLog:(Security|System|Application)\b")
    new_s2 = pat2.sub(lambda m: f'sourcetype=WinEventLog source="WinEventLog:{m.group(1)}"', s)
    if new_s2 != s:
        return new_s2, "Rewrote sourcetype=WinEventLog:<Channel> to canonical Windows Event Log fields"

    return s, None


@app.get("/health/virustotal")
def health_virustotal():
    """Quick health check for VirusTotal API key and connectivity."""
    try:
        api_key = os.getenv("VT_API_KEY")
        if not api_key:
            return {
                "connected": False,
                "message": "VT_API_KEY not set in environment",
            }
        # Try a simple known-good hash lookup (EICAR test file MD5)
        test_hash = "44d88612fea8a8f36de82e1278abb02f"
        result = check_virustotal(test_hash, ioc_type="hash", api_key=api_key)
        if result.get("success"):
            return {
                "connected": True,
                "message": "VirusTotal API key valid and reachable",
                "test_ioc": test_hash,
            }
        else:
            return {
                "connected": False,
                "message": f"VirusTotal API error: {result.get('error', 'Unknown')}",
            }
    except Exception as e:
        return {
            "connected": False,
            "message": str(e),
        }


@app.get("/health/atomicredteam")
def health_atomicredteam():
    """Quick health check for Atomic Red Team module availability."""
    try:
        from tools.atomic_red_team import AtomicRedTeamTool
        art_tool = AtomicRedTeamTool()
        # Check if the module is available
        if art_tool._check_prerequisites():
            return {
                "connected": True,
                "message": "Invoke-AtomicRedTeam module found and accessible",
            }
        else:
            return {
                "connected": False,
                "message": "Invoke-AtomicRedTeam module not found. Please install it on the Windows host.",
            }
    except Exception as e:
        return {
            "connected": False,
            "message": f"Error checking Atomic Red Team: {str(e)}",
        }



@app.get("/health/sigma")
def health_sigma():
    """Quick health check for Sigma rules and pySigma library."""
    try:
        # Check if pySigma is installed
        pysigma_installed = False
        try:
            import sigma
            pysigma_installed = True
        except ImportError:
            pass
        
        # Check if Sigma rules repository exists
        sigma_repo_path = os.getenv("SIGMA_RULES_PATH", "/opt/sigma/rules")
        repo_exists = os.path.isdir(sigma_repo_path)
        
        # Count rules if repo exists
        rule_count = 0
        if repo_exists:
            from pathlib import Path
            rules_path = Path(sigma_repo_path)
            rule_files = list(rules_path.rglob("*.yml")) + list(rules_path.rglob("*.yaml"))
            rule_count = len(rule_files)
        
        if pysigma_installed and repo_exists:
            return {
                "connected": True,
                "message": f"pySigma installed and {rule_count} Sigma rules available",
                "pysigma_installed": True,
                "repo_path": sigma_repo_path,
                "rule_count": rule_count,
            }
        elif pysigma_installed and not repo_exists:
            return {
                "connected": False,
                "message": "pySigma installed but Sigma rules repository not found",
                "pysigma_installed": True,
                "repo_path": sigma_repo_path,
                "repo_exists": False,
                "hint": "Clone https://github.com/SigmaHQ/sigma or set SIGMA_RULES_PATH",
            }
        elif not pysigma_installed and repo_exists:
            return {
                "connected": False,
                "message": f"Sigma rules found ({rule_count}) but pySigma not installed",
                "pysigma_installed": False,
                "repo_path": sigma_repo_path,
                "rule_count": rule_count,
                "hint": "Install with: pip install pysigma pysigma-backend-splunk",
            }
        else:
            return {
                "connected": False,
                "message": "pySigma not installed and Sigma rules repository not found",
                "pysigma_installed": False,
                "repo_path": sigma_repo_path,
                "repo_exists": False,
                "hint": "Install pySigma and clone Sigma rules repository",
            }
    except Exception as e:
        return {
            "connected": False,
            "message": str(e),
        }


@app.websocket("/ws")
async def ws_chat(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            # Expect plain text or JSON payload with the user's question
            incoming = await websocket.receive_text()
            # Parse either plain text or JSON payload with settings
            req_default_index = DEFAULT_INDEX
            req_time_mode = TIME_POLICY_MODE
            req_spl_model = OLLAMA_MODEL
            req_vql_model = VQL_MODEL
            req_summary_model = SUMMARY_MODEL
            req_coder_model = CODER_MODEL
            req_raw_limit = 50
            try:
                data = json.loads(incoming)
                if isinstance(data, dict) and ("question" in data or data.get("type") == "ask"):
                    question = data.get("question") or data.get("q") or ""
                    settings = data.get("settings") or {}
                    req_default_index = settings.get("defaultIndex", req_default_index)
                    req_time_mode = (settings.get("timePolicyMode", req_time_mode) or req_time_mode).lower()
                    req_spl_model = settings.get("splModel", req_spl_model)
                    req_vql_model = settings.get("vqlModel", req_vql_model)
                    req_vql_model = settings.get("vqlModel", req_vql_model)
                    req_summary_model = settings.get("summaryModel", req_summary_model)
                    req_coder_model = settings.get("coderModel", req_coder_model)
                    try:
                        req_raw_limit = int(settings.get("rawResultLimit", req_raw_limit))
                    except Exception:
                        req_raw_limit = 50
                else:
                    question = incoming
            except Exception:
                # Treat as plain text
                question = incoming

            # 1) Notify start
            await websocket.send_json({
                "type": "activity",
                "title": "Analyzing question",
                "detail": question,
                "status": "running",
                "icon": "search",
            })

            # 2) Route to best tool
            tool_choice = await _route_tool(question)
            await websocket.send_json({
                "type": "activity",
                "title": "Tool selected",
                "detail": tool_choice,
                "status": "done",
                "icon": "robot",
            })

            if tool_choice == "check_virustotal":
                # Extract IOC from question using simple heuristics or LLM
                await websocket.send_json({
                    "type": "activity",
                    "title": "Extracting IOC",
                    "detail": "Identifying IP/hash/URL from question",
                    "status": "running",
                    "icon": "search",
                })
                
                # Simple extraction: look for common patterns
                import re
                q = question
                # IP pattern
                ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", q)
                # Hash pattern (MD5=32 hex, SHA1=40 hex, SHA256=64 hex)
                hash_match = re.search(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b", q)
                # URL pattern (http/https)
                url_match = re.search(r"https?://[^\s]+", q)
                
                ioc = None
                ioc_type = "hash"
                if ip_match:
                    ioc = ip_match.group(0)
                    ioc_type = "ip"
                elif url_match:
                    ioc = url_match.group(0)
                    ioc_type = "url"
                elif hash_match:
                    ioc = hash_match.group(0)
                    ioc_type = "hash"
                
                if not ioc:
                    await websocket.send_json({
                        "type": "error",
                        "title": "IOC extraction failed",
                        "detail": "Could not identify IP, hash, or URL in question",
                    })
                    continue
                
                await websocket.send_json({
                    "type": "activity",
                    "title": "Extracting IOC",
                    "detail": f"{ioc_type.upper()}: {ioc}",
                    "status": "done",
                    "icon": "search",
                })
                
                # Query VirusTotal
                await websocket.send_json({
                    "type": "activity",
                    "title": "Querying VirusTotal",
                    "detail": f"Checking {ioc_type} reputation",
                    "status": "running",
                    "icon": "shield",
                })
                
                try:
                    vt_result = await run_in_threadpool(check_virustotal, ioc, ioc_type)
                    await websocket.send_json({
                        "type": "activity",
                        "title": "Querying VirusTotal",
                        "detail": f"{vt_result.get('malicious', 0)}/{vt_result.get('total', 0)} vendors flagged as malicious",
                        "status": "done",
                        "icon": "shield",
                    })
                    
                    # Summarize
                    await websocket.send_json({
                        "type": "activity",
                        "title": "Summarizing threat intel",
                        "detail": "Generating human-readable overview",
                        "status": "running",
                        "icon": "robot",
                    })
                    
                    if vt_result.get("success"):
                        mal = vt_result.get("malicious", 0)
                        total = vt_result.get("total", 0)
                        if mal > 0:
                            summary_body = f"The {ioc_type.upper()} {ioc} is flagged as malicious by {mal}/{total} vendors on VirusTotal."
                        else:
                            summary_body = f"The {ioc_type.upper()} {ioc} is clean (0/{total} vendors flagged it)."
                        if vt_result.get("message"):
                            summary_body += f" {vt_result['message']}"
                    else:
                        summary_body = f"VirusTotal lookup failed: {vt_result.get('error', 'Unknown error')}"
                    
                    formatted_summary = f"Threat Intel Summary: {summary_body}"
                    await websocket.send_json({
                        "type": "activity",
                        "title": "Summarizing threat intel",
                        "detail": formatted_summary[:180] + ("…" if len(formatted_summary) > 180 else ""),
                        "status": "done",
                        "icon": "robot",
                    })

                    # If the IOC is an IP and malicious, perform follow-on hunts
                    proceed_hunt = vt_result.get("success") and vt_result.get("malicious", 0) > 0 and ioc_type == "ip"
                    if not proceed_hunt:
                        # Send VirusTotal-only final payload
                        await websocket.send_json({
                            "type": "final",
                            "source": "virustotal",
                            "spl": None,
                            "vql": None,
                            "ioc": ioc,
                            "ioc_type": ioc_type,
                            "count": 1,
                            "results": [vt_result],
                            "summary": formatted_summary,
                        })
                        continue

                    # Begin threat hunt sequence
                    await websocket.send_json({
                        "type": "activity",
                        "title": "Malicious verdict: starting threat hunt",
                        "detail": f"IOC {ioc} flagged by VirusTotal; proceeding with endpoint and SIEM hunts",
                        "status": "done",
                        "icon": "alert",
                    })

                    # 1) Velociraptor: Check active connections to the IOC IP
                    velo_vql = f'SELECT LocalAddress, LocalPort, RemoteAddress, State, Pid, Name FROM netstat() WHERE RemoteAddress = "{ioc}"'
                    # Announce VQL (consistent with existing flow)
                    await websocket.send_json({
                        "type": "activity",
                        "title": "VQL generated",
                        "detail": velo_vql,
                        "status": "done",
                        "icon": "code",
                    })
                    # Execute Velociraptor query (use standard title to correlate "Search completed")
                    await websocket.send_json({
                        "type": "activity",
                        "title": "Executing Velociraptor query",
                        "detail": "Querying endpoint via Velociraptor",
                        "status": "running",
                        "icon": "bolt",
                    })
                    velo_results_list = []
                    try:
                        velo_raw = await run_in_threadpool(run_velociraptor_query, velo_vql)
                        try:
                            velo_results_list = json.loads(velo_raw)
                        except Exception:
                            velo_results_list = [{"raw": velo_raw}]
                        await websocket.send_json({
                            "type": "activity",
                            "title": "Search completed",
                            "detail": f"{len(velo_results_list) if isinstance(velo_results_list, list) else 1} rows returned",
                            "status": "done",
                            "icon": "check",
                        })
                    except Exception as e:
                        await websocket.send_json({
                            "type": "activity",
                            "title": "Executing Velociraptor query",
                            "detail": f"Error: {str(e)}",
                            "status": "done",
                            "icon": "x",
                        })

                    # 2) Splunk: Hunt for historical communication with the IOC IP
                    spl_hunt = f'search index=* ("{ioc}") | stats earliest(_time) as first_seen, latest(_time) as last_seen, count by host, sourcetype | convert ctime(first_seen) ctime(last_seen)'
                    # Announce SPL (consistent with existing flow)
                    await websocket.send_json({
                        "type": "activity",
                        "title": "Final SPL query to Splunk",
                        "detail": spl_hunt,
                        "status": "done",
                        "icon": "code",
                    })
                    await websocket.send_json({
                        "type": "activity",
                        "title": "Executing Splunk search",
                        "detail": "Running query against Splunk",
                        "status": "running",
                        "icon": "search",
                    })
                    
                    splunk_rows = []
                    try:
                        splunk_rows = await run_in_threadpool(_execute_splunk_search, spl_hunt)
                        await websocket.send_json({
                            "type": "activity",
                            "title": "Search completed",
                            "detail": f"{len(splunk_rows)} events found",
                            "status": "done",
                            "icon": "check",
                        })
                    except Exception as e:
                        await websocket.send_json({
                            "type": "activity",
                            "title": "Executing Splunk search",
                            "detail": f"Error: {str(e)}",
                            "status": "done",
                            "icon": "x",
                        })

                    # Combine results
                    combined_summary = f"Threat Hunt Results for {ioc}:\n"
                    combined_summary += f"- VirusTotal: {mal}/{total} malicious.\n"
                    combined_summary += f"- Endpoint (Velociraptor): Found {len(velo_results_list)} active connections.\n"
                    combined_summary += f"- SIEM (Splunk): Found {len(splunk_rows)} historical events.\n"
                    
                    await websocket.send_json({
                        "type": "final",
                        "source": "combined_hunt",
                        "spl": spl_hunt,
                        "vql": velo_vql,
                        "ioc": ioc,
                        "ioc_type": ioc_type,
                        "count": len(splunk_rows) + len(velo_results_list),
                        "results": {
                            "virustotal": vt_result,
                            "velociraptor": velo_results_list,
                            "splunk": splunk_rows
                        },
                        "summary": combined_summary,
                    })

                except Exception as e:
                    await websocket.send_json({
                        "type": "error",
                        "title": "Threat hunt error",
                        "detail": str(e),
                    })
                continue

            # 3) Execute other tools via the Agent Graph
            # Define callbacks for the graph
            def _graph_velo(vql: str) -> str:
                # Use the .func attribute if it's a LangChain tool, otherwise call directly
                fn = getattr(run_velociraptor_query, "func", run_velociraptor_query)
                return fn(vql)

            # Build the graph
            agent_graph = build_multitool_graph(
                splunk_execute_fn=_execute_splunk_search,
                velociraptor_fn=_graph_velo,
                router_model=req_summary_model, # Use summary model for routing as it's usually smarter/faster
                spl_model=req_spl_model,
                vql_model=req_vql_model,
                coder_model=req_coder_model,
            )

            # Initial state
            initial_state = {
                "user_query": question,
                "tool_choice": tool_choice,
                "retry_count": 0,
                "messages": [],
                "error": None
            }

            # Run the graph
            # We use astream to get updates if possible, but for now invoke is safer for synchronous-like flow
            # or we can just use invoke since the graph steps are synchronous except for the LLM calls which are blocking in this setup
            
            # Notify execution start
            await websocket.send_json({
                "type": "activity",
                "title": "Executing tool",
                "detail": f"Running {tool_choice}...",
                "status": "running",
                "icon": "bolt",
            })

            try:
                # Use astream to get intermediate steps (like generated query)
                final_state = initial_state.copy()
                
                # We use astream to iterate over the graph steps
                async for output in agent_graph.astream(initial_state):
                    for node_name, state_update in output.items():
                        # Update our local view of the state
                        final_state.update(state_update)
                        
                        if node_name == "generate_query":
                            # Check for generated queries and notify UI
                            spl = state_update.get("spl_query")
                            vql = state_update.get("vql_query")
                            web_q = state_update.get("web_query")
                            web_url = state_update.get("web_url")
                            
                            detail = ""
                            title = "Query Generated"
                            
                            if spl:
                                detail = spl
                                title = "Generated SPL"
                            elif vql:
                                detail = vql
                                title = "Generated VQL"
                            elif web_q:
                                detail = web_q
                                title = "Web Search Query"
                            elif web_url:
                                detail = web_url
                                title = "Visiting URL"
                                
                            if detail:
                                await websocket.send_json({
                                    "type": "activity",
                                    "title": title,
                                    "detail": detail,
                                    "status": "done",
                                    "icon": "code",
                                })

                # Extract results from final state
                results = final_state.get("results")
                error = final_state.get("error")
                
                if error:
                    await websocket.send_json({
                        "type": "error",
                        "title": "Tool execution failed",
                        "detail": error,
                    })
                    continue

                # Mark tool execution as complete
                await websocket.send_json({
                    "type": "activity",
                    "title": "Executing tool",
                    "detail": f"Completed {tool_choice}",
                    "status": "done",
                    "icon": "bolt",
                })

                # Summarize results
                await websocket.send_json({
                    "type": "activity",
                    "title": "Summarizing results",
                    "detail": "Generating human-readable answer...",
                    "status": "running",
                    "icon": "robot",
                })

                summary_text = ""
                query_str = ""
                if tool_choice == "execute_splunk_search":
                    query_str = final_state.get("spl_query")
                elif tool_choice == "run_velociraptor_query":
                    query_str = final_state.get("vql_query")
                elif tool_choice == "web_search":
                    query_str = final_state.get("web_query")
                elif tool_choice == "visit_page":
                    query_str = final_state.get("web_url")

                summary_text = await _summarize_results(
                    question=question,
                    query=query_str,
                    rows=results,
                    tool_name=tool_choice,
                    model=req_summary_model
                )

                await websocket.send_json({
                    "type": "activity",
                    "title": "Summarizing results",
                    "detail": summary_text[:100] + "...",
                    "status": "done",
                    "icon": "robot",
                })

                # Send final response
                await websocket.send_json({
                    "type": "final",
                    "source": tool_choice,
                    "spl": final_state.get("spl_query"),
                    "vql": final_state.get("vql_query"),
                    "web_query": final_state.get("web_query"),
                    "web_url": final_state.get("web_url"),
                    "count": len(results) if isinstance(results, list) else None,  # Don't show count for web tools
                    "results": results,
                    "summary": summary_text,
                })

            except Exception as e:
                await websocket.send_json({
                    "type": "error",
                    "title": "Agent execution error",
                    "detail": str(e),
                })
                import traceback
                traceback.print_exc()
            continue

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
