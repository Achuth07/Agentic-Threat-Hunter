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


# Load env
load_dotenv()

# Splunk config
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_PORT = int(os.getenv("SPLUNK_PORT", "8089"))
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD")

# Ollama model
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3:8b")

app = FastAPI(title="Agentic-Threat-Hunter UI")

# Serve static frontend
STATIC_DIR = os.path.join(os.path.dirname(__file__), "web")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index():
    # Serve the SPA
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


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


def _build_prompt():
    return ChatPromptTemplate.from_messages([
        (
            "system",
                        """You are a Splunk search assistant.
Your job is to output only a valid Splunk SPL query — no explanations, code blocks, or backticks.
Rules:
- Prefer starting queries with the generating command 'search '.
- It's okay to use other generating commands ('from', 'tstats', 'mstats') when needed.
Examples:
    User: Find login failures
    You: search index=auth sourcetype=secure action=failure | stats count""",
        ),
        ("human", "{question}"),
    ])


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

            # 2) Generate SPL with LLM
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
            # ChatOllama.invoke is sync; run in thread to avoid blocking event loop.
            from starlette.concurrency import run_in_threadpool

            ai_message = await run_in_threadpool(llm.invoke, messages)
            raw_spl = ai_message.content if hasattr(ai_message, "content") else str(ai_message)
            spl = raw_spl.strip().strip("`")
            await websocket.send_json({
                "type": "activity",
                "title": "SPL generated",
                "detail": spl,
                "status": "done",
                "icon": "code",
            })

            def _normalize_spl(q: str) -> str:
                # Remove triple backtick blocks if present
                q = q.strip()
                if q.startswith("```") and q.endswith("```"):
                    q = q.strip("`")
                q = q.strip()
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

            # 3) Execute Splunk search
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
                # 4) Send final payload
                await websocket.send_json({
                    "type": "final",
                    "spl": normalized_spl,
                    "count": count,
                    "results": results_list[:50],  # cap to keep payload small
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


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=True)
