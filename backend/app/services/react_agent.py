"""
QuShield ReAct Agent — LlamaIndex-powered reasoning agent for the AI assistant.

Tools available:
  1. rag_tool          — search user's ChromaDB vectors + global knowledge base
  2. sql_tool          — natural-language queries over scan data (assets, risks, CBOM, compliance)
  3. json_tool         — load and inspect generated report JSON
  4. web_search_tool   — DuckDuckGo internet search for PQC/regulatory context

Architecture:
  - LlamaIndex ReActAgent with max_iterations=8
  - Groq llama-3.3-70b-versatile (Cloud Free tier)
  - Streaming via sync generator that yields SSE lines
  - Reasoning trace included in stream
"""
import asyncio
import json
import logging
import queue
import sqlite3
import os
from pathlib import Path
from typing import AsyncGenerator, Generator, List, Optional

from sqlalchemy.orm import Session

from app.models.auth import User
from app.config import settings

logger = logging.getLogger(__name__)

# ─── Lazy imports so server still starts if llama-index not installed ─────────

# Ordered fallback model list — first available model that doesn't rate-limit wins
_GROQ_MODELS = [
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "gemma2-9b-it",
]


def _get_llm():
    key = settings.GROQ_API_KEY
    if not key:
        raise RuntimeError(
            "GROQ_API_KEY is not configured. Set it in your .env file. "
            "Get a free key at https://console.groq.com"
        )

    # Try native LlamaIndex Groq integration first
    for model in _GROQ_MODELS:
        try:
            from llama_index.llms.groq import Groq
            llm = Groq(
                model=model,
                api_key=key,
                temperature=0.1,
                max_tokens=4096,
                context_window=32768,
            )
            logger.info(f"ReAct agent LLM: Groq/{model} (native)")
            return llm
        except ImportError:
            break  # llama-index-llms-groq not installed, try OpenAI-compat
        except Exception as e:
            logger.warning(f"Groq/{model} init failed: {e} — trying next model")
            continue

    # Fallback: use llama-index OpenAI provider pointing at Groq's OpenAI-compatible endpoint
    for model in _GROQ_MODELS:
        try:
            from llama_index.llms.openai import OpenAI
            llm = OpenAI(
                model=model,
                api_key=key,
                api_base="https://api.groq.com/openai/v1",
                temperature=0.1,
                max_tokens=4096,
                context_window=32768,
            )
            logger.info(f"ReAct agent LLM: Groq/{model} (OpenAI-compat fallback)")
            return llm
        except Exception as e:
            logger.warning(f"Groq OpenAI-compat/{model} init failed: {e}")
            continue

    raise RuntimeError(
        "Could not initialise any Groq model. Check GROQ_API_KEY and network connectivity."
    )


def _get_embed_model():
    try:
        from llama_index.embeddings.jinaai import JinaEmbedding
        key = settings.JINA_API_KEY
        if key:
            return JinaEmbedding(api_key=key, model="jina-embeddings-v3")
    except ImportError:
        pass
    try:
        from llama_index.core.embeddings import resolve_embed_model
        return resolve_embed_model("local:BAAI/bge-small-en-v1.5")
    except Exception:
        return None


# ─── Tool: RAG ────────────────────────────────────────────────────────────────

def _build_rag_tool(user: User, db: Session, scan_id: Optional[str] = None):
    from llama_index.core.tools import FunctionTool

    def rag_search(query: str, n_results: int = 6) -> str:
        """
        Search the knowledge base and user's scan data using semantic similarity.
        Use this for questions about PQC standards, compliance frameworks, past reports, and scan findings.
        """
        results = []

        # 1. Global knowledge base
        try:
            from app.services.knowledge_seeder import search_knowledge_base
            kb_results = search_knowledge_base(query, n_results=4)
            for r in kb_results:
                src = r["metadata"].get("source", "knowledge_base")
                results.append(f"[Knowledge: {src}]\n{r['content']}")
        except Exception as e:
            logger.debug(f"KB search failed: {e}")

        # 2. User vector store — filtered by scan_id tag when provided
        try:
            from app.services.vector_store import VectorStore
            vs = VectorStore(user)
            where_filter = {"scan_id": scan_id} if scan_id else None
            user_results = vs.search(query, n_results=n_results, where=where_filter)
            for r in user_results:
                src = r.get("metadata", {}).get("source", "scan_data")
                sid = r.get("metadata", {}).get("scan_id", "")
                tag = f" | scan:{sid[:8]}" if sid else ""
                results.append(f"[Scan data: {src}{tag}]\n{r['content']}")
        except Exception as e:
            logger.debug(f"User vector search failed: {e}")

        if not results:
            return "No relevant information found in the knowledge base or scan data."
        return "\n\n---\n\n".join(results[:8])

    scope_note = f" Results are scoped to scan {scan_id[:8].upper()}." if scan_id else ""
    return FunctionTool.from_defaults(
        fn=rag_search,
        name="rag_search",
        description=(
            "Search the QuShield knowledge base (PQC standards, RBI/SEBI/NPCI regulations, "
            "vendor PQC status, migration guides) and the user's scan data (assets, risks, "
            "compliance findings, generated reports). "
            "Use this first for any question about cryptographic standards, regulations, "
            f"or findings from scans.{scope_note}"
        ),
    )


# ─── Tool: SQL ────────────────────────────────────────────────────────────────

def _build_sql_tool(user: User, db: Session, scan_id: Optional[str] = None):
    from llama_index.core.tools import FunctionTool

    def sql_query(question: str) -> str:
        """
        Query the scan database using natural language.
        Use this for questions about counts, statistics, asset lists, risk scores,
        compliance status, CBOM components, or certificate data.
        """
        try:
            from app.services.sql_agent import TabularAgent
            agent = TabularAgent(user, db, scan_id=scan_id)
            return agent.query(question)
        except Exception as e:
            logger.error(f"SQL tool error: {e}")
            return f"Database query failed: {e}"

    scope_note = f" Data is scoped to scan {scan_id[:8].upper()}." if scan_id else ""
    return FunctionTool.from_defaults(
        fn=sql_query,
        name="sql_query",
        description=(
            "Query the QuShield scan database with natural language questions. "
            "Use this for: counting assets by risk level, listing critical assets, "
            "summarizing compliance statistics, finding CBOM components, "
            f"looking up specific scan results, or any question requiring structured data retrieval.{scope_note}"
        ),
    )


# ─── Tool: JSON Report ────────────────────────────────────────────────────────

def _build_json_tool(user: User, db: Session):
    from llama_index.core.tools import FunctionTool

    def load_report_json(report_type: str = "executive") -> str:
        """
        Load the most recent generated report in JSON format for analysis.
        Supported types: executive, full_scan, rbi_submission, cbom_audit,
        migration_progress, pqc_migration_plan.
        """
        try:
            from app.models.generated_report import GeneratedReport
            record = (
                db.query(GeneratedReport)
                .filter(
                    GeneratedReport.user_id == user.id,
                    GeneratedReport.report_type == report_type,
                    GeneratedReport.format == "json",
                )
                .order_by(GeneratedReport.generated_at.desc())
                .first()
            )
            if not record or not record.file_path:
                # Try generating in-memory JSON snapshot
                return f"No saved JSON report found for type '{report_type}'. Use sql_query to get current data."

            if not os.path.exists(record.file_path):
                return f"Report file not found on disk: {record.file_path}"

            with open(record.file_path, "r") as f:
                data = json.load(f)

            # Return a summarized version to stay within context
            summary = {
                "report_type": data.get("report_type", report_type),
                "generation_date": data.get("generation_date"),
                "targets": data.get("targets"),
                "stats": data.get("stats"),
                "risk_counts": data.get("risk_counts"),
                "top_algorithms": data.get("top_algorithms", [])[:10],
                "critical_assets_count": len(data.get("critical_assets", [])),
                "top_critical": data.get("critical_assets", [])[:5],
            }
            return json.dumps(summary, indent=2)
        except Exception as e:
            logger.error(f"JSON tool error: {e}")
            return f"Failed to load report: {e}"

    return FunctionTool.from_defaults(
        fn=load_report_json,
        name="load_report_json",
        description=(
            "Load the most recent saved report data in JSON format. "
            "Use this when asked about specific report findings, historical scan data, "
            "or to compare current state against a previous report. "
            "Provide report_type as one of: executive, full_scan, rbi_submission, "
            "cbom_audit, migration_progress, pqc_migration_plan."
        ),
    )


# ─── Tool: Web Search ─────────────────────────────────────────────────────────

def _build_web_search_tool():
    from llama_index.core.tools import FunctionTool

    def web_search(query: str, max_results: int = 4) -> str:
        """
        Search the internet for up-to-date information about PQC standards,
        vendor announcements, regulatory updates, and cryptographic news.
        """
        try:
            from duckduckgo_search import DDGS
            with DDGS() as ddgs:
                results = list(ddgs.text(query, max_results=max_results))
            if not results:
                return "No web search results found."
            output = []
            for r in results:
                output.append(f"**{r.get('title', 'No title')}**\n{r.get('body', '')}\nURL: {r.get('href', '')}")
            return "\n\n---\n\n".join(output)
        except ImportError:
            return "Web search unavailable — duckduckgo-search not installed."
        except Exception as e:
            logger.error(f"Web search failed: {e}")
            return f"Web search failed: {e}"

    return FunctionTool.from_defaults(
        fn=web_search,
        name="web_search",
        description=(
            "Search the internet for current information about post-quantum cryptography, "
            "NIST standards updates, vendor PQC support announcements, RBI/SEBI regulatory news, "
            "or any topic not covered in the local knowledge base. "
            "Use sparingly — prefer rag_search for known topics."
        ),
    )


# ─── Agent factory ────────────────────────────────────────────────────────────

def build_react_agent(user: User, db: Session, scan_id: Optional[str] = None):
    """Build and return a configured LlamaIndex ReActAgent for the given user."""
    from llama_index.core.agent import ReActAgent
    from llama_index.core import Settings as LISettings

    llm = _get_llm()
    embed_model = _get_embed_model()

    LISettings.llm = llm
    if embed_model:
        LISettings.embed_model = embed_model

    tools = [
        _build_rag_tool(user, db, scan_id=scan_id),
        _build_sql_tool(user, db, scan_id=scan_id),
        _build_json_tool(user, db),
        _build_web_search_tool(),
    ]

    scan_scope_note = (
        f" This conversation is scoped to scan ID {scan_id[:8].upper()} — "
        "filter all database queries and vector searches to data from this specific scan."
    ) if scan_id else (
        " You have access to ALL scans for this user. "
        "Use your tools to find, compare, and aggregate data across all scans when answering."
    )

    system_prompt = (
        "You are QuShield AI, an expert Post-Quantum Cryptography security advisor for Indian banking infrastructure. "
        "You have access to tools to search the knowledge base, query scan data, load reports, and search the web. "
        "Always use tools to ground your answers in actual data. "
        "When analyzing quantum risk, reference specific assets, scores, and regulatory requirements. "
        f"Be precise, technical, and actionable. Cite data sources in your response.{scan_scope_note}"
    )

    agent = ReActAgent(
        tools=tools,
        llm=llm,
        max_iterations=8,
        verbose=True,
        system_prompt=system_prompt,
        timeout=120.0,
    )
    return agent


# ─── Streaming response generator ─────────────────────────────────────────────

async def stream_agent_response(
    user: User, db: Session, query: str,
    chat_history: Optional[List[dict]] = None,
    scan_id: Optional[str] = None,
) -> AsyncGenerator[str, None]:
    """
    Async generator that yields SSE-formatted lines for streaming to the frontend.
    Events: thought | tool | status | answer | error | done
    Trace and status events are emitted in real time via concurrent drain tasks.
    """
    import io
    import sys

    def _sse(event_type: str, content: str) -> str:
        payload = json.dumps({"type": event_type, "content": content})
        return f"data: {payload}\n\n"

    try:
        agent = build_react_agent(user, db, scan_id=scan_id)
    except Exception as e:
        import traceback
        logger.error(f"Agent initialization failed: {e}\n{traceback.format_exc()}")
        yield _sse("error", f"Agent initialization failed: {e}")
        return

    # ─── Central SSE event bus ────────────────────────────────────────────────
    # All concurrent tasks PUT events here; the generator consumes and yields them.
    event_bus: asyncio.Queue = asyncio.Queue()
    _DONE = object()   # sentinel: agent finished
    _SENTINEL = object()  # sentinel for thread-safe queues

    # Thread-safe queues that sync code (LlamaIndex internals) writes into;
    # async drain tasks poll them and forward to event_bus.
    trace_tq: queue.SimpleQueue = queue.SimpleQueue()

    # ─ Redirect stdout → trace queue ─────────────────────────────────────────
    class _TraceCapture(io.StringIO):
        def __init__(self):
            super().__init__()
            self._buf = ""

        def write(self, s: str):
            self._buf += s
            if "\n" in self._buf:
                lines = self._buf.split("\n")
                for line in lines[:-1]:
                    stripped = line.strip()
                    if stripped:
                        trace_tq.put_nowait(stripped)
                self._buf = lines[-1]

        def flush(self):
            pass

    old_stdout = sys.stdout
    sys.stdout = _TraceCapture()

    # ─ Async task: drain stdout trace into event_bus ─────────────────────────
    async def _drain_trace():
        while True:
            await asyncio.sleep(0.05)
            try:
                while True:
                    line = trace_tq.get_nowait()
                    if line is _SENTINEL:
                        return
                    if line.startswith("Thought:") or line.startswith("> "):
                        await event_bus.put(_sse("thought", line))
                    elif (line.startswith("Action:") or line.startswith("Observation:")
                          or line.startswith("Tool:")):
                        await event_bus.put(_sse("tool", line))
                    elif line.strip():
                        await event_bus.put(_sse("thought", line))
            except queue.Empty:
                pass

    # ─ Async task: run the agent, put DONE/error when finished ───────────────
    async def _run_agent():
        try:
            result = await agent.run(user_msg=query)
            await event_bus.put((_DONE, result))
        except Exception as exc:
            await event_bus.put((_DONE, exc))
        finally:
            trace_tq.put_nowait(_SENTINEL)

    # ─ Start background tasks ─────────────────────────────────────────────────
    drain_task = asyncio.create_task(_drain_trace())
    agent_task = asyncio.create_task(_run_agent())

    # Yield initial status immediately
    yield _sse("status", "🤔 Agent is thinking…")

    agent_result = None
    try:
        while True:
            item = await event_bus.get()
            if isinstance(item, tuple) and len(item) == 2 and item[0] is _DONE:
                agent_result = item[1]
                break
            yield item  # real-time SSE line
    except Exception as e:
        sys.stdout = old_stdout
        drain_task.cancel()
        agent_task.cancel()
        yield _sse("error", f"Agent execution failed: {str(e)}")
        return
    finally:
        sys.stdout = old_stdout
        # Wait for drain to flush remaining lines
        try:
            await asyncio.wait_for(drain_task, timeout=1.0)
        except Exception:
            drain_task.cancel()

    # Flush any remaining events that arrived after _DONE
    while not event_bus.empty():
        try:
            item = event_bus.get_nowait()
            if not (isinstance(item, tuple) and item[0] is _DONE):
                yield item
        except asyncio.QueueEmpty:
            break

    if isinstance(agent_result, Exception):
        yield _sse("error", f"Agent execution failed: {str(agent_result)}")
        return

    response_text = str(getattr(agent_result, "response", agent_result) or "")

    # Yield final answer in chunks for streaming feel
    chunk_size = 80
    for i in range(0, len(response_text), chunk_size):
        yield _sse("answer", response_text[i:i + chunk_size])

    yield _sse("done", "")
