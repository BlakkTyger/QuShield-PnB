"""
AI API Endpoints — RAG Chatbot, SQL Agent tabular lookup, and vector store management.
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional
from sqlalchemy.orm import Session
import json
from uuid import UUID

from app.core.database import get_db
from app.api.v1.auth import get_current_user
from app.models.auth import User
from app.models.scan import ScanJob
from app.models.risk import RiskScore
from app.services.ai_service import get_ai_provider
from app.services.vector_store import VectorStore
from app.services.sql_agent import TabularAgent

router = APIRouter()

class ChatRequest(BaseModel):
    message: str
    mode: str = "auto"  # auto | rag | sql

class ChatResponse(BaseModel):
    response: str
    mode_used: str
    sources: List[str] = []

@router.post("/chat", response_model=ChatResponse)
def ai_chat(request: ChatRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Chat with the QuShield-PnB AI assistant using scan data context."""
    import logging
    logger = logging.getLogger(__name__)

    query = request.message
    # Simple heuristic for mode: if words like "how many", "count", "list", "table", "all" -> SQL
    mode = request.mode
    if mode == "auto":
        sql_keywords = ["how many", "count", "list", "table", "all", "average", "percent", "which assets"]
        if any(kw in query.lower() for kw in sql_keywords):
            mode = "sql"
        else:
            mode = "rag"

    if mode == "sql":
        logger.info(f"AI Chat: Using SQL Agent for user {current_user.id}")
        agent = TabularAgent(current_user, db)
        answer = agent.query(query)
        return ChatResponse(response=answer, mode_used="sql")
        
    elif mode == "rag":
        logger.info(f"AI Chat: Using RAG Vector Store for user {current_user.id}")
        vector_store = VectorStore(current_user)
        results = vector_store.search(query, n_results=5)
        
        context_texts = []
        sources = []
        for r in results:
            context_texts.append(r["content"])
            sources.append(r["metadata"].get("source", "unknown"))

        context_str = "\n\n---\n\n".join(context_texts)
        
        system_prompt = f"""You are a specialized Quantum Security Analyst AI.
Please answer the user's question using ONLY the provided findings/context below.
If the context does not contain the answer, say "I don't have enough information about that."

Context:
{context_str}
"""
        ai = get_ai_provider(current_user)
        try:
            answer = ai.generate(prompt=query, system=system_prompt)
        except Exception as e:
            answer = f"AI Error: {str(e)}"
            
        return ChatResponse(response=answer, mode_used="rag", sources=sources)

    raise HTTPException(status_code=400, detail="Invalid mode")


@router.post("/embed/refresh")
def refresh_embeddings(background_tasks: BackgroundTasks, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Background task to sync the user's latest High-Risk assets into the ChromaDB Vector Store."""
    
    def _run_embedding():
        # Requires its own DB session in background
        from app.core.database import SessionLocal
        local_db = SessionLocal()
        try:
            vector_store = VectorStore(current_user)
            
            # Fetch high risk scores
            scans = local_db.query(ScanJob).filter(ScanJob.user_id == current_user.id).all()
            scan_ids = [s.id for s in scans]
            
            if not scan_ids:
                return
                
            risks = local_db.query(RiskScore).filter(
                RiskScore.scan_id.in_(scan_ids),
                RiskScore.risk_classification.in_(["quantum_critical", "quantum_vulnerable"])
            ).all()

            texts = []
            metadatas = []
            ids = []

            for r in risks:
                texts.append(f"Asset ID {r.asset_id} has {r.risk_classification} quantum risk. Score: {r.quantum_risk_score}/1000. HNDL exposed: {r.hndl_exposed}.")
                # Note: vector_store forcefully injects user_id into this dict
                metadatas.append({"source": f"risk_score_{r.asset_id}", "scan_id": str(r.scan_id)})
                ids.append(f"risk_{r.asset_id}")

            if texts:
                vector_store.embed_and_store(texts, metadatas, ids)
        finally:
            local_db.close()

    background_tasks.add_task(_run_embedding)
    return {"status": "accepted", "message": "Vector store refresh queued"}


@router.get("/status")
def ai_status(current_user: User = Depends(get_current_user)):
    """Check AI deployment status and active tiers."""
    mode = getattr(current_user, "deployment_mode", "secure")
    tier = getattr(current_user, "ai_tier", "free")
    
    return {
        "deployment_mode": mode,
        "active_tier": tier,
        "vector_store": "ChromaDB + Jina Cloud",
        "tabular_agent": "SQLite Memory DB (Isolated)"
    }


class AISettingsUpdate(BaseModel):
    deployment_mode: Optional[str] = None
    ai_tier: Optional[str] = None
    cloud_api_keys: Optional[dict] = None

@router.patch("/settings")
def update_ai_settings(settings: AISettingsUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Update AI deployment mode, tier, and API keys."""
    if settings.deployment_mode:
        if settings.deployment_mode not in ("secure", "cloud"):
            raise HTTPException(status_code=400, detail="Invalid deployment mode")
        current_user.deployment_mode = settings.deployment_mode
    if settings.ai_tier:
        if settings.ai_tier not in ("free", "professional", "enterprise"):
            raise HTTPException(status_code=400, detail="Invalid AI tier")
        current_user.ai_tier = settings.ai_tier
    if settings.cloud_api_keys is not None:
        current_user.cloud_api_keys = settings.cloud_api_keys
        
    db.commit()
    db.refresh(current_user)
    return {"status": "success", "deployment_mode": current_user.deployment_mode, "ai_tier": current_user.ai_tier}


@router.get("/models")
def list_ai_models(current_user: User = Depends(get_current_user)):
    """List available LLMs based on current deployment mode and tier."""
    mode = getattr(current_user, "deployment_mode", "secure")
    tier = getattr(current_user, "ai_tier", "free")
    
    if mode == "secure":
        models = ["qwen2.5:3b", "nomic-embed-text"]
        if tier in ("professional", "enterprise"):
            models.append("llama3-8b")
        if tier == "enterprise":
            models.append("llama3.1:70b")
        return {"mode": "secure", "tier": tier, "models": models}
        
    else:
        models = ["llama-3.1-8b-instant (Groq)", "jina-embeddings-v3"]
        if tier in ("professional", "enterprise"):
            models.extend(["gpt-4o-mini", "text-embedding-3-small"])
        if tier == "enterprise":
            models.extend(["gpt-4o", "text-embedding-3-large"])
        return {"mode": "cloud", "tier": tier, "models": models}


@router.post("/migration-roadmap/{scan_id}")
def generate_roadmap(scan_id: UUID, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Generate a structured, 4-phase PQC migration roadmap for a completed scan."""
    from app.services.roadmap_agent import generate_migration_roadmap

    scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not scan_job or scan_job.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Scan not found or access denied")

    try:
        roadmap = generate_migration_roadmap(str(scan_id), db, current_user)
        return {"scan_id": str(scan_id), "roadmap": roadmap}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to generate AI roadmap")


# ─── ReAct Agent — Streaming Chat ─────────────────────────────────────────────

class AgentChatRequest(BaseModel):
    message: str
    history: Optional[List[dict]] = None  # [{"role": "user"|"assistant", "content": "..."}]


@router.post("/agent/chat")
def agent_chat_stream(
    request: AgentChatRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Stream a ReAct agent response with reasoning trace.
    Returns Server-Sent Events (text/event-stream).
    Each SSE data line is JSON: {"type": "thought"|"tool"|"answer"|"error"|"done", "content": "..."}
    """
    from fastapi.responses import StreamingResponse
    from app.services.react_agent import stream_agent_response

    def _gen():
        try:
            yield from stream_agent_response(
                user=current_user,
                db=db,
                query=request.message,
                chat_history=request.history,
            )
        except Exception as e:
            import json as _json
            yield f"data: {_json.dumps({'type': 'error', 'content': str(e)})}\n\n"

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.get("/agent/status")
def agent_status(current_user: User = Depends(get_current_user)):
    """Check whether the ReAct agent is available (Groq API key configured)."""
    available = bool(getattr(__import__('app.config', fromlist=['settings']).settings, 'GROQ_API_KEY', ''))
    return {
        "available": available,
        "mode": "cloud_groq" if available else "unavailable",
        "model": "llama-3.3-70b-versatile",
        "features": ["rag", "sql", "report_json", "web_search"],
    }

