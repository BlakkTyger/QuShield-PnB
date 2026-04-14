"""
Knowledge Base Seeder — Reads bundled compliance and PQC guidance documents,
chunks them, and embeds them into a global ChromaDB collection for RAG retrieval.

The global collection (qushield_knowledge_global) is NOT user-isolated — it is
shared read-only context available to all users' AI assistant queries.
"""
import os
import logging
from pathlib import Path
from typing import List, Tuple

logger = logging.getLogger(__name__)

# In Docker, knowledge files are copied to /app/knowledge (outside the volume mount).
# In local dev they live at backend/data/knowledge relative to the repo root.
_DOCKER_KNOWLEDGE = Path("/app/knowledge")
_LOCAL_KNOWLEDGE = Path(__file__).resolve().parent.parent.parent / "data" / "knowledge"
KNOWLEDGE_DIR = _DOCKER_KNOWLEDGE if _DOCKER_KNOWLEDGE.exists() else _LOCAL_KNOWLEDGE
GLOBAL_COLLECTION = "qushield_knowledge_global"
CHUNK_SIZE = 800          # characters per chunk
CHUNK_OVERLAP = 100       # overlap between consecutive chunks
SEED_MARKER_ID = "__seed_complete__"


def _chunk_text(text: str, source: str) -> Tuple[List[str], List[dict], List[str]]:
    """Split document text into overlapping chunks with metadata."""
    texts, metas, ids = [], [], []
    start = 0
    chunk_idx = 0
    # Extract tags from first line if present
    tags = ""
    lines = text.strip().splitlines()
    for line in lines[:5]:
        if line.startswith("Tags:"):
            tags = line.replace("Tags:", "").strip()
            break

    while start < len(text):
        end = start + CHUNK_SIZE
        chunk = text[start:end]
        if chunk.strip():
            chunk_id = f"kb_{source}_{chunk_idx}"
            texts.append(chunk)
            metas.append({
                "source": source,
                "source_type": "compliance_doc",
                "tags": tags,
                "chunk_index": chunk_idx,
            })
            ids.append(chunk_id)
            chunk_idx += 1
        start += CHUNK_SIZE - CHUNK_OVERLAP

    return texts, metas, ids


def seed_knowledge_base() -> int:
    """
    Seeds the global ChromaDB knowledge collection from bundled text files.
    Returns the number of chunks embedded, or 0 if already seeded / unavailable.
    Idempotent: checks for marker ID before embedding.
    """
    try:
        import chromadb
        from chromadb.config import Settings
    except ImportError:
        logger.warning("ChromaDB not installed — knowledge base seeding skipped.")
        return 0

    if not KNOWLEDGE_DIR.exists():
        logger.warning(f"Knowledge directory not found: {KNOWLEDGE_DIR}")
        return 0

    try:
        db_path = str(Path(__file__).resolve().parent.parent.parent / "data" / "chroma")
        os.makedirs(db_path, exist_ok=True)
        client = chromadb.PersistentClient(
            path=db_path,
            settings=Settings(anonymized_telemetry=False)
        )
    except Exception as e:
        logger.error(f"Failed to initialize ChromaDB for seeding: {e}")
        return 0

    # Determine whether we can use Jina (1024-dim) or must fall back to ChromaDB default (384-dim)
    embedder, jina_available = _get_embedder()
    expected_dim = 1024 if jina_available else 384

    # Detect and resolve dimension mismatch: if collection exists with wrong dim, delete it
    try:
        existing_col = client.get_collection(GLOBAL_COLLECTION)
        # Probe the dimension by checking any stored embedding
        probe = existing_col.get(limit=1, include=["embeddings"])
        stored_embs = probe.get("embeddings") or []
        if stored_embs and len(stored_embs[0]) != expected_dim:
            logger.warning(
                f"Knowledge collection dimension mismatch "
                f"(stored={len(stored_embs[0])}, expected={expected_dim}) — "
                "deleting stale collection and reseeding."
            )
            client.delete_collection(GLOBAL_COLLECTION)
    except Exception:
        pass  # collection doesn't exist yet, or probe failed — proceed normally

    try:
        collection = client.get_or_create_collection(
            GLOBAL_COLLECTION,
            metadata={"hnsw:space": "cosine"}
        )
    except Exception as e:
        logger.error(f"Failed to get/create ChromaDB collection: {e}")
        return 0

    # Check if already seeded
    try:
        existing = collection.get(ids=[SEED_MARKER_ID])
        if existing and existing.get("ids"):
            logger.info("Knowledge base already seeded — skipping.")
            return 0
    except Exception:
        pass

    all_texts, all_metas, all_ids = [], [], []

    txt_files = sorted(KNOWLEDGE_DIR.glob("*.txt"))
    if not txt_files:
        logger.warning("No .txt files found in knowledge directory.")
        return 0

    for filepath in txt_files:
        try:
            content = filepath.read_text(encoding="utf-8")
            source_name = filepath.stem
            texts, metas, ids = _chunk_text(content, source_name)
            all_texts.extend(texts)
            all_metas.extend(metas)
            all_ids.extend(ids)
            logger.info(f"Knowledge: prepared {len(texts)} chunks from '{filepath.name}'")
        except Exception as e:
            logger.error(f"Failed to read knowledge file {filepath}: {e}")

    if not all_texts:
        return 0

    # Embed in batches of 50 to avoid API rate limits
    batch_size = 50
    total_stored = 0
    for i in range(0, len(all_texts), batch_size):
        batch_texts = all_texts[i:i + batch_size]
        batch_metas = all_metas[i:i + batch_size]
        batch_ids = all_ids[i:i + batch_size]

        try:
            if jina_available:
                embeddings = embedder(batch_texts)
                valid = embeddings and all(len(e) > 0 for e in embeddings)
            else:
                valid = False

            if valid:
                collection.add(
                    ids=batch_ids,
                    documents=batch_texts,
                    embeddings=embeddings,
                    metadatas=batch_metas,
                )
            else:
                # Let ChromaDB use its built-in default embedder (all-MiniLM-L6-v2)
                collection.add(
                    ids=batch_ids,
                    documents=batch_texts,
                    metadatas=batch_metas,
                )
            total_stored += len(batch_texts)
        except Exception as e:
            logger.error(f"Failed to embed/store knowledge batch {i}: {e}")

    # Store seed marker
    try:
        collection.add(
            ids=[SEED_MARKER_ID],
            documents=["Knowledge base seed complete."],
            metadatas=[{"source_type": "marker", "source": "system"}],
        )
    except Exception:
        pass

    logger.info(f"Knowledge base seeded: {total_stored} chunks from {len(txt_files)} documents.")
    return total_stored


def search_knowledge_base(query: str, n_results: int = 5, tag_filter: str = None) -> List[dict]:
    """
    Search the global knowledge collection. Optionally filter by tag substring.
    Returns list of {content, metadata, distance}.
    """
    try:
        import chromadb
        from chromadb.config import Settings
    except ImportError:
        return []

    try:
        db_path = str(Path(__file__).resolve().parent.parent.parent / "data" / "chroma")
        client = chromadb.PersistentClient(
            path=db_path,
            settings=Settings(anonymized_telemetry=False)
        )
        collection = client.get_or_create_collection(GLOBAL_COLLECTION)
    except Exception as e:
        logger.error(f"Knowledge base search init failed: {e}")
        return []

    embedder, jina_available = _get_embedder()

    try:
        where_filter = {"source_type": "compliance_doc"}
        if jina_available:
            query_emb = embedder([query])
            if not query_emb or not query_emb[0]:
                return []
            results = collection.query(
                query_embeddings=query_emb,
                n_results=min(n_results, 20),
                where=where_filter,
            )
        else:
            # Let ChromaDB's built-in embedder handle the query
            results = collection.query(
                query_texts=[query],
                n_results=min(n_results, 20),
                where=where_filter,
            )
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        dists = results.get("distances", [[]])[0]

        output = []
        for d, m, dist in zip(docs, metas, dists):
            if tag_filter and tag_filter.lower() not in (m.get("tags", "") or "").lower():
                continue
            output.append({"content": d, "metadata": m, "distance": dist})
        return output[:n_results]
    except Exception as e:
        logger.error(f"Knowledge base search failed: {e}")
        return []


def list_knowledge_documents() -> List[dict]:
    """Return a list of all seeded document names and chunk counts."""
    try:
        import chromadb
        from chromadb.config import Settings
    except ImportError:
        return []

    try:
        db_path = str(Path(__file__).resolve().parent.parent.parent / "data" / "chroma")
        client = chromadb.PersistentClient(
            path=db_path,
            settings=Settings(anonymized_telemetry=False)
        )
        collection = client.get_or_create_collection(GLOBAL_COLLECTION)
        all_items = collection.get(where={"source_type": "compliance_doc"})
        source_counts: dict = {}
        for meta in (all_items.get("metadatas") or []):
            src = meta.get("source", "unknown")
            source_counts[src] = source_counts.get(src, 0) + 1
        return [{"source": k, "chunks": v} for k, v in sorted(source_counts.items())]
    except Exception:
        return []


def _get_embedder():
    """
    Return (callable, jina_available: bool).
    If jina_available is True the callable produces 1024-dim Jina v3 vectors.
    Otherwise returns (dummy, False) and callers should omit embeddings= so
    ChromaDB uses its built-in all-MiniLM-L6-v2 (384-dim) embedder.
    """
    from app.config import settings
    jina_key = settings.JINA_API_KEY

    if jina_key:
        import requests as req

        def jina_embed(texts: List[str]) -> List[List[float]]:
            try:
                resp = req.post(
                    "https://api.jina.ai/v1/embeddings",
                    headers={"Authorization": f"Bearer {jina_key}", "Content-Type": "application/json"},
                    json={"model": "jina-embeddings-v3", "input": [{"text": t, "task": "retrieval.passage"} for t in texts]},
                    timeout=60,
                )
                resp.raise_for_status()
                return [item["embedding"] for item in resp.json().get("data", [])]
            except Exception as e:
                logger.error(f"Jina embedding failed during seeding: {e}")
                return [[] for _ in texts]

        return jina_embed, True

    # No embedding key — ChromaDB will use its own default embedder
    def dummy_embed(texts: List[str]) -> List[List[float]]:
        return [[] for _ in texts]

    logger.warning("No JINA_API_KEY found — knowledge base will use ChromaDB default embeddings.")
    return dummy_embed, False
