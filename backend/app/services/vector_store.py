"""
Vector Store Service — Initializes ChromaDB and manages embeddings/retrieval
with strict tenant isolation.
"""
import os
import logging
from typing import List, Dict, Any, Optional

try:
    import chromadb
    from chromadb.config import Settings
except ImportError:
    chromadb = None

from app.services.embedding_service import get_embedding_provider
from app.models.auth import User

logger = logging.getLogger(__name__)

# Single global instance
_chroma_client = None

def get_chroma_client():
    global _chroma_client
    if not chromadb:
        logger.warning("ChromaDB not installed. Vector store disables.")
        return None
        
    if _chroma_client is None:
        # Use local persistent storage inside data dir
        db_path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "chroma")
        os.makedirs(db_path, exist_ok=True)
        try:
            _chroma_client = chromadb.PersistentClient(
                path=db_path,
                settings=Settings(anonymized_telemetry=False)
            )
            logger.info(f"Initialized ChromaDB at {db_path}")
        except Exception as e:
            logger.error(f"Failed to initialize ChromaDB: {e}")
            _chroma_client = None
    return _chroma_client


class VectorStore:
    def __init__(self, user: User):
        self.user = user
        self.client = get_chroma_client()
        self.embedder = get_embedding_provider(user)
        
        if self.client:
            # We use a single shared collection for scans to maximize vector space utility,
            # but STRICTLY partition via metadata {"user_id": user_id}.
            self.collection = self.client.get_or_create_collection("qushield_knowledge")
        else:
            self.collection = None

    def embed_and_store(self, texts: List[str], metadatas: List[Dict[str, Any]], ids: List[str]):
        """Embed and store texts with user_id forcefully injected to metadata."""
        if not self.collection:
            logger.error("Cannot store vectors, ChromaDB unavailable.")
            return False
            
        if not texts:
            return True

        # Generate embeddings
        embeddings = self.embedder.embed(texts)
        
        # Enforce strict tenant isolation: Force inject user_id into metadata
        user_id_str = str(self.user.id)
        for meta in metadatas:
            if meta is None:
                meta = {}
            meta["user_id"] = user_id_str
            
        try:
            self.collection.add(
                ids=ids,
                documents=texts,
                embeddings=embeddings,
                metadatas=metadatas
            )
            logger.info(f"Stored {len(texts)} vector chunks for user {user_id_str}")
            return True
        except Exception as e:
            logger.error(f"Vector store add failed: {e}")
            return False

    def search(self, query: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Semantic search isolated entirely to the querying user's data."""
        if not self.collection:
            logger.error("Cannot search vectors, ChromaDB unavailable.")
            return []
            
        query_emb = self.embedder.embed([query])
        if not query_emb or not query_emb[0]:
            return []
            
        user_id_str = str(self.user.id)
        
        try:
            results = self.collection.query(
                query_embeddings=query_emb,
                n_results=n_results,
                where={"user_id": user_id_str}  # 🚨 STRICT ISOLATION FILTER
            )
            
            # Format output gracefully
            docs = results.get("documents", [[]])[0]
            metas = results.get("metadatas", [[]])[0]
            dists = results.get("distances", [[]])[0]
            
            response = []
            for d, m, dist in zip(docs, metas, dists):
                response.append({
                    "content": d,
                    "metadata": m,
                    "distance": dist
                })
            return response
            
        except Exception as e:
            logger.error(f"Vector search failed: {e}")
            return []
