"""
Topology API Router — graph data, blast radius computation.
"""
import json
import os
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.services.graph_builder import build_topology_graph, compute_blast_radius
from app.api.v1.auth import get_optional_user
from app.models.auth import User
from app.models.scan import ScanJob

router = APIRouter()

def get_superadmin_id(db: Session) -> UUID:
    sa_email = "superadmin@qushield.local"
    sa = db.query(User).filter(User.email == sa_email).first()
    return sa.id if sa else None

def check_scan_access(db: Session, scan_id: UUID, user: Optional[User]) -> bool:
    scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not scan: return False
    sa_id = get_superadmin_id(db)
    return (scan.user_id == sa_id) or (user and scan.user_id == user.id) or (user and user.id == sa_id)

@router.get("/scan/{scan_id}")
def get_topology_graph(
    scan_id: UUID,
    rebuild: bool = Query(False, description="Force rebuild graph from DB"),
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """
    Get topology graph for a scan.
    Returns nodes (domains, IPs, certificates, issuers) and edges (relationships).
    """
    if not check_scan_access(db, scan_id, user):
        raise HTTPException(status_code=404, detail="Scan not found")
        
    # Check for cached graph file
    graph_file = f"data/graphs/{scan_id}.json"
    if not rebuild and os.path.exists(graph_file):
        with open(graph_file, "r") as f:
            data = json.load(f)
        return {
            "scan_id": str(scan_id),
            "node_count": len(data.get("nodes", [])),
            "edge_count": len(data.get("edges", [])),
            "nodes": data.get("nodes", []),
            "edges": data.get("edges", []),
        }

    # Build from DB
    try:
        result = build_topology_graph(str(scan_id), db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to build topology: {e}")

    return {
        "scan_id": str(scan_id),
        "node_count": result["node_count"],
        "edge_count": result["edge_count"],
        "nodes": result["graph_data"]["nodes"],
        "edges": result["graph_data"]["edges"],
    }

@router.get("/scan/{scan_id}/blast-radius")
def get_blast_radius(
    scan_id: UUID,
    cert_fingerprint: str = Query(..., description="SHA256 fingerprint or CN of the certificate"),
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """
    Compute blast radius for a specific certificate -
    how many domains/assets would be affected if this cert is compromised.
    """
    if not check_scan_access(db, scan_id, user):
        raise HTTPException(status_code=404, detail="Scan not found")
        
    try:
        result = compute_blast_radius(str(scan_id), cert_fingerprint, db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Blast radius computation failed: {e}")

    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])

    return {
        "scan_id": str(scan_id),
        "certificate": result["certificate"],
        "blast_radius": result["blast_radius"],
        "affected_domains": result["affected_domains"],
    }

@router.get("/scan/{scan_id}/stats")
def get_topology_stats(
    scan_id: UUID,
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Summary topology statistics: node/edge counts, degree distribution."""
    if not check_scan_access(db, scan_id, user):
        raise HTTPException(status_code=404, detail="Scan not found")
        
    graph_file = f"data/graphs/{scan_id}.json"
    if not os.path.exists(graph_file):
        try:
            build_topology_graph(str(scan_id), db)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to build topology: {e}")

    if not os.path.exists(graph_file):
        raise HTTPException(status_code=404, detail="No topology data available")

    with open(graph_file) as f:
        data = json.load(f)

    nodes = data.get("nodes", [])
    edges = data.get("edges", [])

    # Count by type
    type_dist = {}
    for n in nodes:
        ntype = n.get("type", "unknown")
        type_dist[ntype] = type_dist.get(ntype, 0) + 1

    # Relation distribution
    rel_dist = {}
    for e in edges:
        rel = e.get("relation", "unknown")
        rel_dist[rel] = rel_dist.get(rel, 0) + 1

    return {
        "scan_id": str(scan_id),
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "node_type_distribution": type_dist,
        "relationship_distribution": rel_dist,
    }
