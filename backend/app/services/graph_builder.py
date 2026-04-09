import networkx as nx
import json
import os
import logging
from app.models.asset import Asset
from app.models.certificate import Certificate

logger = logging.getLogger(__name__)

def build_topology_graph(scan_id: str, db) -> dict:
    G = nx.DiGraph()

    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    for asset in assets:
        G.add_node(asset.hostname, type="Domain", ip=asset.ip_v4, risk_class=asset.asset_type)
        if asset.ip_v4:
            G.add_node(asset.ip_v4, type="IP")
            G.add_edge(asset.hostname, asset.ip_v4, relation="RESOLVES_TO")

        # Map Certificates
        certs = db.query(Certificate).filter(Certificate.asset_id == asset.id).all()
        for cert in certs:
            fingerprint = cert.sha256_fingerprint or cert.common_name
            G.add_node(fingerprint, type="Certificate", cn=cert.common_name, key_length=cert.key_length)
            G.add_edge(asset.hostname, fingerprint, relation="USES_CERTIFICATE")
            if cert.issuer:
                G.add_node(cert.issuer, type="Issuer")
                G.add_edge(fingerprint, cert.issuer, relation="ISSUED_BY")

    data = {
        "nodes": [{"id": n, **attr} for n, attr in G.nodes(data=True)],
        "edges": [{"source": u, "target": v, **attr} for u, v, attr in G.edges(data=True)]
    }

    # Ensure output directory exists
    dir_path = "data/graphs"
    os.makedirs(dir_path, exist_ok=True)
    file_path = os.path.join(dir_path, f"{scan_id}.json")
    
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)

    logger.info(f"Graph topology saved for mapping {len(G.nodes)} nodes to {file_path}")
    return {"graph_file": file_path, "node_count": len(G.nodes), "edge_count": len(G.edges), "graph_data": data}

def compute_blast_radius(scan_id: str, cert_fingerprint: str, db) -> dict:
    """
    Computes blast radius of a specific certificate across shared topology boundaries.
    """
    topology = build_topology_graph(scan_id, db)
    G = nx.DiGraph()
    for node in topology["graph_data"]["nodes"]:
        G.add_node(node["id"], **node)
    for edge in topology["graph_data"]["edges"]:
        G.add_edge(edge["source"], edge["target"], **edge)

    # Convert to undirected graph for backward traversal of USES_CERTIFICATE
    U = G.to_undirected()

    if cert_fingerprint not in U:
        return {"error": "Certificate fingerprint not found in topology graph."}

    reachable = list(nx.bfs_tree(U, cert_fingerprint))
    affected_domains = [n for n in reachable if U.nodes[n].get("type") == "Domain"]

    return {
        "certificate": cert_fingerprint,
        "blast_radius": len(affected_domains),
        "affected_domains": affected_domains
    }
