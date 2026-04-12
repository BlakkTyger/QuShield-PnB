"use client";

import { useState, useEffect, useRef, useMemo } from "react";
import * as d3 from "d3";
import { X, ZoomIn, ZoomOut, Maximize2, Filter, Search } from "lucide-react";
import { useScans, useTopology } from "@/lib/hooks";
import { RiskBadge, EmptyState, Skeleton } from "@/components/ui";
import type { TopologyNode, TopologyEdge } from "@/lib/types";

const NODE_TYPE_COLORS: Record<string, string> = {
  domain: "#3b82f6",
  ip: "#6b7280",
  certificate: "#eab308",
  service: "#8b5cf6",
  issuer: "#f97316",
  organization: "#14b8a6",
};

const NODE_TYPE_RADIUS: Record<string, number> = {
  domain: 6,
  ip: 5,
  certificate: 7,
  service: 5,
  issuer: 8,
  organization: 9,
};

interface SimNode extends d3.SimulationNodeDatum {
  id: string;
  label: string;
  type: string;
  risk_level: string | null;
  metadata: Record<string, unknown>;
}

interface SimLink extends d3.SimulationLinkDatum<SimNode> {
  type: string;
}

export default function TopologyPage() {
  const svgRef = useRef<SVGSVGElement>(null);
  const zoomRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<SimNode | null>(null);
  const [filterType, setFilterType] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState("");
  const [showSearchDropdown, setShowSearchDropdown] = useState(false);
  const nodesRef = useRef<SimNode[]>([]);
  const searchInputRef = useRef<HTMLInputElement>(null);

  const { data: scans } = useScans();
  useEffect(() => {
    const stored = typeof window !== "undefined" ? localStorage.getItem("qushield_scan_id") : null;
    if (stored) { setScanId(stored); return; }
    if (scans?.length) {
      const completed = scans.find((s) => s.status === "completed");
      if (completed) setScanId(completed.scan_id);
    }
  }, [scans]);

  const { data: topology, isLoading } = useTopology(scanId);

  // Zoom controls
  const handleZoomIn = () => {
    if (!svgRef.current || !zoomRef.current) return;
    d3.select(svgRef.current).transition().duration(300).call(zoomRef.current.scaleBy, 1.4);
  };
  const handleZoomOut = () => {
    if (!svgRef.current || !zoomRef.current) return;
    d3.select(svgRef.current).transition().duration(300).call(zoomRef.current.scaleBy, 0.7);
  };
  const handleZoomReset = () => {
    if (!svgRef.current || !zoomRef.current) return;
    d3.select(svgRef.current).transition().duration(500).call(zoomRef.current.transform, d3.zoomIdentity);
  };

  const handleSearchSelect = (nodeId: string) => {
    const node = nodesRef.current.find((n) => n.id === nodeId);
    if (!node || !svgRef.current || !zoomRef.current || node.x == null || node.y == null) return;
    const svg = d3.select(svgRef.current);
    const width = svgRef.current.clientWidth;
    const height = svgRef.current.clientHeight;
    const scale = 2;
    const transform = d3.zoomIdentity
      .translate(width / 2, height / 2)
      .scale(scale)
      .translate(-node.x, -node.y);
    svg.transition().duration(600).call(zoomRef.current.transform, transform);

    // Pulse highlight
    const g = svg.select("g");
    g.selectAll(".search-highlight").remove();
    g.append("circle")
      .attr("class", "search-highlight")
      .attr("cx", node.x)
      .attr("cy", node.y)
      .attr("r", 12)
      .attr("fill", "none")
      .attr("stroke", "#fff")
      .attr("stroke-width", 2.5)
      .attr("opacity", 1)
      .transition().duration(1500)
      .attr("r", 30)
      .attr("opacity", 0)
      .remove();
    g.append("circle")
      .attr("class", "search-highlight")
      .attr("cx", node.x)
      .attr("cy", node.y)
      .attr("r", 12)
      .attr("fill", "none")
      .attr("stroke", "#fff")
      .attr("stroke-width", 2)
      .attr("opacity", 0.8)
      .transition().delay(300).duration(1500)
      .attr("r", 35)
      .attr("opacity", 0)
      .remove();

    setSelectedNode(node);
    setSearchQuery("");
    setShowSearchDropdown(false);
  };

  const searchResults = useMemo(() => {
    if (!searchQuery.trim() || !topology?.nodes) return [];
    const q = searchQuery.toLowerCase();
    return topology.nodes
      .filter((n) => (n.label || n.id).toLowerCase().includes(q))
      .slice(0, 8);
  }, [searchQuery, topology]);

  // Build D3 graph
  useEffect(() => {
    if (!topology || !svgRef.current) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const width = svgRef.current.clientWidth;
    const height = svgRef.current.clientHeight;

    // --- Glow filter ---
    const defs = svg.append("defs");
    Object.entries(NODE_TYPE_COLORS).forEach(([type, color]) => {
      const filter = defs.append("filter").attr("id", `glow-${type}`).attr("x", "-50%").attr("y", "-50%").attr("width", "200%").attr("height", "200%");
      filter.append("feGaussianBlur").attr("stdDeviation", "3").attr("result", "blur");
      filter.append("feFlood").attr("flood-color", color).attr("flood-opacity", "0.4").attr("result", "color");
      filter.append("feComposite").attr("in", "color").attr("in2", "blur").attr("operator", "in").attr("result", "glow");
      const merge = filter.append("feMerge");
      merge.append("feMergeNode").attr("in", "glow");
      merge.append("feMergeNode").attr("in", "SourceGraphic");
    });

    // Filter nodes/edges
    let nodes: SimNode[] = topology.nodes.map((n) => ({
      ...n,
      x: width / 2 + (Math.random() - 0.5) * 200,
      y: height / 2 + (Math.random() - 0.5) * 200,
    }));
    nodesRef.current = nodes;

    let links: SimLink[] = topology.edges.map((e) => ({
      source: e.source,
      target: e.target,
      type: e.type,
    }));

    if (filterType) {
      const nodeIds = new Set(nodes.filter((n) => n.type === filterType).map((n) => n.id));
      links.forEach((l) => {
        const s = typeof l.source === "string" ? l.source : (l.source as SimNode).id;
        const t = typeof l.target === "string" ? l.target : (l.target as SimNode).id;
        if (nodeIds.has(s)) nodeIds.add(t);
        if (nodeIds.has(t)) nodeIds.add(s);
      });
      nodes = nodes.filter((n) => nodeIds.has(n.id));
      links = links.filter((l) => {
        const s = typeof l.source === "string" ? l.source : (l.source as SimNode).id;
        const t = typeof l.target === "string" ? l.target : (l.target as SimNode).id;
        return nodeIds.has(s) && nodeIds.has(t);
      });
    }

    // Count connections per node for sizing
    const connectionCount: Record<string, number> = {};
    links.forEach((l) => {
      const s = typeof l.source === "string" ? l.source : (l.source as SimNode).id;
      const t = typeof l.target === "string" ? l.target : (l.target as SimNode).id;
      connectionCount[s] = (connectionCount[s] || 0) + 1;
      connectionCount[t] = (connectionCount[t] || 0) + 1;
    });

    // Zoom
    const g = svg.append("g");
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 6])
      .on("zoom", (event) => {
        g.attr("transform", event.transform);
      });
    svg.call(zoom);
    zoomRef.current = zoom;

    // Auto-fit after simulation settles
    const totalNodes = nodes.length;
    const scaleFactor = Math.min(1, 300 / Math.sqrt(totalNodes));

    // Simulation with stronger forces for cleaner layout
    const simulation = d3
      .forceSimulation(nodes)
      .force("link", d3.forceLink(links).id((d: unknown) => (d as SimNode).id).distance(60).strength(0.3))
      .force("charge", d3.forceManyBody().strength(-200).distanceMax(400))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius((d: unknown) => {
        const nd = d as SimNode;
        const baseR = NODE_TYPE_RADIUS[nd.type] || 6;
        const conns = connectionCount[nd.id] || 0;
        return baseR + Math.min(conns, 10) + 8;
      }))
      .force("x", d3.forceX(width / 2).strength(0.03))
      .force("y", d3.forceY(height / 2).strength(0.03));

    // Links with subtle gradient by type
    const link = g
      .selectAll("line")
      .data(links)
      .enter()
      .append("line")
      .attr("stroke", (d: SimLink) => {
        if (d.type === "cert_chain") return "rgba(234,179,8,0.15)";
        if (d.type === "resolves_to") return "rgba(59,130,246,0.15)";
        return "rgba(255,255,255,0.06)";
      })
      .attr("stroke-width", (d: SimLink) => d.type === "cert_chain" ? 1.5 : 0.8)
      .attr("stroke-dasharray", (d: SimLink) =>
        d.type === "cert_chain" ? "4 2" : d.type === "resolves_to" ? "" : "2 2"
      );

    // Nodes
    const node = g
      .selectAll("g.node")
      .data(nodes)
      .enter()
      .append("g")
      .attr("class", "node")
      .style("cursor", "pointer")
      .call(
        d3.drag<SVGGElement, SimNode>()
          .on("start", (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on("drag", (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on("end", (event, d) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          })
      );

    // Node shapes with vivid colors and glow
    node.each(function (d) {
      const el = d3.select(this);
      const color = NODE_TYPE_COLORS[d.type] || "#6b7280";
      const conns = connectionCount[d.id] || 0;
      const baseR = NODE_TYPE_RADIUS[d.type] || 6;
      const r = baseR + Math.min(conns * 0.5, 5);

      if (d.type === "ip") {
        el.append("rect")
          .attr("x", -r)
          .attr("y", -r)
          .attr("width", r * 2)
          .attr("height", r * 2)
          .attr("rx", 3)
          .attr("fill", color)
          .attr("stroke", "rgba(255,255,255,0.3)")
          .attr("stroke-width", 1.5)
          .attr("filter", `url(#glow-${d.type})`);
      } else if (d.type === "certificate") {
        el.append("polygon")
          .attr("points", `0,${-r} ${r},0 0,${r} ${-r},0`)
          .attr("fill", color)
          .attr("stroke", "rgba(255,255,255,0.3)")
          .attr("stroke-width", 1.5)
          .attr("filter", `url(#glow-${d.type})`);
      } else {
        el.append("circle")
          .attr("r", r)
          .attr("fill", color)
          .attr("stroke", "rgba(255,255,255,0.3)")
          .attr("stroke-width", 1.5)
          .attr("filter", `url(#glow-${d.type})`);
      }
    });

    // Node labels — only show for hub nodes (>3 connections) to reduce clutter
    node
      .filter((d) => d.type !== "certificate")
      .append("text")
      .attr("dy", (d) => {
        const r = (NODE_TYPE_RADIUS[d.type] || 6) + Math.min((connectionCount[d.id] || 0) * 0.5, 5);
        return r + 12;
      })
      .attr("text-anchor", "middle")
      .attr("fill", "rgba(255,255,255,0.6)")
      .attr("font-size", "9px")
      .attr("font-family", "Inter, sans-serif")
      .attr("pointer-events", "none")
      .text((d) => {
        const label = d.label || d.id;
        return label.length > 24 ? label.slice(0, 22) + "…" : label;
      });

    // Click handler
    node.on("click", (event, d) => {
      event.stopPropagation();
      setSelectedNode(d);
    });

    // Hover — highlight connections
    node
      .on("mouseenter", function (event, d) {
        const hoveredId = d.id;
        // Highlight node
        d3.select(this).select("circle, rect, polygon")
          .attr("stroke", "#fff")
          .attr("stroke-width", 2.5);
        // Highlight connected links
        link.attr("stroke-opacity", (l: SimLink) => {
          const s = typeof l.source === "string" ? l.source : (l.source as SimNode).id;
          const t = typeof l.target === "string" ? l.target : (l.target as SimNode).id;
          return (s === hoveredId || t === hoveredId) ? 1 : 0.3;
        }).attr("stroke-width", (l: SimLink) => {
          const s = typeof l.source === "string" ? l.source : (l.source as SimNode).id;
          const t = typeof l.target === "string" ? l.target : (l.target as SimNode).id;
          return (s === hoveredId || t === hoveredId) ? 2 : 0.5;
        });
        // Dim other nodes
        node.style("opacity", (n: SimNode) => {
          if (n.id === hoveredId) return "1";
          // Check if connected
          const connected = links.some((l) => {
            const s = typeof l.source === "string" ? l.source : (l.source as SimNode).id;
            const t = typeof l.target === "string" ? l.target : (l.target as SimNode).id;
            return (s === hoveredId && t === n.id) || (t === hoveredId && s === n.id);
          });
          return connected ? "1" : "0.2";
        });
      })
      .on("mouseleave", function () {
        d3.select(this).select("circle, rect, polygon")
          .attr("stroke", "rgba(255,255,255,0.3)")
          .attr("stroke-width", 1.5);
        link
          .attr("stroke-opacity", 1)
          .attr("stroke-width", (d: SimLink) => d.type === "cert_chain" ? 1.5 : 0.8);
        node.style("opacity", "1");
      });

    // Tick
    simulation.on("tick", () => {
      link
        .attr("x1", (d: SimLink) => (d.source as SimNode).x || 0)
        .attr("y1", (d: SimLink) => (d.source as SimNode).y || 0)
        .attr("x2", (d: SimLink) => (d.target as SimNode).x || 0)
        .attr("y2", (d: SimLink) => (d.target as SimNode).y || 0);

      node.attr("transform", (d) => `translate(${d.x || 0},${d.y || 0})`);
    });

    // Click background to deselect
    svg.on("click", () => setSelectedNode(null));

    // Auto-fit after simulation settles
    simulation.on("end", () => {
      // Calculate bounding box
      let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
      nodes.forEach((n) => {
        if (n.x! < minX) minX = n.x!;
        if (n.x! > maxX) maxX = n.x!;
        if (n.y! < minY) minY = n.y!;
        if (n.y! > maxY) maxY = n.y!;
      });
      const padding = 60;
      const bboxWidth = maxX - minX + padding * 2;
      const bboxHeight = maxY - minY + padding * 2;
      const scale = Math.min(width / bboxWidth, height / bboxHeight, 1.2);
      const centerX = (minX + maxX) / 2;
      const centerY = (minY + maxY) / 2;
      const transform = d3.zoomIdentity
        .translate(width / 2, height / 2)
        .scale(scale)
        .translate(-centerX, -centerY);
      svg.transition().duration(800).call(zoom.transform, transform);
    });

    return () => {
      simulation.stop();
    };
  }, [topology, filterType]);

  if (!scanId) {
    return <EmptyState message="No scan data available. Run a Quick Scan first." />;
  }

  // Unique node types for filter
  const nodeTypes = topology?.nodes
    ? [...new Set(topology.nodes.map((n) => n.type))]
    : [];

  // Count by type
  const typeCounts: Record<string, number> = {};
  topology?.nodes.forEach((n) => {
    typeCounts[n.type] = (typeCounts[n.type] || 0) + 1;
  });

  return (
    <div className="animate-fade-in" style={{ height: "calc(100vh - 120px)" }}>
      {/* Controls */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-black" style={{ color: "var(--text-primary)" }}>
            Topology Map
          </h1>
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            {topology?.nodes.length || 0} nodes • {topology?.edges.length || 0} edges
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Search node */}
          <div className="relative">
            <div className="flex items-center gap-2" style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "4px 10px" }}>
              <Search size={13} style={{ color: "var(--text-muted)" }} />
              <input
                ref={searchInputRef}
                type="text"
                placeholder="Search node…"
                className="text-xs bg-transparent outline-none"
                style={{ color: "var(--text-primary)", width: "160px" }}
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); setShowSearchDropdown(true); }}
                onFocus={() => setShowSearchDropdown(true)}
                onBlur={() => setTimeout(() => setShowSearchDropdown(false), 200)}
              />
            </div>
            {showSearchDropdown && searchResults.length > 0 && (
              <div
                className="absolute top-full left-0 mt-1 w-[260px] rounded-lg overflow-hidden shadow-xl z-30"
                style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}
              >
                {searchResults.map((n) => (
                  <button
                    key={n.id}
                    className="w-full text-left px-3 py-2 text-xs flex items-center gap-2 transition-colors"
                    style={{ color: "var(--text-primary)" }}
                    onMouseDown={() => handleSearchSelect(n.id)}
                    onMouseEnter={(e) => { (e.target as HTMLElement).style.background = "rgba(255,255,255,0.05)"; }}
                    onMouseLeave={(e) => { (e.target as HTMLElement).style.background = "transparent"; }}
                  >
                    <span className="w-2.5 h-2.5 rounded-sm flex-shrink-0" style={{ background: NODE_TYPE_COLORS[n.type] || "#6b7280" }} />
                    <span className="truncate">{n.label || n.id}</span>
                    <span className="ml-auto text-[10px] capitalize" style={{ color: "var(--text-muted)" }}>{n.type}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
          {/* Filter by type */}
          <div className="flex items-center gap-2">
            <Filter size={14} style={{ color: "var(--text-muted)" }} />
            <select
              className="py-1.5 px-3 text-xs rounded-lg"
              style={{
                background: "var(--bg-card)",
                border: "1px solid var(--border-subtle)",
                color: "var(--text-primary)",
                outline: "none",
              }}
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
            >
              <option value="">All Types</option>
              {nodeTypes.map((t) => (
                <option key={t} value={t}>{t} ({typeCounts[t] || 0})</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Legend */}
      <div className="flex gap-4 mb-3">
        {Object.entries(NODE_TYPE_COLORS).map(([type, color]) => (
          <div key={type} className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-sm" style={{ background: color, boxShadow: `0 0 6px ${color}` }} />
            <span className="text-[10px] capitalize" style={{ color: "var(--text-muted)" }}>
              {type} {typeCounts[type] ? `(${typeCounts[type]})` : ""}
            </span>
          </div>
        ))}
      </div>

      {/* Graph Canvas */}
      <div
        className="glass-card-static relative overflow-hidden"
        style={{ height: "calc(100% - 100px)" }}
      >
        {isLoading ? (
          <div className="flex items-center justify-center h-full">
            <Skeleton width={200} height={30} />
          </div>
        ) : (
          <svg
            ref={svgRef}
            width="100%"
            height="100%"
            style={{ background: "transparent" }}
          />
        )}

        {/* Zoom Controls — bottom right */}
        <div
          className="absolute bottom-4 right-4 flex flex-col gap-1.5"
          style={{ zIndex: 20 }}
        >
          <button
            onClick={handleZoomIn}
            className="w-8 h-8 flex items-center justify-center rounded-md transition-colors"
            style={{
              background: "rgba(255,255,255,0.08)",
              border: "1px solid rgba(255,255,255,0.12)",
              color: "var(--text-secondary)",
            }}
            title="Zoom in"
          >
            <ZoomIn size={14} />
          </button>
          <button
            onClick={handleZoomOut}
            className="w-8 h-8 flex items-center justify-center rounded-md transition-colors"
            style={{
              background: "rgba(255,255,255,0.08)",
              border: "1px solid rgba(255,255,255,0.12)",
              color: "var(--text-secondary)",
            }}
            title="Zoom out"
          >
            <ZoomOut size={14} />
          </button>
          <button
            onClick={handleZoomReset}
            className="w-8 h-8 flex items-center justify-center rounded-md transition-colors"
            style={{
              background: "rgba(255,255,255,0.08)",
              border: "1px solid rgba(255,255,255,0.12)",
              color: "var(--text-secondary)",
            }}
            title="Fit to screen"
          >
            <Maximize2 size={14} />
          </button>
        </div>
      </div>

      {/* Detail Panel */}
      {selectedNode && (
        <>
          <div
            className="fixed inset-0 z-40"
            style={{ background: "rgba(0,0,0,0.3)" }}
            onClick={() => setSelectedNode(null)}
          />
          <div
            className="fixed top-0 right-0 w-[400px] h-full z-50 p-6 overflow-y-auto"
            style={{
              background: "var(--bg-secondary)",
              borderLeft: "1px solid var(--border-subtle)",
            }}
          >
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-bold" style={{ color: "var(--text-primary)" }}>
                Node Detail
              </h2>
              <button onClick={() => setSelectedNode(null)} style={{ color: "var(--text-muted)" }}>
                <X size={18} />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <span className="text-xs uppercase" style={{ color: "var(--text-muted)" }}>Label</span>
                <p className="text-base font-bold break-all" style={{ color: "var(--text-primary)" }}>
                  {selectedNode.label || selectedNode.id}
                </p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-xs" style={{ color: "var(--text-muted)" }}>Type</span>
                  <div className="flex items-center gap-2 mt-1">
                    <span
                      className="w-3 h-3 rounded-sm"
                      style={{ background: NODE_TYPE_COLORS[selectedNode.type] || "#888", boxShadow: `0 0 6px ${NODE_TYPE_COLORS[selectedNode.type] || "#888"}` }}
                    />
                    <span className="text-sm capitalize" style={{ color: "var(--text-primary)" }}>
                      {selectedNode.type}
                    </span>
                  </div>
                </div>
                {selectedNode.risk_level && (
                  <div>
                    <span className="text-xs" style={{ color: "var(--text-muted)" }}>Risk</span>
                    <div className="mt-1">
                      <RiskBadge classification={selectedNode.risk_level} />
                    </div>
                  </div>
                )}
              </div>

              {/* Metadata */}
              {Object.keys(selectedNode.metadata || {}).length > 0 && (
                <div>
                  <span className="text-xs uppercase" style={{ color: "var(--text-muted)" }}>Metadata</span>
                  <div className="mt-2 space-y-1.5">
                    {Object.entries(selectedNode.metadata).map(([key, val]) => (
                      <div key={key} className="flex justify-between text-xs">
                        <span style={{ color: "var(--text-secondary)" }}>{key}</span>
                        <span className="font-mono text-right max-w-[200px] truncate" style={{ color: "var(--text-primary)" }}>
                          {String(val)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
