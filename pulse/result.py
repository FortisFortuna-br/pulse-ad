"""Structured, machine-readable views of an analysis (for --format json, stats)."""
from __future__ import annotations

from collections import Counter

from .model import Graph
from .pathfinder import TakeoverPath, find_paths, onprem_user_ids


def graph_stats(graph: Graph) -> dict:
    nodes_by_kind = Counter(f"{n.realm}/{n.kind}" for n in graph.nodes.values())
    edges_by_kind = Counter(e.kind for e in graph.edges)
    return {
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "bridge_edges": sum(1 for e in graph.edges if e.bridge),
        "nodes_by_kind": dict(sorted(nodes_by_kind.items())),
        "edges_by_kind": dict(sorted(edges_by_kind.items())),
    }


def exposure(graph: Graph) -> dict:
    """How exposed is the tenant: how many on-prem users can reach cloud admin."""
    footholds = onprem_user_ids(graph)
    paths = find_paths(graph, footholds)
    reached = {p.start.id for p in paths}
    return {
        "onprem_users": len(footholds),
        "can_reach_cloud_admin": len(reached),
        "admin_roles_reachable": sorted({p.goal.label for p in paths}),
    }


def path_to_dict(path: TakeoverPath, graph: Graph) -> dict:
    return {
        "foothold": path.start.label,
        "foothold_id": path.start.id,
        "goal": path.goal.label,
        "hops": path.hops,
        "crosses_bridge": path.crosses_bridge,
        "edges": [
            {
                "src": graph.nodes[e.src].label,
                "dst": graph.nodes[e.dst].label,
                "kind": e.kind,
                "bridge": e.bridge,
                "note": e.note,
            }
            for e in path.edges
        ],
    }


def analysis_to_dict(graph: Graph, findings, paths) -> dict:
    return {
        "summary": graph_stats(graph),
        "exposure": exposure(graph),
        "bridges": [
            {"kind": f.kind, "title": f.title, "detail": f.detail, "severity": f.severity}
            for f in findings
        ],
        "paths": [path_to_dict(p, graph) for p in paths],
    }
