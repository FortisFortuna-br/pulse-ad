"""Find the shortest on-prem -> cloud-admin takeover paths."""
from __future__ import annotations

from dataclasses import dataclass

from .model import CLOUD, Edge, Graph, Node


def is_cloud_admin(node: Node) -> bool:
    return node.realm == CLOUD and node.kind == "Role" and bool(node.props.get("privileged"))


@dataclass
class TakeoverPath:
    start: Node
    goal: Node
    edges: list[Edge]

    @property
    def crosses_bridge(self) -> bool:
        return any(edge.bridge for edge in self.edges)

    @property
    def hops(self) -> int:
        return len(self.edges)


def find_paths(graph: Graph, footholds: list[str]) -> list[TakeoverPath]:
    """For each foothold id, return the shortest path to any privileged cloud
    role, sorted shortest-first. Footholds that reach nothing are omitted."""
    paths: list[TakeoverPath] = []
    for start_id in footholds:
        start_node = graph.nodes.get(start_id)
        if start_node is None:
            continue
        edges = graph.shortest_path(start_id, is_cloud_admin)
        if not edges:
            continue
        goal = graph.nodes[edges[-1].dst]
        paths.append(TakeoverPath(start=start_node, goal=goal, edges=edges))
    paths.sort(key=lambda p: p.hops)
    return paths


def onprem_user_ids(graph: Graph) -> list[str]:
    """Every on-prem user - the default set of candidate footholds."""
    from .model import ONPREM
    return [n.id for n in graph.nodes.values() if n.realm == ONPREM and n.kind == "User"]
