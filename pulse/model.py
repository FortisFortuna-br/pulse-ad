"""Pulse core graph model.

A small, dependency-free identity graph spanning two realms:
on-prem Active Directory and the cloud (Entra ID). Nodes are identities
and assets; edges are relationships and, crucially, the *bridge* edges
that let an on-prem compromise become a cloud compromise.

Pulse never touches a live target. It only reasons over data that was
already collected (SharpHound, AzureHound, ROADrecon) by an operator who
is authorized to test the tenant/domain in question.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Optional

# Realms
ONPREM = "onprem"
CLOUD = "cloud"


@dataclass
class Node:
    id: str               # stable identifier (on-prem: SID, cloud: object id)
    kind: str             # "User", "Computer", "Group", "Role", "ServicePrincipal"
    label: str            # human-readable name
    realm: str            # ONPREM or CLOUD
    props: dict = field(default_factory=dict)


@dataclass
class Edge:
    src: str
    dst: str
    kind: str             # "MemberOf", "AdminTo", "HasRole", "SyncedTo", ...
    bridge: bool = False  # True if this edge crosses on-prem <-> cloud
    note: str = ""
    props: dict = field(default_factory=dict)


class Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._adj: dict[str, list[Edge]] = {}

    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing:
            # Same identity seen twice (e.g. as group member then as user
            # object): merge props, keep the richer/first label+kind.
            existing.props.update({k: v for k, v in node.props.items() if v is not None})
            if existing.kind == "Unknown" and node.kind != "Unknown":
                existing.kind = node.kind
                existing.label = node.label
            return existing
        self.nodes[node.id] = node
        self._adj.setdefault(node.id, [])
        return node

    def ensure(self, node_id: str) -> None:
        """Reference an endpoint that may not have a full object yet."""
        if node_id not in self.nodes:
            self.add_node(Node(id=node_id, kind="Unknown", label=node_id, realm=ONPREM))

    def add_edge(self, edge: Edge) -> None:
        self.ensure(edge.src)
        self.ensure(edge.dst)
        self.edges.append(edge)
        self._adj[edge.src].append(edge)

    def out_edges(self, node_id: str) -> list[Edge]:
        return self._adj.get(node_id, [])

    def find(self, name_or_id: str) -> Optional[Node]:
        """Resolve a node by id, or by case-insensitive label match
        (with or without the @DOMAIN suffix)."""
        if name_or_id in self.nodes:
            return self.nodes[name_or_id]
        needle = name_or_id.strip().lower()
        for node in self.nodes.values():
            label = node.label.lower()
            if label == needle or label.split("@", 1)[0] == needle:
                return node
        return None

    def shortest_path(
        self, start: str, goal: Callable[[Node], bool]
    ) -> Optional[list[Edge]]:
        """Breadth-first search from `start` to the nearest node for which
        `goal(node)` is True. Returns the list of edges on that path, an
        empty list if `start` itself is a goal, or None if unreachable."""
        if start not in self._adj:
            return None
        start_node = self.nodes.get(start)
        if start_node and goal(start_node):
            return []
        visited = {start}
        queue: deque[tuple[str, list[Edge]]] = deque([(start, [])])
        while queue:
            cur, path = queue.popleft()
            for edge in self._adj.get(cur, []):
                nxt = edge.dst
                if nxt in visited:
                    continue
                visited.add(nxt)
                new_path = path + [edge]
                node = self.nodes.get(nxt)
                if node and goal(node):
                    return new_path
                queue.append((nxt, new_path))
        return None
