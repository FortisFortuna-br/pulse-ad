"""Ingest cloud (Entra ID) data.

Two input shapes are accepted:

1. **Real AzureHound output** -- ``{"meta": ..., "data": [{"kind": ...,
   "data": {...}}]}`` where each item is a typed Entra object (``AZUser``,
   ``AZGroup``, ``AZRole``, ``AZRoleAssignment``, ``AZServicePrincipal`` ...).
   This is what ``azurehound list`` produces for BloodHound CE.

2. **Normalized export** -- ``{"users": [...], "roles": [...]}`` -- a compact
   shape handy for quick tests and tools that pre-shape their data.

The linchpin field is ``onPremisesSecurityIdentifier``: it is how Entra records
which cloud identity is the same person as an on-prem SID. Pulse uses it to weld
the two graphs together (see :mod:`pulse.bridge`).
"""
from __future__ import annotations

import json

from ..model import CLOUD, Edge, Graph, Node

# Entra directory roles that effectively own the tenant.
PRIVILEGED_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Hybrid Identity Administrator",
    "Intune Administrator",
    "Security Administrator",
}


def _first(d: dict, *names, default=None):
    for name in names:
        if d.get(name) is not None:
            return d[name]
    return default


def load(path: str, graph: Graph | None = None) -> Graph:
    graph = graph or Graph()
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if _is_azurehound(doc):
        _load_azurehound(doc, graph)
    else:
        _load_normalized(doc, graph)
    return graph


def _is_azurehound(doc: dict) -> bool:
    data = doc.get("data")
    if isinstance(data, list) and not doc.get("users"):
        return any(isinstance(item, dict) and "kind" in item for item in data[:5])
    return False


# --- real AzureHound -------------------------------------------------------

def _add_cloud_user(graph: Graph, obj: dict) -> None:
    oid = _first(obj, "id", "Id", "objectId")
    if not oid:
        return
    graph.add_node(Node(
        id=oid, kind="User",
        label=_first(obj, "userPrincipalName", "UserPrincipalName", "displayName", default=oid),
        realm=CLOUD,
        props={"onprem_sid": _first(obj, "onPremisesSecurityIdentifier", "OnPremisesSecurityIdentifier")},
    ))


def _add_cloud_role(graph: Graph, obj: dict, template_index: dict) -> None:
    rid = _first(obj, "id", "Id")
    if not rid:
        return
    name = _first(obj, "displayName", "DisplayName", default=rid)
    graph.add_node(Node(id=rid, kind="Role", label=name, realm=CLOUD,
                        props={"privileged": name in PRIVILEGED_ROLES}))
    template = _first(obj, "templateId", "roleTemplateId", "TemplateId")
    if template:
        template_index[template] = rid
    for member in obj.get("members", []) or []:  # some versions embed members
        mid = member.get("id") if isinstance(member, dict) else member
        if mid:
            graph.add_edge(Edge(src=mid, dst=rid, kind="HasRole"))


def _load_azurehound(doc: dict, graph: Graph) -> None:
    template_index: dict[str, str] = {}
    assignments: list[tuple[str, str]] = []

    for item in doc.get("data", []):
        if not isinstance(item, dict):
            continue
        kind = (item.get("kind") or "").lower()
        data = item.get("data") or {}
        if kind == "azuser":
            _add_cloud_user(graph, data)
        elif kind == "azgroup":
            gid = _first(data, "id", "Id")
            if gid:
                graph.add_node(Node(id=gid, kind="Group",
                                    label=_first(data, "displayName", default=gid), realm=CLOUD))
        elif kind in ("azserviceprincipal", "azapp", "azapplication"):
            sid = _first(data, "id", "Id")
            if sid:
                graph.add_node(Node(id=sid, kind="ServicePrincipal",
                                    label=_first(data, "displayName", default=sid), realm=CLOUD))
        elif kind == "azrole":
            _add_cloud_role(graph, data, template_index)
        elif kind in ("azroleassignment", "azroleeligibility"):
            principal = _first(data, "principalId", "PrincipalId")
            role_ref = _first(data, "roleDefinitionId", "RoleDefinitionId", "roleId", "RoleId")
            if principal and role_ref:
                assignments.append((principal, role_ref))

    # Resolve assignments once every role is known (template id -> node id).
    for principal, role_ref in assignments:
        graph.add_edge(Edge(src=principal, dst=template_index.get(role_ref, role_ref), kind="HasRole"))


# --- normalized ------------------------------------------------------------

def _load_normalized(doc: dict, graph: Graph) -> None:
    for user in doc.get("users", []):
        oid = user.get("id")
        if not oid:
            continue
        graph.add_node(Node(id=oid, kind="User", label=user.get("userPrincipalName", oid),
                            realm=CLOUD,
                            props={"onprem_sid": user.get("onPremisesSecurityIdentifier")}))
    for role in doc.get("roles", []):
        rid = role.get("id")
        if not rid:
            continue
        name = role.get("displayName", rid)
        graph.add_node(Node(id=rid, kind="Role", label=name, realm=CLOUD,
                            props={"privileged": name in PRIVILEGED_ROLES}))
        for member in role.get("members", []):
            graph.add_edge(Edge(src=member, dst=rid, kind="HasRole"))
