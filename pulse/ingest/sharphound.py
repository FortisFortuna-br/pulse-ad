"""Ingest on-prem Active Directory from real SharpHound (BloodHound CE) output.

Accepts any of:
  * a ``.zip`` produced by SharpHound,
  * a directory of ``*.json`` collection files, or
  * a single ``*.json`` collection file.

Each collection file uses the BloodHound CE envelope::

    {"data": [ <objects> ], "meta": {"type": "users"|"computers"|..., ...}}

Objects carry a top-level ``ObjectIdentifier`` (SID) plus a ``Properties`` map.
From them we build:

  * nodes for users / computers / groups / domains
  * ``MemberOf``    from a group's ``Members``
  * ``AdminTo``     from a computer's ``LocalAdmins``
  * ``HasSession``  from a computer's ``Sessions`` (own the box, recover the creds)
  * ``<AclRight>``  from every object's ``Aces`` (principal -> object)
"""
from __future__ import annotations

import glob
import json
import os
import zipfile
from typing import Iterable

from ..model import ONPREM, Edge, Graph, Node

# ACL rights that amount to full control of the target object.
CONTROL_RIGHTS = {
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
    "AllExtendedRights", "ForceChangePassword", "AddMember", "AddSelf",
    "AddKeyCredentialLink", "ReadLAPSPassword", "ReadGMSAPassword",
}
# Replication rights that grant DCSync (dump any credential in the directory).
DCSYNC_RIGHTS = {"GetChanges", "GetChangesAll", "GetChangesInFilteredSet", "DCSync"}

_KIND_BY_TYPE = {
    "users": "User", "computers": "Computer", "groups": "Group",
    "domains": "Domain", "ous": "OU", "gpos": "GPO", "containers": "Container",
}


def _iter_collections(path: str) -> Iterable[dict]:
    """Yield parsed JSON documents from a zip, a directory, or a single file."""
    if path.lower().endswith(".zip"):
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if name.lower().endswith(".json"):
                    with zf.open(name) as fh:
                        yield json.loads(fh.read().decode("utf-8"))
        return
    if os.path.isdir(path):
        for name in sorted(glob.glob(os.path.join(path, "*.json"))):
            with open(name, encoding="utf-8") as fh:
                yield json.load(fh)
        return
    with open(path, encoding="utf-8") as fh:
        yield json.load(fh)


def _object_id(obj: dict) -> str | None:
    return obj.get("ObjectIdentifier") or obj.get("Properties", {}).get("objectid")


def _results(value) -> list:
    """SharpHound nests collected lists as ``{"Collected":.., "Results":[..]}``;
    group ``Members`` is a plain list. Accept both shapes."""
    if isinstance(value, dict):
        return value.get("Results") or []
    if isinstance(value, list):
        return value
    return []


def _add_aces(graph: Graph, obj_id: str, aces) -> None:
    for ace in aces or []:
        principal = ace.get("PrincipalSID")
        right = ace.get("RightName")
        if not principal or not right:
            continue
        if right in CONTROL_RIGHTS or right in DCSYNC_RIGHTS:
            graph.add_edge(Edge(src=principal, dst=obj_id, kind=right,
                                note=f"ACL: {right} over target"))


def load(path: str, graph: Graph | None = None) -> Graph:
    graph = graph or Graph()
    for doc in _iter_collections(path):
        col_type = doc.get("meta", {}).get("type", "")
        kind = _KIND_BY_TYPE.get(col_type, "Unknown")
        for obj in doc.get("data", []):
            oid = _object_id(obj)
            if not oid:
                continue
            props = obj.get("Properties", {})
            graph.add_node(Node(id=oid, kind=kind, label=props.get("name", oid),
                                realm=ONPREM, props={"enabled": props.get("enabled", True)}))

            if kind == "Group":
                for member in _results(obj.get("Members")):
                    mid = member.get("ObjectIdentifier")
                    if mid:
                        graph.add_edge(Edge(src=mid, dst=oid, kind="MemberOf"))
            elif kind == "Computer":
                for admin in _results(obj.get("LocalAdmins")):
                    aid = admin.get("ObjectIdentifier")
                    if aid:
                        graph.add_edge(Edge(src=aid, dst=oid, kind="AdminTo",
                                            note="local admin => full control of host"))
                for sess in _results(obj.get("Sessions")):
                    uid = sess.get("UserSID") or sess.get("UserId")
                    if uid:
                        graph.add_edge(Edge(src=oid, dst=uid, kind="HasSession",
                                            note="own the host => recover this user's creds"))

            _add_aces(graph, oid, obj.get("Aces"))
    return graph
