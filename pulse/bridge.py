"""The bridge: where on-prem compromise becomes cloud compromise.

This module is what makes Pulse *Pulse*. BloodHound models on-prem; AzureHound
models the cloud. Neither welds them together. Here we add the cross-realm
edges that real attackers walk, detected from real collected data (no manual
flags required):

  1. SyncedTo             - an on-prem identity and its cloud twin share a
                            credential (Password Hash Sync). Own one, own both.
  2. DirSyncReplication   - a principal that can replicate directory secrets
                            (the MSOL_/AAD_ sync account, or anyone with DCSync
                            rights) can dump any hash and impersonate any synced
                            identity - up to Global Administrator.
  3. SyncServerCompromise - whoever is local admin on the Entra Connect (AAD
                            Connect) host owns the sync account, and therefore
                            the cloud.

Everything here is pure analysis over already-collected data. No packets are
sent to any target.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .model import CLOUD, ONPREM, Edge, Graph

# On-prem account names that ARE the hybrid sync machinery.
SYNC_ACCOUNT_RE = re.compile(r"^(MSOL_|AAD_|Sync_|AZUREADSSOACC)", re.IGNORECASE)
# Host names that betray an Entra Connect / AAD Connect sync server.
SYNC_HOST_RE = re.compile(r"(AADCONNECT|AZUREADCONNECT|AADSYNC|ENTRACONNECT)", re.IGNORECASE)


@dataclass
class BridgeFinding:
    kind: str
    title: str
    detail: str
    severity: str  # CRITICAL / HIGH / MEDIUM


def _short(label: str) -> str:
    return label.split("@", 1)[0]


def _replication_principals(graph: Graph) -> set[str]:
    """Principals that can replicate directory secrets: either named like a
    sync account, or holding DCSync rights (GetChanges + GetChangesAll, or an
    equivalent) over a Domain object."""
    found: set[str] = set()

    for node in graph.nodes.values():
        if node.realm == ONPREM and node.kind == "User" and SYNC_ACCOUNT_RE.match(_short(node.label)):
            found.add(node.id)

    domain_ids = {n.id for n in graph.nodes.values() if n.kind == "Domain"}
    rights: dict[str, set[str]] = {}
    for edge in graph.edges:
        if edge.dst in domain_ids and edge.kind in ("GetChanges", "GetChangesAll", "DCSync", "GenericAll"):
            rights.setdefault(edge.src, set()).add(edge.kind)
    for sid, got in rights.items():
        if "DCSync" in got or "GenericAll" in got or {"GetChanges", "GetChangesAll"}.issubset(got):
            found.add(sid)

    return found


def _sync_hosts(graph: Graph, sync_account_ids: set[str]) -> list[str]:
    """Computers that run directory sync: explicitly flagged, name-matched, or
    holding a session of a sync account."""
    hosts: list[str] = []
    for node in graph.nodes.values():
        if not (node.realm == ONPREM and node.kind == "Computer"):
            continue
        is_host = bool(node.props.get("is_sync_server")) or bool(SYNC_HOST_RE.search(node.label))
        if not is_host:
            for edge in graph.out_edges(node.id):
                if edge.kind == "HasSession" and edge.dst in sync_account_ids:
                    is_host = True
                    break
        if is_host:
            hosts.append(node.id)
    return hosts


def link(graph: Graph) -> list[BridgeFinding]:
    """Add bridge edges to ``graph`` in place; return what was discovered."""
    findings: list[BridgeFinding] = []

    # Cloud identities keyed by the on-prem SID they claim as their origin.
    sid_to_cloud: dict[str, str] = {}
    for node in graph.nodes.values():
        if node.realm == CLOUD and node.kind == "User":
            sid = node.props.get("onprem_sid")
            if sid:
                sid_to_cloud[sid] = node.id
    synced_cloud_ids = sorted(set(sid_to_cloud.values()))

    # (1) PHS: control of the on-prem account == control of its cloud twin.
    for sid, cloud_id in sid_to_cloud.items():
        if sid in graph.nodes:
            graph.add_edge(Edge(src=sid, dst=cloud_id, kind="SyncedTo", bridge=True,
                                note="on-prem identity synced to cloud (same credential via PHS)"))

    if not synced_cloud_ids:
        return findings  # nothing hybrid to bridge to

    sync_account_ids = {
        n.id for n in graph.nodes.values()
        if n.realm == ONPREM and n.kind == "User" and SYNC_ACCOUNT_RE.match(_short(n.label))
    }

    # (2) Replication principals can impersonate ANY synced identity.
    for pid in _replication_principals(graph):
        node = graph.nodes.get(pid)
        if node is None:
            continue
        for cloud_id in synced_cloud_ids:
            graph.add_edge(Edge(src=pid, dst=cloud_id, kind="DirSyncReplication", bridge=True,
                                note="directory replication (DCSync/PHS) => impersonate any synced cloud user"))
        findings.append(BridgeFinding(
            kind="dirsync_principal",
            title=f"Directory-sync principal: {node.label}",
            detail=(f"{node.label} can replicate directory secrets and impersonate "
                    f"all {len(synced_cloud_ids)} synced cloud identities."),
            severity="CRITICAL",
        ))

    # (3) The Entra Connect host: own the box, own the sync account, own the cloud.
    for host_id in _sync_hosts(graph, sync_account_ids):
        node = graph.nodes[host_id]
        for cloud_id in synced_cloud_ids:
            graph.add_edge(Edge(src=host_id, dst=cloud_id, kind="SyncServerCompromise", bridge=True,
                                note="Entra Connect host => sync account => impersonate any synced cloud user"))
        findings.append(BridgeFinding(
            kind="entra_connect_host",
            title=f"Entra Connect sync host: {node.label}",
            detail=(f"{node.label} runs directory synchronization. Local admin here "
                    f"yields the sync account and, via DCSync/PHS, all "
                    f"{len(synced_cloud_ids)} synced identities."),
            severity="CRITICAL",
        ))

    return findings
