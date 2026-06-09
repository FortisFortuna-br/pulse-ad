"""Acceptance tests: the scary hybrid path must be discovered from real-format
SharpHound + AzureHound data.

Scenario encoded in samples/ (real BloodHound CE / AzureHound field shapes):
  - ALICE is local admin on AADCONNECT01 (an Entra Connect sync host, detected
    by name + a session of the MSOL_ sync account; no manual flag).
  - ALICE herself is only Global *Reader* in the cloud.
  - BOB is a synced user who holds Global *Administrator*.
  - MSOL_... holds DCSync rights on the domain.

So ALICE -> AADCONNECT01 -> (sync host) -> BOB(cloud) -> Global Administrator.
ALICE is nobody special; owning one box makes her tenant admin. That is the
entire product thesis.
"""
from __future__ import annotations

import os

from pulse.bridge import link
from pulse.ingest import azurehound, sharphound
from pulse.model import Graph
from pulse.pathfinder import find_paths, is_cloud_admin, onprem_user_ids

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")
ONPREM_DIR = os.path.join(SAMPLES, "onprem")
CLOUD_FILE = os.path.join(SAMPLES, "cloud_azurehound.json")


def build_graph() -> Graph:
    graph = Graph()
    sharphound.load(ONPREM_DIR, graph)      # directory of SharpHound JSON files
    azurehound.load(CLOUD_FILE, graph)
    link(graph)
    return graph


def test_ingest_reads_multi_file_onprem():
    graph = Graph()
    sharphound.load(ONPREM_DIR, graph)
    labels = {n.label for n in graph.nodes.values()}
    assert "ALICE@CORP.LOCAL" in labels        # users
    assert "AADCONNECT01.CORP.LOCAL" in labels  # computers
    assert "DOMAIN ADMINS@CORP.LOCAL" in labels  # groups
    assert "CORP.LOCAL" in labels               # domains


def test_dcsync_rights_become_acl_edges():
    graph = Graph()
    sharphound.load(ONPREM_DIR, graph)
    dcsync_edges = [e for e in graph.edges if e.kind in ("GetChanges", "GetChangesAll")]
    assert len(dcsync_edges) == 2  # MSOL_ account on the domain


def test_bridge_findings_flag_sync_host_and_principal():
    graph = build_graph()  # link() already ran
    # Re-run link on a fresh graph to inspect findings.
    g2 = Graph()
    sharphound.load(ONPREM_DIR, g2)
    azurehound.load(CLOUD_FILE, g2)
    findings = link(g2)
    kinds = {f.kind for f in findings}
    assert "entra_connect_host" in kinds      # AADCONNECT01 detected by name/session
    assert "dirsync_principal" in kinds       # MSOL_ detected by name + DCSync rights
    assert all(f.severity == "CRITICAL" for f in findings)


def test_alice_reaches_global_admin_via_bridge():
    graph = build_graph()
    alice = graph.find("ALICE")
    assert alice is not None

    paths = find_paths(graph, [alice.id])
    assert paths, "expected ALICE to reach a cloud admin"

    path = paths[0]
    assert path.goal.label == "Global Administrator"
    assert path.crosses_bridge, "the path must cross an on-prem -> cloud bridge"
    assert path.hops == 3  # ALICE -> AADCONNECT01 -> BOB(cloud) -> Global Administrator
    assert any(e.kind == "SyncServerCompromise" for e in path.edges)


def test_alice_is_not_directly_cloud_admin():
    graph = build_graph()
    alice_cloud = graph.find("alice@corp.com")
    assert alice_cloud is not None
    assert not is_cloud_admin(alice_cloud)  # she is only Global Reader


def test_helpdesk_has_no_path():
    graph = build_graph()
    helpdesk = graph.find("HELPDESK01")
    assert helpdesk is not None
    assert not find_paths(graph, [helpdesk.id])  # admin only on a normal workstation


def test_default_footholds_are_onprem_users():
    graph = build_graph()
    labels = {graph.nodes[i].label for i in onprem_user_ids(graph)}
    assert "ALICE@CORP.LOCAL" in labels
    assert "BOB@CORP.LOCAL" in labels
    assert "alice@corp.com" not in labels  # cloud users are not on-prem footholds


# --- Step 1: real AzureHound ingest ---------------------------------------

def test_azurehound_raw_format_equivalent():
    """The real AzureHound shape must yield the same hybrid path as normalized."""
    graph = Graph()
    sharphound.load(ONPREM_DIR, graph)
    azurehound.load(os.path.join(SAMPLES, "cloud_azurehound_raw.json"), graph)
    link(graph)

    bob_cloud = graph.find("bob@corp.com")
    assert bob_cloud is not None and bob_cloud.realm == "cloud"

    alice = graph.find("ALICE")
    paths = find_paths(graph, [alice.id])
    assert paths and paths[0].goal.label == "Global Administrator"
    assert paths[0].crosses_bridge


# --- Step 2: JSON output + stats ------------------------------------------

def test_json_analysis_is_serializable_and_complete():
    import json
    from pulse.result import analysis_to_dict

    graph = Graph()
    sharphound.load(ONPREM_DIR, graph)
    azurehound.load(CLOUD_FILE, graph)
    findings = link(graph)
    paths = find_paths(graph, onprem_user_ids(graph))

    blob = analysis_to_dict(graph, findings, paths)
    json.dumps(blob)  # must not raise
    assert blob["summary"]["nodes"] > 0
    assert blob["bridges"], "expected bridge findings in the json blob"
    assert any(p["goal"] == "Global Administrator" for p in blob["paths"])


def test_exposure_counts_only_reachable_footholds():
    from pulse.result import exposure
    exp = exposure(build_graph())
    assert exp["onprem_users"] == 4               # ALICE, BOB, HELPDESK, MSOL_
    assert exp["can_reach_cloud_admin"] == 3       # all but HELPDESK
    assert exp["admin_roles_reachable"] == ["Global Administrator"]


# --- Step 3: visualization export -----------------------------------------

def test_export_dot_marks_bridges_red():
    from pulse import export
    dot = export.to_dot(build_graph())
    assert dot.startswith("digraph pulse")
    assert "color=red" in dot                      # bridge edges highlighted
    assert "AADCONNECT01.CORP.LOCAL" in dot


def test_export_graphml_is_well_formed_xml():
    import xml.etree.ElementTree as ET
    from pulse import export
    graphml = export.to_graphml(build_graph())
    root = ET.fromstring(graphml)                  # raises if malformed
    assert root.tag.endswith("graphml")
