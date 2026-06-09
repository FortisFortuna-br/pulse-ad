"""Export the identity graph for visualization.

  * DOT     -> render with Graphviz  (`dot -Tpng graph.dot -o graph.png`)
  * GraphML -> open in Gephi / yEd / Cytoscape

Bridge edges (on-prem -> cloud) are drawn bold red so the dangerous hop pops.
"""
from __future__ import annotations

import xml.sax.saxutils as su

from .model import CLOUD, Graph

_REALM_COLOR = {CLOUD: "lightskyblue", "onprem": "lightgray"}


def _dot_esc(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def to_dot(graph: Graph) -> str:
    lines = [
        "digraph pulse {",
        "  rankdir=LR;",
        '  node [shape=box, style="rounded,filled", fontname="Helvetica"];',
        '  edge [fontname="Helvetica", fontsize=10];',
    ]
    for node in graph.nodes.values():
        color = _REALM_COLOR.get(node.realm, "white")
        label = _dot_esc(f"{node.label}\\n({node.kind})")
        lines.append(f'  "{_dot_esc(node.id)}" [label="{label}", fillcolor={color}];')
    for edge in graph.edges:
        if edge.bridge:
            style = '[label="%s", color=red, penwidth=2.2, fontcolor=red]' % _dot_esc(edge.kind)
        else:
            style = '[label="%s", color=gray40]' % _dot_esc(edge.kind)
        lines.append(f'  "{_dot_esc(edge.src)}" -> "{_dot_esc(edge.dst)}" {style};')
    lines.append("}")
    return "\n".join(lines)


def to_graphml(graph: Graph) -> str:
    out = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
        '  <key id="label" for="node" attr.name="label" attr.type="string"/>',
        '  <key id="realm" for="node" attr.name="realm" attr.type="string"/>',
        '  <key id="kind" for="node" attr.name="kind" attr.type="string"/>',
        '  <key id="ekind" for="edge" attr.name="kind" attr.type="string"/>',
        '  <key id="bridge" for="edge" attr.name="bridge" attr.type="boolean"/>',
        '  <graph edgedefault="directed">',
    ]
    for node in graph.nodes.values():
        out.append(f"    <node id={su.quoteattr(node.id)}>")
        out.append(f'      <data key="label">{su.escape(node.label)}</data>')
        out.append(f'      <data key="realm">{su.escape(node.realm)}</data>')
        out.append(f'      <data key="kind">{su.escape(node.kind)}</data>')
        out.append("    </node>")
    for i, edge in enumerate(graph.edges):
        out.append(
            f'    <edge id="e{i}" source={su.quoteattr(edge.src)} target={su.quoteattr(edge.dst)}>'
        )
        out.append(f'      <data key="ekind">{su.escape(edge.kind)}</data>')
        out.append(f'      <data key="bridge">{"true" if edge.bridge else "false"}</data>')
        out.append("    </edge>")
    out.append("  </graph>")
    out.append("</graphml>")
    return "\n".join(out)
