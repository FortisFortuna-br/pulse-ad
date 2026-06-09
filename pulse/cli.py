"""Pulse command line.

    pulse analyze --onprem <sharphound> --cloud <azurehound> [--foothold ALICE] [--format json]
    pulse stats   --onprem <sharphound> --cloud <azurehound> [--format json]
    pulse export  --onprem <sharphound> --cloud <azurehound> --format dot|graphml [-o out]

`--onprem` accepts a SharpHound .zip, a directory of collection .json files, or
a single file. `--cloud` accepts AzureHound output or a normalized export.
Text output is ASCII so it renders cleanly in any terminal.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__, export
from .bridge import link
from .ingest import azurehound, sharphound
from .model import Graph
from .pathfinder import TakeoverPath, find_paths, onprem_user_ids
from .result import analysis_to_dict, exposure, graph_stats

BANNER = r"""
  ____        _
 |  _ \ _   _| |___  ___    Hybrid Identity Attack Path Engine
 | |_) | | | | / __|/ _ \   on-prem AD  -->  Entra ID
 |  __/| |_| | \__ \  __/   v{version}
 |_|    \__,_|_|___/\___|
"""

AUTHORIZATION_NOTICE = (
    "Pulse analyzes already-collected data only. Use it solely against "
    "tenants/domains you own or are explicitly authorized to assess."
)


def _load(onprem: str, cloud: str):
    graph = Graph()
    sharphound.load(onprem, graph)
    azurehound.load(cloud, graph)
    findings = link(graph)
    return graph, findings


def _format_path(path: TakeoverPath, graph: Graph) -> str:
    lines = [f"  [{path.hops} hops] foothold: {path.start.label}"]
    cursor = path.start.label
    for edge in path.edges:
        dst = graph.nodes[edge.dst].label
        marker = "  ==[BRIDGE]==> " if edge.bridge else "  --" + edge.kind + "--> "
        lines.append(f"      {cursor}{marker}{dst}")
        if edge.note:
            lines.append(f"          ^ {edge.note}")
        cursor = dst
    lines.append(f"      RESULT: {path.goal.label} (cloud admin)  *** TENANT COMPROMISE ***")
    return "\n".join(lines)


def cmd_analyze(args: argparse.Namespace) -> int:
    graph, findings = _load(args.onprem, args.cloud)

    if args.foothold:
        node = graph.find(args.foothold)
        if node is None:
            print(f"error: foothold '{args.foothold}' not found in on-prem data", file=sys.stderr)
            return 2
        footholds = [node.id]
    else:
        footholds = onprem_user_ids(graph)

    paths = find_paths(graph, footholds)

    if args.format == "json":
        print(json.dumps(analysis_to_dict(graph, findings, paths), indent=2))
        return 0

    print(BANNER.format(version=__version__))
    print(AUTHORIZATION_NOTICE)
    print()
    print(f"Loaded {len(graph.nodes)} nodes, {len(graph.edges)} edges.")
    if findings:
        print(f"\nHybrid bridges found ({len(findings)}):")
        for finding in findings:
            print(f"  [{finding.severity}] {finding.title}")
            print(f"      {finding.detail}")
    if not paths:
        print("\nNo on-prem -> cloud-admin path found. (Good news for the defender.)")
        return 0
    print(f"\nAttack paths to cloud admin ({len(paths)}):\n")
    for path in paths:
        tag = " via hybrid bridge" if path.crosses_bridge else ""
        print(_format_path(path, graph) + tag + "\n")
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    graph, findings = _load(args.onprem, args.cloud)
    stats = graph_stats(graph)
    exp = exposure(graph)

    if args.format == "json":
        print(json.dumps({
            "summary": stats,
            "exposure": exp,
            "bridges": [{"kind": f.kind, "title": f.title, "severity": f.severity} for f in findings],
        }, indent=2))
        return 0

    print("Pulse summary")
    print(f"  nodes: {stats['nodes']}   edges: {stats['edges']}   bridge edges: {stats['bridge_edges']}")
    print("  nodes by kind:")
    for key, count in stats["nodes_by_kind"].items():
        print(f"    {key}: {count}")
    print("  exposure:")
    print(f"    on-prem users: {exp['onprem_users']}")
    print(f"    can reach cloud admin: {exp['can_reach_cloud_admin']}")
    if exp["admin_roles_reachable"]:
        print(f"    admin roles reachable: {', '.join(exp['admin_roles_reachable'])}")
    if findings:
        print(f"  hybrid bridges ({len(findings)}):")
        for finding in findings:
            print(f"    [{finding.severity}] {finding.title}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    graph, _ = _load(args.onprem, args.cloud)
    text = export.to_dot(graph) if args.format == "dot" else export.to_graphml(graph)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {args.format} graph ({len(graph.nodes)} nodes) to {args.output}")
    else:
        print(text)
    return 0


def _add_io(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--onprem", required=True, help="SharpHound .zip / dir / .json")
    parser.add_argument("--cloud", required=True, help="AzureHound or normalized Entra JSON")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pulse", description="Hybrid Identity Attack Path Engine")
    parser.add_argument("--version", action="version", version=f"pulse {__version__}")
    sub = parser.add_subparsers(dest="command")

    analyze = sub.add_parser("analyze", help="find on-prem -> cloud takeover paths")
    _add_io(analyze)
    analyze.add_argument("--foothold", help="start node (name or SID); default: all on-prem users")
    analyze.add_argument("--format", choices=["text", "json"], default="text")
    analyze.set_defaults(func=cmd_analyze)

    stats = sub.add_parser("stats", help="summarize the graph and tenant exposure")
    _add_io(stats)
    stats.add_argument("--format", choices=["text", "json"], default="text")
    stats.set_defaults(func=cmd_stats)

    exp = sub.add_parser("export", help="export the graph for visualization")
    _add_io(exp)
    exp.add_argument("--format", choices=["dot", "graphml"], default="dot")
    exp.add_argument("-o", "--output", help="output file (default: stdout)")
    exp.set_defaults(func=cmd_export)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
