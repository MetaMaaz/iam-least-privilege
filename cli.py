#!/usr/bin/env python3
"""IAM Least-Privilege Analyzer — command-line entry point.

Three subcommands mirror the data flow and keep ingestion separate from
reasoning, so the whole analysis runs offline on the mock account:

    ingest   AWS export (or live read-only boto3) -> normalised inventory.json
    analyze  inventory.json -> findings + escalation summary (stdout)
    report   inventory.json -> full Markdown report + remediation policies

Examples
--------
    python cli.py report  --in data/mock_account.json --out output/
    python cli.py analyze --in data/mock_account.json
    python cli.py ingest  --export export.json --out inventory.json
    python cli.py ingest  --live --profile readonly --out inventory.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# Ensure the package is importable when run from anywhere.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzer.analyzer import analyze, score_risk  # noqa: E402
from analyzer.escalation import escalation_reach_counts, find_escalation_paths  # noqa: E402
from analyzer.ingestion import inventory_from_live, load_inventory  # noqa: E402
from analyzer.models import Inventory  # noqa: E402
from analyzer.reporter import write_report  # noqa: E402


def _dump_inventory(inv: Inventory, path: str) -> None:
    payload = {
        "account_id": inv.account_id,
        "identities": [
            {
                "name": i.name,
                "kind": i.kind,
                "attached_groups": i.attached_groups,
                "last_used": i.last_used,
                "trusted_principals": i.trusted_principals,
                "access_key_ages": i.access_key_ages,
                "policies": [
                    {
                        "name": p.name,
                        "type": p.type,
                        "permissions": [
                            {"action": perm.action, "resource": perm.resource,
                             "effect": perm.effect, "conditions": perm.conditions}
                            for perm in p.permissions
                        ],
                    }
                    for p in i.policies
                ],
            }
            for i in inv.identities
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def cmd_ingest(args: argparse.Namespace) -> int:
    if args.live:
        inv = inventory_from_live(profile=args.profile, region=args.region)
    elif args.export:
        inv = load_inventory(args.export)
    else:
        print("error: provide --export <file> or --live", file=sys.stderr)
        return 2
    _dump_inventory(inv, args.out)
    print(f"Wrote normalised inventory ({len(inv.identities)} identities) -> {args.out}")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    inv = load_inventory(getattr(args, "in"))
    findings = analyze(inv)
    reach = escalation_reach_counts(inv)
    risks = score_risk(inv, findings, reach)
    paths = find_escalation_paths(inv)

    print(f"\n=== {len(findings)} findings ===")
    for f in findings:
        print(f"  [{f.severity.upper():8}] {f.identity:18} {f.category:16} {f.detail}")

    print("\n=== Risk scoreboard ===")
    for r in risks:
        print(f"  {r.score:3}  {r.band:8} {r.identity:18} ({', '.join(r.contributing) or '—'})")

    print(f"\n=== {len(paths)} escalation path(s) to admin ===")
    for path in paths:
        print(f"  {path.start_identity} via {path.technique}")
        for step in path.steps:
            print(f"      {step}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    inv = load_inventory(getattr(args, "in"))
    report_path = write_report(inv, args.out)
    print(f"Report written -> {report_path}")
    print(f"Remediation policies -> {os.path.join(args.out, 'policies/')}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="iam-analyzer", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    pi = sub.add_parser("ingest", help="AWS export / live -> normalised inventory.json")
    pi.add_argument("--export", help="path to get-account-authorization-details JSON")
    pi.add_argument("--live", action="store_true", help="pull live via boto3 (read-only)")
    pi.add_argument("--profile", help="AWS profile (read-only) for --live")
    pi.add_argument("--region", default="us-east-1")
    pi.add_argument("--out", default="inventory.json")
    pi.set_defaults(func=cmd_ingest)

    pa = sub.add_parser("analyze", help="print findings + escalation summary")
    pa.add_argument("--in", required=True, help="inventory or mock JSON")
    pa.set_defaults(func=cmd_analyze)

    pr = sub.add_parser("report", help="write full Markdown report + policies")
    pr.add_argument("--in", required=True, help="inventory or mock JSON")
    pr.add_argument("--out", default="output", help="output directory")
    pr.set_defaults(func=cmd_report)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
