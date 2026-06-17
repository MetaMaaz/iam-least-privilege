"""Reporting — Markdown report, Mermaid escalation diagram, policy export.

Pure presentation: takes the structures the reasoning modules produced and
writes a self-contained, recruiter-readable Markdown report plus the tightened
policy JSON files. No analysis happens here.
"""

from __future__ import annotations

import json
import os
from datetime import date

from analyzer.analyzer import analyze, score_risk
from analyzer.classifier import classify_inventory
from analyzer.escalation import (
    diff_paths,
    escalation_path_edges,
    escalation_reach_counts,
    find_escalation_paths,
)
from analyzer.models import EscalationPath, Inventory
from analyzer.recommender import build_remediated_inventory, recommend

_SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        out.append("| " + " | ".join(row) + " |")
    return "\n".join(out)


def _mermaid_escalation(inventory: Inventory, paths: list[EscalationPath]) -> str:
    """Render the before-remediation escalation graph as Mermaid.

    Nodes are declared once (with labels), then referenced by id in the edges,
    so the diagram stays readable.
    """
    edges = escalation_path_edges(inventory)
    on_path_nodes: set[str] = {p.start_identity for p in paths}

    lines = ["```mermaid", "graph LR"]
    lines.append('    ADMIN(["ADMIN — full account control"]):::admin')

    # declare every identity node once
    nodes = {e.src for e in edges} | {e.dst for e in edges}
    nodes.discard("ADMIN")
    for n in sorted(nodes):
        lines.append(f'    {_safe(n)}["{n}"]')

    drawn: set[tuple[str, str, str]] = set()
    for e in edges:
        key = (e.src, e.dst, e.technique)
        if key in drawn:
            continue
        drawn.add(key)
        label = e.technique.replace('"', "'")
        lines.append(f'    {_safe(e.src)} -->|"{label}"| {_safe(e.dst)}')

    lines.append("    classDef admin fill:#b00020,stroke:#600,color:#fff;")
    lines.append("    classDef start fill:#ffd54f,stroke:#c79100,color:#000;")
    for n in sorted(on_path_nodes):
        lines.append(f"    class {_safe(n)} start;")
    lines.append("```")
    return "\n".join(lines)


def _safe(name: str) -> str:
    if name == "ADMIN":
        return "ADMIN"
    return name.replace("-", "_")


def build_report(inventory: Inventory) -> tuple[str, dict[str, dict]]:
    """Run the full analysis and return (markdown_report, {identity: policy_json})."""
    classified = classify_inventory(inventory)
    findings = analyze(inventory)
    reach = escalation_reach_counts(inventory)
    risks = score_risk(inventory, findings, reach)

    before_paths = find_escalation_paths(inventory)
    remediated = build_remediated_inventory(inventory)
    after_paths = find_escalation_paths(remediated)
    annotated_paths = diff_paths(before_paths, after_paths)

    recs = recommend(inventory)
    policy_files = {r.identity: r.policy_document for r in recs}

    md = _render_markdown(
        inventory, classified, findings, risks, annotated_paths, after_paths, recs
    )
    return md, policy_files


def _render_markdown(inventory, classified, findings, risks, before_paths, after_paths, recs) -> str:
    p: list[str] = []
    crit = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    cut = sum(1 for path in before_paths if path.cut_by)

    p.append("# IAM Least-Privilege Analysis Report")
    p.append("")
    p.append(f"*Generated {date.today().isoformat()} · account `{inventory.account_id}`*")
    p.append("")
    p.append(
        "Findings map to **NIST SP 800-207** (Zero Trust Architecture — identity "
        "pillar: least privilege, per-request access) and **AWS IAM best "
        "practices**. Every finding cites the principle it violates. The tool is "
        "**read-only**; it recommends, a human applies."
    )
    p.append("")

    # -- executive summary --
    p.append("## Executive summary")
    p.append("")
    p.append(
        f"- **{len(inventory.identities)}** identities analysed "
        f"({len(inventory.of_kind('user'))} users, {len(inventory.of_kind('role'))} roles, "
        f"{len(inventory.of_kind('group'))} groups)."
    )
    p.append(f"- **{len(findings)}** findings — {crit} critical, {high} high.")
    p.append(
        f"- **{len(before_paths)}** privilege-escalation path(s) to admin found; "
        f"**{cut}** cut by the recommended remediation."
    )
    p.append("")

    # -- risk scoreboard --
    p.append("## Risk scoreboard")
    p.append("")
    p.append("Per-identity risk = Σ finding severity weights + escalation blast-radius bonus (capped 100).")
    p.append("")
    rows = [
        [r.identity, str(r.score), f"{_SEV_EMOJI.get(r.band, '')} {r.band}",
         classified[r.identity].privilege_tier, ", ".join(r.contributing) or "—"]
        for r in risks
    ]
    p.append(_md_table(["Identity", "Risk", "Band", "Tier", "Drivers"], rows))
    p.append("")

    # -- escalation paths (the centrepiece) --
    p.append("## Privilege-escalation paths (before → after)")
    p.append("")
    p.append(
        "Identities, assumable roles and escalation grants modelled as a graph "
        "(the IAM analogue of a network attack-path; conceptually in "
        "[BloodHound](https://github.com/BloodHoundAD/BloodHound) territory, cited "
        "as prior art). A path to **ADMIN** is a concrete escalation chain.")
    p.append("")
    p.append(_mermaid_escalation(inventory, before_paths))
    p.append("")
    if before_paths:
        for path in before_paths:
            status = "✅ **CUT** by remediation" if path.cut_by else "❌ still open"
            p.append(f"### `{path.start_identity}` → admin — {status}")
            p.append("")
            p.append(f"*Technique:* {path.technique}")
            p.append("")
            for step in path.steps:
                p.append(f"- `{step}`")
            p.append("")
    else:
        p.append("_No escalation paths to admin were found._")
        p.append("")
    p.append(
        f"After applying the recommended policies, **{len(after_paths)}** "
        f"escalation path(s) remain — the low-privilege entry points above can no "
        f"longer reach admin.")
    p.append("")

    # -- findings by severity --
    p.append("## Findings")
    p.append("")
    for sev in ("critical", "high", "medium", "low"):
        sev_findings = [f for f in findings if f.severity == sev]
        if not sev_findings:
            continue
        p.append(f"### {_SEV_EMOJI[sev]} {sev.title()} ({len(sev_findings)})")
        p.append("")
        for f in sev_findings:
            p.append(f"**`{f.identity}` — {f.category}**")
            p.append("")
            p.append(f"- {f.detail}")
            p.append(f"- *Principle:* {f.principle}")
            p.append(f"- *Fix:* {f.recommendation}")
            p.append("")

    # -- remediation policies --
    p.append("## Recommended least-privilege policies")
    p.append("")
    p.append("Valid AWS policy documents written to `output/policies/`. Each is the tightened replacement for the identity's current grants.")
    p.append("")
    for r in recs:
        p.append(f"### `{r.identity}`")
        p.append("")
        for note in r.justifications:
            p.append(f"- {note}")
        p.append("")
        p.append("```json")
        p.append(json.dumps(r.policy_document, indent=2))
        p.append("```")
        p.append("")

    p.append("---")
    p.append("")
    p.append(
        "*Generated by the IAM Least-Privilege Analyzer. Rules-based and "
        "explainable — no ML. Heuristics live in `data/*.yaml`.*")
    return "\n".join(p)


def write_report(inventory: Inventory, out_dir: str) -> str:
    """Generate everything and write to ``out_dir``. Returns the report path."""
    os.makedirs(out_dir, exist_ok=True)
    policies_dir = os.path.join(out_dir, "policies")
    os.makedirs(policies_dir, exist_ok=True)

    md, policy_files = build_report(inventory)

    report_path = os.path.join(out_dir, "report.md")
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(md)

    for identity, doc in policy_files.items():
        with open(os.path.join(policies_dir, f"{identity}.json"), "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)

    return report_path
