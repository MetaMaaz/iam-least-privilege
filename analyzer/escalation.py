"""Privilege-escalation path graph — pure logic, the interview centrepiece.

We model identities (and a virtual ``ADMIN`` sink) as nodes, and turn the
escalation techniques in ``data/escalation_rules.yaml`` into directed edges:
"holding grant X, identity A can act as identity B". A path from a low-privilege
identity to ``ADMIN`` is a concrete privilege-escalation chain.

This is the IAM analogue of a network attack-path, and conceptually in the same
territory as BloodHound's Active Directory graphs (cited as prior art). Running
the same computation on the *remediated* inventory shows the path is **cut** —
the single most interview-valuable artifact in the project.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Optional

from analyzer.analyzer import load_escalation_rules
from analyzer.classifier import _action_matches, classify_inventory, effective_permissions
from analyzer.models import EscalationPath, Identity, Inventory

ADMIN = "ADMIN"  # virtual sink: "can obtain arbitrary privilege"


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    technique: str
    rule_id: str


def _held_actions(ident: Identity, inventory: Inventory) -> set[str]:
    return {p.action for p in effective_permissions(ident, inventory) if p.effect == "Allow"}


def _can_pass_role(ident: Identity, inventory: Inventory, role: Identity) -> bool:
    """True if the identity holds iam:PassRole with a resource covering *role*.

    Resource-aware so that *scoping* PassRole (not only deleting it) visibly
    removes the edge in the after-remediation graph.
    """
    for perm in effective_permissions(ident, inventory):
        if perm.effect != "Allow" or not _action_matches(perm.action, "iam:PassRole"):
            continue
        if perm.is_resource_wildcard() or role.name in perm.resource:
            return True
    return False


def _assume_targets(ident: Identity, inventory: Inventory) -> list[str]:
    """Roles this identity may sts:AssumeRole, honouring resource scoping."""
    targets: list[str] = []
    roles = inventory.of_kind("role")
    for perm in effective_permissions(ident, inventory):
        if perm.effect != "Allow" or not _action_matches(perm.action, "sts:AssumeRole"):
            continue
        if perm.is_resource_wildcard():
            targets.extend(r.name for r in roles)
        else:
            # match role whose name appears in the resource ARN
            targets.extend(r.name for r in roles if r.name in perm.resource)
    return list(dict.fromkeys(targets))  # dedupe, keep order


def build_edges(inventory: Inventory) -> list[Edge]:
    """Derive all escalation edges from the rule catalogue."""
    rules = load_escalation_rules()["rules"]
    classified = classify_inventory(inventory)
    users = inventory.of_kind("user")
    roles = inventory.of_kind("role")
    edges: list[Edge] = []

    # 1) Any identity that is already admin-tier connects to the ADMIN sink.
    for name, ci in classified.items():
        if ci.privilege_tier == "admin":
            edges.append(
                Edge(name, ADMIN, "holds admin-equivalent permissions", "admin_tier")
            )

    # 2) Rule-derived edges. Groups are not actors (their grants already flow
    #    to member users via effective_permissions), so skip them as sources.
    for ident in inventory.identities:
        if ident.kind == "group":
            continue
        held = _held_actions(ident, inventory)

        for rule in rules:
            if not all(any(_action_matches(h, req) for h in held) for req in rule["requires_all"]):
                continue
            etype = rule["edge_type"]
            tech = rule["technique"]
            rid = rule["id"]

            if etype == "self_escalation":
                edges.append(Edge(ident.name, ADMIN, tech, rid))

            elif etype == "passrole_service":
                service = rule["service"]
                for r in roles:
                    if service in r.trusted_principals and _can_pass_role(ident, inventory, r):
                        edges.append(Edge(ident.name, r.name, tech, rid))

            elif etype == "assume_role":
                for target in _assume_targets(ident, inventory):
                    if target != ident.name:
                        edges.append(Edge(ident.name, target, tech, rid))

            elif etype in ("access_key", "login_profile"):
                for u in users:
                    if u.name != ident.name:
                        edges.append(Edge(ident.name, u.name, tech, rid))

    return edges


def _adjacency(edges: list[Edge]) -> dict[str, list[Edge]]:
    adj: dict[str, list[Edge]] = {}
    for e in edges:
        adj.setdefault(e.src, []).append(e)
    return adj


def _shortest_path(start: str, adj: dict[str, list[Edge]]) -> Optional[list[Edge]]:
    """BFS from start to the ADMIN sink; returns the edge list or None."""
    queue: deque[tuple[str, list[Edge]]] = deque([(start, [])])
    seen = {start}
    while queue:
        node, path = queue.popleft()
        for edge in adj.get(node, []):
            if edge.dst == ADMIN:
                return path + [edge]
            if edge.dst not in seen:
                seen.add(edge.dst)
                queue.append((edge.dst, path + [edge]))
    return None


def _reachable_count(start: str, adj: dict[str, list[Edge]]) -> int:
    """Number of distinct identity nodes reachable from start (blast radius)."""
    seen: set[str] = set()
    queue: deque[str] = deque([start])
    while queue:
        node = queue.popleft()
        for edge in adj.get(node, []):
            if edge.dst != ADMIN and edge.dst not in seen and edge.dst != start:
                seen.add(edge.dst)
                queue.append(edge.dst)
    return len(seen)


def _format_steps(start: str, path: list[Edge]) -> list[str]:
    steps = [f"start: {start} ({'low/standard privilege'})"]
    cursor = start
    for edge in path:
        dst = "admin (arbitrary privilege)" if edge.dst == ADMIN else edge.dst
        steps.append(f"{cursor} --[{edge.technique}]--> {dst}")
        cursor = edge.dst
    return steps


def find_escalation_paths(inventory: Inventory) -> list[EscalationPath]:
    """One shortest escalation path to ADMIN per non-admin starting identity."""
    classified = classify_inventory(inventory)
    edges = build_edges(inventory)
    adj = _adjacency(edges)

    paths: list[EscalationPath] = []
    for ident in inventory.identities:
        if ident.kind == "group":
            continue
        # Skip identities that are already admin — that's a standing-admin finding,
        # not an escalation path.
        if classified[ident.name].privilege_tier == "admin":
            continue
        path = _shortest_path(ident.name, adj)
        if path:
            technique = " + ".join(dict.fromkeys(e.technique for e in path if e.rule_id != "admin_tier"))
            paths.append(
                EscalationPath(
                    start_identity=ident.name,
                    steps=_format_steps(ident.name, path),
                    reaches="admin (full account control)",
                    technique=technique or path[0].technique,
                )
            )
    # Most steps first — the more interesting chains lead.
    paths.sort(key=lambda p: len(p.steps), reverse=True)
    return paths


def escalation_path_edges(inventory: Inventory) -> list[Edge]:
    """The edges that lie on a reported shortest escalation path.

    Used by the reporter to draw a focused diagram of the actual attack paths,
    rather than the full (visually noisy) edge set.
    """
    classified = classify_inventory(inventory)
    edges = build_edges(inventory)
    adj = _adjacency(edges)
    out: list[Edge] = []
    seen: set[tuple[str, str, str]] = set()
    for ident in inventory.identities:
        if ident.kind == "group" or classified[ident.name].privilege_tier == "admin":
            continue
        path = _shortest_path(ident.name, adj)
        if not path:
            continue
        for e in path:
            key = (e.src, e.dst, e.technique)
            if key not in seen:
                seen.add(key)
                out.append(e)
    return out


def escalation_reach_counts(inventory: Inventory) -> dict[str, int]:
    """Per-identity blast radius, for the risk scorer."""
    edges = build_edges(inventory)
    adj = _adjacency(edges)
    return {
        ident.name: _reachable_count(ident.name, adj)
        for ident in inventory.identities
        if ident.kind != "group"
    }


def diff_paths(
    before: list[EscalationPath], after: list[EscalationPath]
) -> list[EscalationPath]:
    """Annotate each before-path with whether remediation cut it."""
    after_starts = {p.start_identity for p in after}
    annotated: list[EscalationPath] = []
    for p in before:
        cut = p.start_identity not in after_starts
        annotated.append(
            EscalationPath(
                start_identity=p.start_identity,
                steps=p.steps,
                reaches=p.reaches,
                technique=p.technique,
                cut_by="remediation (path no longer reaches admin)" if cut else None,
            )
        )
    return annotated
