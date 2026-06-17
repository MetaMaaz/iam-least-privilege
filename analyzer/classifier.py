"""Identity & permission classification — pure logic, no AWS calls.

Loads ``data/sensitive_actions.yaml`` and, for each identity, computes:
  * a **privilege tier** (admin / power / standard / limited),
  * the set of **sensitive services** it can touch,
  * whether it holds **wildcard** grants.

The classifier annotates each ``Identity`` in place (``privilege_tier`` and
``sensitive_services``) and returns helper structures the analyzer and reporter
reuse, so group membership is only resolved once.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Optional

import yaml

from analyzer.models import Identity, Inventory, Permission

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")


@lru_cache(maxsize=4)
def load_sensitive_actions(path: Optional[str] = None) -> dict:
    path = path or os.path.join(_DATA_DIR, "sensitive_actions.yaml")
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _action_matches(held: str, pattern: str) -> bool:
    """True if a held action satisfies a pattern, honouring AWS wildcards.

    ``iam:*`` (held) satisfies the pattern ``iam:PassRole``; ``*`` satisfies
    anything; an exact string matches itself; a ``foo:*`` pattern is satisfied
    by any ``foo:Action``.
    """
    if held == "*":
        return True
    if held == pattern:
        return True
    # held is a service wildcard, e.g. 'iam:*'
    if held.endswith(":*"):
        service = held[:-2]
        return pattern == "*" or pattern.split(":", 1)[0] == service
    # pattern is a service wildcard, e.g. 'iam:*' — held within that service
    if pattern.endswith(":*"):
        service = pattern[:-2]
        return held.split(":", 1)[0] == service
    return False


@dataclass
class ClassifiedIdentity:
    """Classifier output for one identity (kept alongside the annotated Identity)."""

    identity: Identity
    privilege_tier: str
    sensitive_services: dict[str, int]  # service -> sensitivity weight
    high_signal_hits: list[str] = field(default_factory=list)
    wildcard_actions: list[Permission] = field(default_factory=list)
    wildcard_resources: list[Permission] = field(default_factory=list)
    reach_score: int = 0


def effective_permissions(identity: Identity, inventory: Inventory) -> list[Permission]:
    """All Allow permissions for an identity, including inherited group grants.

    Users inherit the policies of every group named in ``attached_groups``.
    Roles and groups contribute only their own policies.
    """
    perms = list(identity.all_permissions())
    for group_name in identity.attached_groups:
        group = inventory.by_name(group_name)
        if group is not None and group.kind == "group":
            perms.extend(group.all_permissions())
    return perms


def classify_identity(identity: Identity, inventory: Inventory) -> ClassifiedIdentity:
    cfg = load_sensitive_actions()
    sensitive_cfg: dict = cfg["sensitive_services"]
    high_signal: list[str] = cfg["high_signal_actions"]
    thresholds: dict = cfg["tier_thresholds"]

    perms = [p for p in effective_permissions(identity, inventory) if p.effect == "Allow"]

    sensitive_hits: dict[str, int] = {}
    high_signal_hits: list[str] = []
    wildcard_actions: list[Permission] = []
    wildcard_resources: list[Permission] = []
    reach = 0

    for perm in perms:
        service = perm.action_service()

        if perm.is_action_wildcard():
            wildcard_actions.append(perm)
        if perm.is_resource_wildcard():
            wildcard_resources.append(perm)

        # sensitive service?
        if service in sensitive_cfg:
            weight = sensitive_cfg[service]["sensitivity"]
            # only the strongest hit per service is kept for display
            sensitive_hits[service] = max(sensitive_hits.get(service, 0), weight)
            # reach: weight, doubled when paired with a wildcard resource
            reach += weight * (2 if perm.is_resource_wildcard() else 1)

        # high-signal action?
        for sig in high_signal:
            if _action_matches(perm.action, sig):
                if sig not in high_signal_hits:
                    high_signal_hits.append(sig)
                # high-signal actions on '*' resource carry account-takeover risk
                reach += 12 if perm.is_resource_wildcard() else 6
                break

    # '*' on '*' is unbounded admin.
    if any(p.action == "*" and p.is_resource_wildcard() for p in perms):
        reach = max(reach, thresholds["admin"])
    # iam:* on '*' is effectively admin too.
    if any(
        _action_matches(p.action, "iam:*") and p.action.endswith(":*") and p.is_resource_wildcard()
        for p in perms
    ):
        reach = max(reach, thresholds["admin"])

    tier = _tier_for(reach, thresholds)

    identity.privilege_tier = tier
    identity.sensitive_services = sorted(sensitive_hits.keys())

    return ClassifiedIdentity(
        identity=identity,
        privilege_tier=tier,
        sensitive_services=sensitive_hits,
        high_signal_hits=high_signal_hits,
        wildcard_actions=wildcard_actions,
        wildcard_resources=wildcard_resources,
        reach_score=reach,
    )


def _tier_for(reach: int, thresholds: dict) -> str:
    if reach >= thresholds["admin"]:
        return "admin"
    if reach >= thresholds["power"]:
        return "power"
    if reach >= thresholds["standard"]:
        return "standard"
    return "limited"


def classify_inventory(inventory: Inventory) -> dict[str, ClassifiedIdentity]:
    """Classify every identity; returns name -> ClassifiedIdentity."""
    return {
        ident.name: classify_identity(ident, inventory) for ident in inventory.identities
    }
