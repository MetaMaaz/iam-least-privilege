"""Finding generation + risk scoring — pure logic, core deliverable part 1.

Consumes the classified inventory and emits severity-ranked ``Finding`` objects
across six categories, then rolls them up (with escalation reachability) into a
per-identity numeric ``RiskScore`` so the report has a sortable headline metric.

Every Finding cites the principle it violates — NIST SP 800-207 (identity
pillar: least privilege / per-request access) or a named AWS IAM best practice.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Optional

import yaml

from analyzer.classifier import (
    ClassifiedIdentity,
    _action_matches,
    classify_inventory,
    effective_permissions,
)
from analyzer.models import Finding, Identity, Inventory, RiskScore

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")

# Tunable thresholds.
UNUSED_THRESHOLD_DAYS = 90
KEY_MAX_AGE_DAYS = 90

_NIST_LEAST_PRIV = (
    "NIST SP 800-207 §2.1 (tenet 6, per-request access) & identity pillar — "
    "grant the minimum privilege required, re-evaluated per request."
)
_AWS_NO_WILDCARD = "AWS IAM best practice — grant least privilege; avoid Action/Resource wildcards."
_AWS_ROLES_OVER_KEYS = "AWS IAM best practice — prefer temporary role credentials over long-lived access keys."
_AWS_NO_STANDING_ADMIN = "AWS IAM best practice — avoid standing admin on humans; use roles + just-in-time elevation."


@lru_cache(maxsize=4)
def load_escalation_rules(path: Optional[str] = None) -> dict:
    path = path or os.path.join(_DATA_DIR, "escalation_rules.yaml")
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# ---------------------------------------------------------------------------
# Individual checks. Each returns a list[Finding].
# ---------------------------------------------------------------------------

def find_wildcards(ci: ClassifiedIdentity) -> list[Finding]:
    findings: list[Finding] = []
    name = ci.identity.name
    for perm in ci.wildcard_actions:
        # '*' on '*' is its own (more severe) finding handled by standing-admin.
        if perm.action == "*" and perm.is_resource_wildcard():
            continue
        sev = "high" if perm.is_resource_wildcard() else "medium"
        findings.append(
            Finding(
                identity=name,
                severity=sev,
                category="wildcard",
                detail=(
                    f"Policy grants wildcard action '{perm.action}' on "
                    f"resource '{perm.resource}'. The identity can perform every "
                    f"action in the {perm.action_service()} service."
                ),
                principle=_AWS_NO_WILDCARD,
                recommendation=(
                    f"Replace '{perm.action}' with the specific "
                    f"{perm.action_service()} actions actually used, and scope "
                    f"the resource to specific ARNs."
                ),
            )
        )
    return findings


def find_over_provisioned(ci: ClassifiedIdentity) -> list[Finding]:
    """Broad grants beyond what the identity plausibly needs.

    Heuristic: an identity holding sensitive wildcard services it has not used
    recently (or at all) is over-provisioned. We keep this conservative and
    explainable rather than guessing intent.
    """
    findings: list[Finding] = []
    ident = ci.identity
    last_used = ident.last_used or {}
    for perm in ci.wildcard_actions:
        service = perm.action_service()
        days = last_used.get(service)
        if days is not None and days > UNUSED_THRESHOLD_DAYS:
            findings.append(
                Finding(
                    identity=ident.name,
                    severity="medium",
                    category="over-provisioned",
                    detail=(
                        f"Holds broad '{perm.action}' but last used the "
                        f"{service} service {days} days ago — the grant far "
                        f"exceeds demonstrated need."
                    ),
                    principle=_NIST_LEAST_PRIV,
                    recommendation=(
                        f"Remove {service} access, or downscope to the handful "
                        f"of read actions usage history shows are needed."
                    ),
                )
            )
    return findings


def find_unused(ci: ClassifiedIdentity, inventory: Inventory) -> list[Finding]:
    """Services granted but not touched in N days. Degrades gracefully."""
    ident = ci.identity
    if not ident.last_used:
        return []
    findings: list[Finding] = []
    granted_services = {
        p.action_service()
        for p in effective_permissions(ident, inventory)
        if p.effect == "Allow"
    }
    for service in sorted(granted_services):
        days = ident.last_used.get(service)
        if days is not None and days > UNUSED_THRESHOLD_DAYS:
            findings.append(
                Finding(
                    identity=ident.name,
                    severity="low",
                    category="unused",
                    detail=(
                        f"Access to the {service} service is granted but unused "
                        f"for {days} days (threshold {UNUSED_THRESHOLD_DAYS})."
                    ),
                    principle=_NIST_LEAST_PRIV,
                    recommendation=f"Revoke {service} access; re-grant on demand if needed.",
                )
            )
    return findings


def find_dangerous_combos(ident: Identity, inventory: Inventory) -> list[Finding]:
    """Known privilege-escalation permission patterns (from escalation_rules.yaml)."""
    rules = load_escalation_rules()["rules"]
    held = {p.action for p in effective_permissions(ident, inventory) if p.effect == "Allow"}
    findings: list[Finding] = []
    for rule in rules:
        required = rule["requires_all"]
        if all(any(_action_matches(h, req) for h in held) for req in required):
            findings.append(
                Finding(
                    identity=ident.name,
                    severity="critical",
                    category="dangerous-combo",
                    detail=(
                        f"Holds the '{rule['name']}' escalation pattern "
                        f"({rule['technique']}). {rule['id']}."
                    ),
                    principle=rule["principle"],
                    recommendation=rule["cut_by"],
                )
            )
    return findings


def find_standing_admin(ci: ClassifiedIdentity) -> list[Finding]:
    ident = ci.identity
    if ident.kind != "user":
        return []
    is_admin = ci.privilege_tier == "admin" or any(
        p.action == "*" and p.is_resource_wildcard()
        for p in ident.all_permissions()
    )
    if not is_admin:
        return []
    return [
        Finding(
            identity=ident.name,
            severity="critical",
            category="standing-admin",
            detail=(
                f"Human user '{ident.name}' holds standing administrator "
                f"privileges (tier: admin). Compromise of this single principal "
                f"is full account takeover."
            ),
            principle=_AWS_NO_STANDING_ADMIN,
            recommendation=(
                "Replace standing admin with a role assumed just-in-time (with "
                "MFA), so admin rights exist only during an active task."
            ),
        )
    ]


def find_long_lived_keys(ident: Identity) -> list[Finding]:
    findings: list[Finding] = []
    for age in ident.access_key_ages:
        if age > KEY_MAX_AGE_DAYS:
            sev = "high" if age > 365 else "medium"
            findings.append(
                Finding(
                    identity=ident.name,
                    severity=sev,
                    category="long-lived-key",
                    detail=(
                        f"Access key is {age} days old "
                        f"(threshold {KEY_MAX_AGE_DAYS}). Long-lived keys are a "
                        f"standing credential an attacker can exfiltrate and reuse."
                    ),
                    principle=_AWS_ROLES_OVER_KEYS,
                    recommendation=(
                        "Rotate or retire the key; migrate the workload to role "
                        "assumption (IAM Roles Anywhere / OIDC for CI)."
                    ),
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Orchestration.
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def analyze(inventory: Inventory) -> list[Finding]:
    """Run every check across the inventory; return severity-sorted findings."""
    classified = classify_inventory(inventory)
    findings: list[Finding] = []
    for ident in inventory.identities:
        ci = classified[ident.name]
        findings += find_wildcards(ci)
        findings += find_over_provisioned(ci)
        findings += find_unused(ci, inventory)
        # An admin-tier identity trivially holds every escalation primitive;
        # reporting each combo is noise. It is already flagged as standing-admin
        # (users) or wildcard/over-privileged (roles). Only surface dangerous
        # combos on non-admin identities, where they are the interesting signal.
        if ci.privilege_tier != "admin":
            findings += find_dangerous_combos(ident, inventory)
        findings += find_standing_admin(ci)
        findings += find_long_lived_keys(ident)
    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.identity, f.category))
    return findings


# ---------------------------------------------------------------------------
# Risk scoring (extra: sortable headline metric).
# ---------------------------------------------------------------------------

def _band(score: int) -> str:
    if score >= 60:
        return "critical"
    if score >= 35:
        return "high"
    if score >= 15:
        return "medium"
    return "low"


def score_risk(
    inventory: Inventory,
    findings: list[Finding],
    escalation_reach: Optional[dict[str, int]] = None,
) -> list[RiskScore]:
    """Aggregate findings (and escalation reachability) into a per-identity score.

    Score = sum of finding severity weights + a bonus for every distinct
    identity this principal can escalate to (blast radius). Capped at 100.
    """
    escalation_reach = escalation_reach or {}
    by_identity: dict[str, list[Finding]] = {i.name: [] for i in inventory.identities}
    for f in findings:
        by_identity.setdefault(f.identity, []).append(f)

    scores: list[RiskScore] = []
    for name, fs in by_identity.items():
        base = sum(f.weight for f in fs)
        reach = escalation_reach.get(name, 0)
        reach_bonus = min(reach * 10, 30)
        total = min(base + reach_bonus, 100)
        contributing = sorted({f.category for f in fs})
        if reach:
            contributing.append(f"escalates-to-{reach}")
        scores.append(
            RiskScore(identity=name, score=total, band=_band(total), contributing=contributing)
        )
    scores.sort(key=lambda s: s.score, reverse=True)
    return scores
