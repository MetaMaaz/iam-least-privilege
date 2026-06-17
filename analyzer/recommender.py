"""Least-privilege recommender — pure logic, core deliverable part 2.

For each over-provisioned identity, emit a **tightened, applicable AWS policy
document** (valid JSON the user could actually attach), each statement carrying
a justification. Also builds a *remediated* ``Inventory`` so the escalation
engine can prove the privilege-escalation path is cut.

Remediation rules (least-privilege, explainable):
  * Drop access to services unused beyond the threshold.
  * Scope ``iam:PassRole`` from ``*`` to a safe, non-privileged role ARN.
  * Strip identity-write actions (Put*/Attach*/CreateAccessKey/…) from
    non-administrators — these are the self-escalation primitives.
  * Scope ``sts:AssumeRole`` from ``*`` to an explicit allow-list.
  * Replace remaining service wildcards with a conservative read set, flagged
    for human confirmation against real usage.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field

from analyzer.analyzer import UNUSED_THRESHOLD_DAYS
from analyzer.classifier import _action_matches, classify_inventory
from analyzer.models import Identity, Inventory, Permission, Policy

# Self-escalation primitives removed from non-admins (the priv-esc verbs).
_SELF_ESCALATION_ACTIONS = {
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutGroupPolicy",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:UpdateAssumeRolePolicy",
}

# Placeholder ARNs the user replaces with their real values.
_SAFE_PASSROLE_ARN = "arn:aws:iam::ACCOUNT_ID:role/app-runtime-nonprivileged"
_SAFE_ASSUME_ARN = "arn:aws:iam::ACCOUNT_ID:role/scoped-task-role"


@dataclass
class Recommendation:
    identity: str
    policy_document: dict  # valid AWS policy JSON
    justifications: list[str] = field(default_factory=list)


def _read_scoped(service: str) -> list[str]:
    """Conservative read-only replacement for a 'service:*' wildcard."""
    return [f"{service}:Get*", f"{service}:List*", f"{service}:Describe*"]


def _used_recently(ident: Identity, service: str) -> bool:
    lu = ident.last_used or {}
    days = lu.get(service)
    # No data → keep but downscope (flag for review). Data within threshold → used.
    return days is None or days <= UNUSED_THRESHOLD_DAYS


def tighten_identity(ident: Identity, is_admin_tier: bool) -> tuple[list[Permission], list[str]]:
    """Return (tightened permissions, justifications) for one identity's own policies.

    Operates on the identity's directly-attached permissions (group policies are
    tightened on the group itself).
    """
    new_perms: list[Permission] = []
    notes: list[str] = []
    seen: set[tuple[str, str]] = set()

    def add(action: str, resource: str, cond=None):
        key = (action, resource)
        if key not in seen:
            seen.add(key)
            new_perms.append(Permission(action=action, resource=resource, effect="Allow", conditions=cond))

    for perm in ident.all_permissions():
        if perm.effect != "Allow":
            new_perms.append(perm)
            continue

        action = perm.action
        service = perm.action_service()

        # 1) Full admin '*' on '*' — rebuild from demonstrated need only.
        if action == "*" and perm.is_resource_wildcard():
            used = sorted((ident.last_used or {}).keys())
            if used:
                for svc in used:
                    if _used_recently(ident, svc):
                        for a in _read_scoped(svc):
                            add(a, "*")
                notes.append(
                    f"Removed '*:*' admin grant; reconstructed minimal read access "
                    f"for services actually used ({', '.join(used)}). Confirm write "
                    f"needs explicitly."
                )
            else:
                notes.append("Removed '*:*' admin grant; no usage history — re-grant specific actions on demand.")
            continue

        # 2) Self-escalation primitives — strip from non-admins.
        if not is_admin_tier and any(_action_matches(action, a) for a in _SELF_ESCALATION_ACTIONS):
            notes.append(
                f"Removed identity-write action '{action}' (self-escalation "
                f"primitive); route privileged IAM changes through change-management."
            )
            continue
        # service-wildcard iam:* also covers the primitives — downscope it.
        if not is_admin_tier and action == "iam:*":
            notes.append("Replaced 'iam:*' with read-only iam:Get*/List* (removed all IAM write/escalation verbs).")
            add("iam:GetUser", "*")
            add("iam:ListAccessKeys", "*")
            continue

        # 3) iam:PassRole — scope away from '*'.
        if _action_matches(action, "iam:PassRole") and perm.is_resource_wildcard():
            add("iam:PassRole", _SAFE_PASSROLE_ARN,
                cond={"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}})
            notes.append(
                "Scoped 'iam:PassRole' from '*' to a single non-privileged role ARN "
                "with a PassedToService condition — cuts the PassRole escalation edge."
            )
            continue

        # 4) sts:AssumeRole on '*' — scope to an allow-list.
        if _action_matches(action, "sts:AssumeRole") and perm.is_resource_wildcard():
            add("sts:AssumeRole", _SAFE_ASSUME_ARN)
            notes.append("Scoped 'sts:AssumeRole' from '*' to an explicit role allow-list.")
            continue

        # 5) Drop services unused beyond threshold.
        if not _used_recently(ident, service):
            days = (ident.last_used or {}).get(service)
            notes.append(f"Dropped '{action}' — {service} unused for {days} days.")
            continue

        # 6) Remaining service wildcard — downscope to conservative reads.
        if perm.is_action_wildcard() and action.endswith(":*"):
            for a in _read_scoped(service):
                add(a, perm.resource)
            notes.append(
                f"Replaced wildcard '{action}' with read-only "
                f"{service}:Get*/List*/Describe* (confirm any write actions needed)."
            )
            continue

        # 7) Already specific & used — keep as-is.
        add(action, perm.resource, perm.conditions)

    return new_perms, notes


def _policy_document(perms: list[Permission]) -> dict:
    """Render permissions as a valid AWS IAM policy document."""
    statements = []
    for p in perms:
        stmt = {"Effect": p.effect, "Action": p.action, "Resource": p.resource}
        if p.conditions:
            stmt["Condition"] = p.conditions
        statements.append(stmt)
    return {"Version": "2012-10-17", "Statement": statements}


def recommend(inventory: Inventory) -> list[Recommendation]:
    """Tightened policy per identity that has something to tighten."""
    classified = classify_inventory(inventory)
    recs: list[Recommendation] = []
    for ident in inventory.identities:
        is_admin = classified[ident.name].privilege_tier == "admin" and ident.kind == "role"
        # We still tighten admin roles' wildcards, but never strip the role's
        # core identity-management purpose if it is a genuine admin role.
        tightened, notes = tighten_identity(ident, is_admin_tier=is_admin)
        original_actions = {p.action for p in ident.all_permissions()}
        new_actions = {p.action for p in tightened}
        if notes or original_actions != new_actions:
            recs.append(
                Recommendation(
                    identity=ident.name,
                    policy_document=_policy_document(tightened),
                    justifications=notes,
                )
            )
    return recs


def build_remediated_inventory(inventory: Inventory) -> Inventory:
    """Apply the tightening to produce a new Inventory (for before/after escalation)."""
    classified = classify_inventory(inventory)
    new_identities: list[Identity] = []
    for ident in inventory.identities:
        clone = copy.deepcopy(ident)
        is_admin = classified[ident.name].privilege_tier == "admin" and ident.kind == "role"
        tightened, _ = tighten_identity(ident, is_admin_tier=is_admin)
        clone.policies = [Policy(name=f"{ident.name}-least-privilege", type="inline", permissions=tightened)]
        new_identities.append(clone)
    return Inventory(identities=new_identities, account_id=inventory.account_id)
