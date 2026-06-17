"""AWS-facing ingestion — the ONLY module that knows about AWS shapes.

Two entry points:
  * ``inventory_from_aws_export`` — parse an
    ``aws iam get-account-authorization-details`` JSON blob (read-only snapshot).
  * ``inventory_from_live`` — optional boto3 path that pulls the same data with
    **read-only** credentials, plus service-last-accessed data for unused-access
    detection. Kept thin and lazy-imported so the offline pipeline never needs
    boto3 installed.

Everything downstream consumes the plain ``Inventory`` these produce, so all the
interesting logic stays testable offline against the mock account.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from analyzer.models import Identity, Inventory, Permission, Policy


# ---------------------------------------------------------------------------
# Parsing a get-account-authorization-details export.
# ---------------------------------------------------------------------------

def _expand_statements(policy_doc: dict[str, Any]) -> list[Permission]:
    """Expand an IAM policy document into one Permission per (action, resource)."""
    perms: list[Permission] = []
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        effect = stmt.get("Effect", "Allow")
        actions = stmt.get("Action", stmt.get("NotAction", []))
        resources = stmt.get("Resource", stmt.get("NotResource", "*"))
        conditions = stmt.get("Condition")
        actions = [actions] if isinstance(actions, str) else list(actions)
        resources = [resources] if isinstance(resources, str) else list(resources)
        for action in actions:
            for resource in resources:
                perms.append(Permission(action=action, resource=resource, effect=effect, conditions=conditions))
    return perms


def _managed_policy_lookup(data: dict[str, Any]) -> dict[str, list[Permission]]:
    """Map customer-managed policy ARN -> permissions (from the Policies list)."""
    lookup: dict[str, list[Permission]] = {}
    for pol in data.get("Policies", []):
        arn = pol.get("Arn", pol.get("PolicyName", ""))
        # default version document
        doc = None
        for ver in pol.get("PolicyVersionList", []):
            if ver.get("IsDefaultVersion"):
                doc = ver.get("Document")
                break
        if doc:
            lookup[arn] = _expand_statements(doc)
    return lookup


def _policies_for(entity: dict[str, Any], managed: dict[str, list[Permission]]) -> list[Policy]:
    policies: list[Policy] = []
    # inline
    for inline in entity.get("UserPolicyList", []) + entity.get("RolePolicyList", []) + entity.get("GroupPolicyList", []):
        policies.append(
            Policy(
                name=inline.get("PolicyName", "inline"),
                type="inline",
                permissions=_expand_statements(inline.get("PolicyDocument", {})),
            )
        )
    # attached managed
    for att in entity.get("AttachedManagedPolicies", []):
        arn = att.get("PolicyArn", "")
        name = att.get("PolicyName", arn)
        ptype = "aws-managed" if ":aws:policy/" in arn else "managed"
        policies.append(Policy(name=name, type=ptype, permissions=managed.get(arn, [])))
    return policies


def inventory_from_aws_export(data: dict[str, Any]) -> Inventory:
    """Parse a get-account-authorization-details blob into an Inventory."""
    managed = _managed_policy_lookup(data)
    identities: list[Identity] = []

    for user in data.get("UserDetailList", []):
        identities.append(
            Identity(
                name=user.get("UserName", ""),
                kind="user",
                policies=_policies_for(user, managed),
                attached_groups=user.get("GroupList", []),
            )
        )
    for role in data.get("RoleDetailList", []):
        trusted = _trusted_principals(role.get("AssumeRolePolicyDocument", {}))
        identities.append(
            Identity(
                name=role.get("RoleName", ""),
                kind="role",
                policies=_policies_for(role, managed),
                trusted_principals=trusted,
            )
        )
    for group in data.get("GroupDetailList", []):
        identities.append(
            Identity(
                name=group.get("GroupName", ""),
                kind="group",
                policies=_policies_for(group, managed),
            )
        )

    account_id = data.get("_account_id", "REDACTED")
    return Inventory(identities=identities, account_id=account_id)


def _trusted_principals(assume_doc: dict[str, Any]) -> list[str]:
    out: list[str] = []
    statements = assume_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        principal = stmt.get("Principal", {})
        for _, val in principal.items():
            out.extend([val] if isinstance(val, str) else list(val))
    return out


# ---------------------------------------------------------------------------
# Loading from a file (export path).
# ---------------------------------------------------------------------------

def load_inventory(path: str) -> Inventory:
    """Load an Inventory from a JSON file (mock format or AWS export)."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return Inventory.from_json(data)


# ---------------------------------------------------------------------------
# Optional live boto3 path (read-only). Lazy-imported.
# ---------------------------------------------------------------------------

def inventory_from_live(profile: Optional[str] = None, region: str = "us-east-1") -> Inventory:
    """Pull IAM via boto3 with READ-ONLY credentials.

    Requires the caller's profile to be read-only. This function never calls any
    write/Put/Create/Delete API. It uses get_account_authorization_details and,
    where permitted, service-last-accessed data for unused-access detection.

    Lazy-imports boto3 so the offline pipeline has zero AWS dependencies.
    """
    try:
        import boto3  # noqa: WPS433 (intentional lazy import)
    except ImportError as exc:  # pragma: no cover - only hit without boto3
        raise RuntimeError(
            "boto3 is required for --live ingestion. Install with "
            "`pip install boto3`, and use a read-only profile."
        ) from exc

    session = boto3.Session(profile_name=profile, region_name=region)
    iam = session.client("iam")

    paginator = iam.get_paginator("get_account_authorization_details")
    merged: dict[str, list] = {
        "UserDetailList": [],
        "RoleDetailList": [],
        "GroupDetailList": [],
        "Policies": [],
    }
    for page in paginator.paginate():
        for key in merged:
            merged[key].extend(page.get(key, []))

    inventory = inventory_from_aws_export(merged)
    # Best-effort enrichment with last-used data is left as a documented
    # extension point; it requires GenerateServiceLastAccessedDetails which is
    # async. Kept out of the v1 read path to stay simple and side-effect-free.
    return inventory
