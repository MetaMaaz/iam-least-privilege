"""Core data structures for the IAM Least-Privilege Analyzer.

These dataclasses are the contract between ingestion (AWS-facing) and the
reasoning modules (classifier / analyzer / escalation / recommender / reporter).
Nothing in here calls AWS. ``Inventory.from_json`` accepts both real
``aws iam get-account-authorization-details`` exports and the hand-written
mock account, so the whole analysis pipeline can run fully offline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Privilege tiers and severities are plain strings, but we keep the allowed
# values here so the rest of the codebase reads from one source of truth.
# ---------------------------------------------------------------------------

PRIVILEGE_TIERS = ("admin", "power", "standard", "limited")
SEVERITIES = ("critical", "high", "medium", "low", "info")
FINDING_CATEGORIES = (
    "wildcard",
    "over-provisioned",
    "unused",
    "dangerous-combo",
    "standing-admin",
    "long-lived-key",
)


@dataclass(frozen=True)
class Permission:
    """A single (effect, action, resource) grant.

    Mirrors one expanded entry of an IAM policy ``Statement``. A statement that
    lists several actions or resources is expanded into one ``Permission`` per
    (action, resource) pair at ingestion time so downstream logic never has to
    re-loop over lists.
    """

    action: str
    resource: str
    effect: str = "Allow"
    conditions: Optional[dict[str, Any]] = None

    def action_service(self) -> str:
        """Return the AWS service prefix, e.g. ``iam`` for ``iam:PassRole``."""
        return self.action.split(":", 1)[0] if ":" in self.action else self.action

    def is_action_wildcard(self) -> bool:
        return self.action == "*" or self.action.endswith(":*")

    def is_resource_wildcard(self) -> bool:
        return self.resource == "*"


@dataclass
class Policy:
    """A named policy attached to an identity.

    ``type`` is one of: ``managed`` (customer managed), ``inline``,
    ``aws-managed``.
    """

    name: str
    type: str
    permissions: list[Permission] = field(default_factory=list)


@dataclass
class Identity:
    """A user, role, or group plus the access it holds.

    ``last_used`` maps a service prefix (e.g. ``s3``) to the number of days
    since it was last used, when that data is available (boto3 / Access
    Advisor). ``None`` means we have no usage data and unused-access checks
    should degrade gracefully.
    """

    name: str
    kind: str  # user / role / group
    policies: list[Policy] = field(default_factory=list)
    attached_groups: list[str] = field(default_factory=list)
    last_used: Optional[dict[str, int]] = None
    # role-only: which principals are allowed to sts:AssumeRole this role
    trusted_principals: list[str] = field(default_factory=list)
    # user-only: ages in days of any long-lived access keys
    access_key_ages: list[int] = field(default_factory=list)

    # populated by the classifier; kept on the object so the reporter can read
    # back a single annotated inventory.
    privilege_tier: Optional[str] = None
    sensitive_services: list[str] = field(default_factory=list)

    def all_permissions(self) -> list[Permission]:
        """Flatten every permission across every attached policy."""
        out: list[Permission] = []
        for policy in self.policies:
            out.extend(policy.permissions)
        return out

    def allowed_actions(self) -> set[str]:
        return {p.action for p in self.all_permissions() if p.effect == "Allow"}


@dataclass
class Finding:
    """A single issue discovered by the analyzer.

    ``principle`` is the framework citation that makes the finding defensible
    (NIST SP 800-207 control text or a named AWS IAM best practice).
    """

    identity: str
    severity: str
    category: str
    detail: str
    principle: str
    recommendation: str = ""

    # severity → weight, used by the risk scorer.
    SEVERITY_WEIGHTS = {
        "critical": 40,
        "high": 25,
        "medium": 12,
        "low": 5,
        "info": 1,
    }

    @property
    def weight(self) -> int:
        return self.SEVERITY_WEIGHTS.get(self.severity, 0)


@dataclass
class EscalationPath:
    """A concrete privilege-escalation chain.

    ``steps`` is the human-readable hop list; ``reaches`` is the highest
    privilege the start identity can attain; ``cut_by`` names the remediation
    that breaks the path (populated when comparing before/after).
    """

    start_identity: str
    steps: list[str]
    reaches: str
    technique: str = ""
    cut_by: Optional[str] = None


@dataclass
class RiskScore:
    """Per-identity aggregate risk, for a sortable headline metric."""

    identity: str
    score: int
    band: str  # critical / high / medium / low
    contributing: list[str] = field(default_factory=list)


@dataclass
class Inventory:
    """The whole account: a flat list of identities."""

    identities: list[Identity] = field(default_factory=list)
    account_id: str = "REDACTED"

    def by_name(self, name: str) -> Optional[Identity]:
        for ident in self.identities:
            if ident.name == name:
                return ident
        return None

    def of_kind(self, kind: str) -> list[Identity]:
        return [i for i in self.identities if i.kind == kind]

    # -- loading ----------------------------------------------------------

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Inventory":
        """Build an Inventory from either the mock format or a real AWS export.

        We detect the format by structure. The mock file uses a simple,
        human-authorable shape (top-level ``identities`` list). A real
        ``get-account-authorization-details`` export uses AWS' verbose keys
        (``UserDetailList``, ``RoleDetailList``, ``GroupDetailList``,
        ``Policies``). The actual AWS parsing lives in ``ingestion.py`` to keep
        this module free of AWS-specific knowledge; here we only handle the
        native/mock shape.
        """
        if "identities" in data:
            return cls._from_native(data)
        # Defer to ingestion for the AWS shape to keep models.py AWS-agnostic.
        from analyzer.ingestion import inventory_from_aws_export

        return inventory_from_aws_export(data)

    @classmethod
    def _from_native(cls, data: dict[str, Any]) -> "Inventory":
        identities: list[Identity] = []
        for raw in data.get("identities", []):
            policies = [
                Policy(
                    name=p["name"],
                    type=p.get("type", "inline"),
                    permissions=[
                        Permission(
                            action=perm["action"],
                            resource=perm.get("resource", "*"),
                            effect=perm.get("effect", "Allow"),
                            conditions=perm.get("conditions"),
                        )
                        for perm in p.get("permissions", [])
                    ],
                )
                for p in raw.get("policies", [])
            ]
            identities.append(
                Identity(
                    name=raw["name"],
                    kind=raw["kind"],
                    policies=policies,
                    attached_groups=raw.get("attached_groups", []),
                    last_used=raw.get("last_used"),
                    trusted_principals=raw.get("trusted_principals", []),
                    access_key_ages=raw.get("access_key_ages", []),
                )
            )
        return cls(identities=identities, account_id=data.get("account_id", "REDACTED"))
