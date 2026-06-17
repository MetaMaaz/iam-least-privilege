"""Classifier tests — privilege tiers, wildcards, sensitive-action detection."""

from analyzer.classifier import (
    _action_matches,
    classify_inventory,
    effective_permissions,
)


def test_action_matching_honours_wildcards():
    assert _action_matches("*", "iam:PassRole")
    assert _action_matches("iam:*", "iam:PassRole")
    assert _action_matches("iam:PassRole", "iam:*")
    assert _action_matches("iam:PassRole", "iam:PassRole")
    assert not _action_matches("s3:GetObject", "iam:PassRole")
    assert not _action_matches("iam:GetUser", "iam:PassRole")


def test_admin_user_classified_admin(mock_inventory):
    ci = classify_inventory(mock_inventory)
    assert ci["legacy-admin"].privilege_tier == "admin"


def test_scoped_auditor_is_limited_or_standard(mock_inventory):
    ci = classify_inventory(mock_inventory)
    assert ci["read-only-auditor"].privilege_tier in ("limited", "standard")


def test_wildcards_detected(mock_inventory):
    ci = classify_inventory(mock_inventory)
    # power-analyst holds several 'service:*' grants
    actions = {p.action for p in ci["power-analyst"].wildcard_actions}
    assert "s3:*" in actions
    assert "ec2:*" in actions


def test_sensitive_services_flagged(mock_inventory):
    ci = classify_inventory(mock_inventory)
    assert "iam" in ci["lambda-exec-role"].sensitive_services
    assert "iam" in ci["ci-deploy-user"].sensitive_services


def test_group_permissions_are_inherited(mock_inventory):
    dev = mock_inventory.by_name("dev-user")
    actions = {p.action for p in effective_permissions(dev, mock_inventory)}
    # sts:AssumeRole comes from the 'developers' group, not the user's own policy
    assert "sts:AssumeRole" in actions
    assert "lambda:CreateFunction" in actions
