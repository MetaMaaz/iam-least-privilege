"""Escalation tests — the centrepiece: paths exist before, are cut after."""

from analyzer.escalation import (
    build_edges,
    diff_paths,
    find_escalation_paths,
)
from analyzer.recommender import build_remediated_inventory


def test_dev_user_reaches_admin_before(mock_inventory):
    starts = {p.start_identity for p in find_escalation_paths(mock_inventory)}
    assert "dev-user" in starts


def test_escalation_path_has_concrete_steps(mock_inventory):
    paths = {p.start_identity: p for p in find_escalation_paths(mock_inventory)}
    dev = paths["dev-user"]
    assert dev.reaches.startswith("admin")
    assert len(dev.steps) >= 2
    # the chain should mention passing a role or assuming one
    joined = " ".join(dev.steps).lower()
    assert "passrole" in joined or "assumerole" in joined


def test_remediation_cuts_all_paths(mock_inventory):
    before = find_escalation_paths(mock_inventory)
    remediated = build_remediated_inventory(mock_inventory)
    after = find_escalation_paths(remediated)
    before_starts = {p.start_identity for p in before}
    after_starts = {p.start_identity for p in after}
    # every low-privilege entry point that could reach admin no longer can
    assert before_starts, "expected at least one escalation path before remediation"
    assert not (before_starts & after_starts), (
        f"these still reach admin after remediation: {before_starts & after_starts}"
    )


def test_diff_marks_paths_cut(mock_inventory):
    before = find_escalation_paths(mock_inventory)
    remediated = build_remediated_inventory(mock_inventory)
    after = find_escalation_paths(remediated)
    annotated = diff_paths(before, after)
    assert all(p.cut_by for p in annotated)


def test_passrole_edge_is_resource_aware(mock_inventory):
    # before: dev-user can pass a role into Lambda
    edges = build_edges(mock_inventory)
    passrole = [e for e in edges if e.src == "dev-user" and "PassRole" in e.technique]
    assert passrole, "expected a PassRole edge from dev-user before remediation"
    # after scoping, the edge is gone
    remediated = build_remediated_inventory(mock_inventory)
    edges_after = build_edges(remediated)
    passrole_after = [e for e in edges_after if e.src == "dev-user" and "PassRole" in e.technique]
    assert not passrole_after


def test_clean_identities_have_no_path(mock_inventory):
    starts = {p.start_identity for p in find_escalation_paths(mock_inventory)}
    assert "read-only-auditor" not in starts
    assert "power-analyst" not in starts
