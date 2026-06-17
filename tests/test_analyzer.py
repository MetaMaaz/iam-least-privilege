"""Analyzer tests — findings across categories, principle citations, risk scores."""

from analyzer.analyzer import analyze, score_risk
from analyzer.escalation import escalation_reach_counts


def _by_category(findings):
    out = {}
    for f in findings:
        out.setdefault(f.category, []).append(f)
    return out


def test_every_finding_cites_a_principle(mock_inventory):
    for f in analyze(mock_inventory):
        assert f.principle and f.principle.strip(), f"{f.identity}/{f.category} missing principle"
        assert f.recommendation, f"{f.identity}/{f.category} missing recommendation"


def test_standing_admin_on_human(mock_inventory):
    cats = _by_category(analyze(mock_inventory))
    admins = {f.identity for f in cats.get("standing-admin", [])}
    assert "legacy-admin" in admins


def test_long_lived_key_detected(mock_inventory):
    cats = _by_category(analyze(mock_inventory))
    flagged = {f.identity for f in cats.get("long-lived-key", [])}
    # ci-deploy-user (419d) and legacy-admin (612d) have old keys
    assert "ci-deploy-user" in flagged
    assert "legacy-admin" in flagged


def test_dangerous_combo_detected(mock_inventory):
    cats = _by_category(analyze(mock_inventory))
    combos = {f.identity for f in cats.get("dangerous-combo", [])}
    assert "dev-user" in combos  # iam:PassRole + lambda:CreateFunction


def test_unused_access_detected(mock_inventory):
    cats = _by_category(analyze(mock_inventory))
    unused = {f.identity for f in cats.get("unused", [])}
    assert "power-analyst" in unused  # ec2/rds untouched for months


def test_clean_identity_has_no_critical_findings(mock_inventory):
    findings = analyze(mock_inventory)
    auditor = [f for f in findings if f.identity == "read-only-auditor"]
    assert all(f.severity != "critical" for f in auditor)


def test_risk_scores_rank_dev_user_high(mock_inventory):
    findings = analyze(mock_inventory)
    reach = escalation_reach_counts(mock_inventory)
    scores = {r.identity: r for r in score_risk(mock_inventory, findings, reach)}
    # the escalation entry points should out-score the clean auditor
    assert scores["dev-user"].score > scores["read-only-auditor"].score
    assert scores["read-only-auditor"].band in ("low", "medium")
