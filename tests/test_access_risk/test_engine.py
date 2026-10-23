import copy
from pathlib import Path

from guardian.access_risk.engine import analyze
from guardian.access_risk.loader import load_input

ROOT = Path(__file__).parents[2]


def data():
    return load_input(ROOT / "examples/access_risk_demo.json")


def tuples(report):
    return {(f["rule_id"], f["identity_id"], f.get("permission_id")) for f in report["findings"]}


def test_demo_seeds_all_six_rules():
    r = analyze(data(), contract_reports=[str(ROOT / "examples/access_risk_contract_report.json")])
    assert {x[0] for x in tuples(r)} >= {
        "stale_identity",
        "unused_permission",
        "excessive_scope",
        "peer_drift",
        "unusual_activity",
        "cross_layer_exposure",
    }


def test_stale_status_severity_and_expired_grant_negative():
    d = data()
    d["grants"][0]["expires_at"] = "2026-10-22T00:00:00Z"
    r = analyze(d)
    assert ("stale_identity", "user-01", "p-admin") not in tuples(r)


def test_unused_coverage_positive_and_log_gap_insufficient():
    r = analyze(data())
    fs = [f for f in r["findings"] if f["rule_id"] == "unused_permission"]
    assert any(f["identity_id"] == "user-02" and not f["insufficient_evidence"] for f in fs)
    assert any(f["identity_id"] == "user-08" and f["insufficient_evidence"] for f in fs)


def test_recent_grant_not_unused():
    assert not any(
        f["rule_id"] == "unused_permission"
        and f["identity_id"] == "user-07"
        and f["permission_id"] == "p-new"
        and not f["insufficient_evidence"]
        for f in analyze(data())["findings"]
    )


def test_broad_scope_matrix():
    r = analyze(data())
    f = next(
        f
        for f in r["findings"]
        if f["rule_id"] == "excessive_scope" and f["identity_id"] == "user-04"
    )
    assert f["severity"] == "CRITICAL"


def test_peer_rare_positive_and_group_size_note():
    d = data()
    r = analyze(d)
    assert ("peer_drift", "user-03", "p-rare") in tuples(r)
    d["identities"] = d["identities"][:2]
    d["grants"] = [g for g in d["grants"] if g["user_id"] in {"user-01", "user-02"}]
    r = analyze(d)
    assert any(f["rule_id"] == "peer_drift" and f["insufficient_evidence"] for f in r["findings"])


def test_unusual_activity_new_country_and_baseline_insufficient():
    d = data()
    r = analyze(d)
    assert any(
        f["rule_id"] == "unusual_activity"
        and f["identity_id"] == "user-09"
        and "new_country" in f["evidence"][0]["signals"]
        for f in r["findings"]
    )
    d["events"] = []
    r = analyze(d)
    assert any(
        f["rule_id"] == "unusual_activity" and f["insufficient_evidence"] for f in r["findings"]
    )


def test_cross_layer_increases_priority_without_changing_severity():
    d = data()
    baseline = copy.deepcopy(d)
    baseline["assets"][0]["vyper_report_path"] = None
    before = analyze(baseline)
    after = analyze(d, contract_reports=[str(ROOT / "examples/access_risk_contract_report.json")])
    f = next(f for f in after["findings"] if f["rule_id"] == "cross_layer_exposure")
    base = next(
        x
        for x in before["findings"]
        if x["identity_id"] == "user-05" and x.get("asset_id") == "asset-vault"
    )
    boosted = next(x for x in after["findings"] if x["finding_id"] == base["finding_id"])
    assert (
        f["severity"] == "CRITICAL"
        and boosted["severity"] == base["severity"]
        and boosted["priority_score"] > base["priority_score"]
    )


def test_invalid_contract_report_degrades_gracefully():
    d = data()
    r = analyze(d, contract_reports=["/not/a/report.json"])
    assert r["correlation_notes"] and "No such file" in r["correlation_notes"][0]["reason"]


def test_deterministic_output():
    d = data()
    assert analyze(d) == analyze(d)


def test_stale_identity_boundary_45_days_is_not_flagged():
    d = data()
    user = next(x for x in d["identities"] if x["user_id"] == "user-02")
    user["last_active_at"] = "2026-09-08T00:00:00Z"
    r = analyze(d)
    assert not any(
        f["rule_id"] == "stale_identity" and f["identity_id"] == "user-02" for f in r["findings"]
    )


def test_unused_permission_exact_threshold_is_included():
    d = data()
    grant = next(
        g for g in d["grants"] if g["user_id"] == "user-02" and g["permission_id"] == "p-prod"
    )
    grant["granted_at"] = "2026-08-24T00:00:00Z"
    r = analyze(d)
    assert any(
        f["rule_id"] == "unused_permission"
        and f["identity_id"] == "user-02"
        and not f["insufficient_evidence"]
        for f in r["findings"]
    )


def test_excessive_scope_non_sensitive_broad_permission_is_medium():
    d = data()
    permission = next(p for p in d["permissions"] if p["permission_id"] == "p-wild")
    permission["sensitive"] = False
    r = analyze(d)
    f = next(
        f
        for f in r["findings"]
        if f["rule_id"] == "excessive_scope" and f["identity_id"] == "user-04"
    )
    assert f["severity"] == "MEDIUM"


def test_peer_group_exactly_at_minimum_is_compared():
    d = data()
    for identity in d["identities"]:
        if identity["user_id"] in {"user-05", "user-06", "user-07", "user-08"}:
            identity["team"] = "other"
    r = analyze(d)
    assert ("peer_drift", "user-03", "p-rare") not in tuples(r)
