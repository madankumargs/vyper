from guardian.access_risk.scoring import DryRunExecutor, score_findings


def f(sev, id):
    return {
        "severity": sev,
        "identity_id": id,
        "remediation_tier": "T2",
        "auto_revocation_allowed": False,
        "finding_id": id,
        "permission_id": "p",
        "asset_id": None,
    }


def test_band_caps_and_org_grade_formula():
    scores, org, grade = score_findings([f("HIGH", "a") for _ in range(5)] + [f("LOW", "b")])
    assert scores["a"]["HIGH"] == 40 and scores["b"]["total"] == 5 and org == 33 and grade == "B"


def test_total_cap_and_grade_bands():
    scores, org, grade = score_findings(
        [f(s, "a") for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] * 10]
    )
    assert scores["a"]["total"] == 100 and org == 100 and grade == "F"


def test_tiers_and_no_execute_surface():
    plan = DryRunExecutor().create_plan([f("HIGH", "x")])
    assert plan[0]["approver_required"]
    assert (
        not hasattr(DryRunExecutor(), "execute") and "dry-run only" in plan[0]["action"]
    ) or plan[0]["action"] == "request_access_review"


def test_every_risk_grade_band():
    cases = [
        (0, "A", []),
        (20, "B", [f("MEDIUM", "x") for _ in range(2)]),
        (40, "C", [f("HIGH", "x") for _ in range(2)]),
        (60, "D", [f("HIGH", "x") for _ in range(2)] + [f("MEDIUM", "x") for _ in range(2)]),
        (80, "F", [f("CRITICAL", "x") for _ in range(2)] + [f("HIGH", "x"), f("MEDIUM", "x")]),
    ]
    for value, grade, findings in cases:
        _, org, actual = score_findings(findings)
        assert (org, actual) == (value, grade)


def test_plan_tiers_remain_review_or_dry_run_actions():
    rows = []
    for tier, auto in [("T1", True), ("T2", False), ("T3", False)]:
        row = f("LOW", tier)
        row["remediation_tier"] = tier
        row["auto_revocation_allowed"] = auto
        rows.append(row)
    plan = DryRunExecutor().create_plan(rows)
    assert {x["tier"] for x in plan} == {"T1", "T2", "T3"}
    assert all("revoke" in x["action"] or "review" in x["action"] for x in plan)
