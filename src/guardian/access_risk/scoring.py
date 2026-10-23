"""Risk scoring and approval-gated dry-run remediation."""

from __future__ import annotations

WEIGHTS = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5, "INFO": 1}
CAPS = {"CRITICAL": 50, "HIGH": 40, "MEDIUM": 20, "LOW": 10, "INFO": 5}


def score_findings(findings, identity_ids=()):
    scores = {identity: {s: 0 for s in WEIGHTS} for identity in identity_ids}
    for finding in findings:
        scores.setdefault(finding["identity_id"], {s: 0 for s in WEIGHTS})
        sev = finding["severity"]
        scores[finding["identity_id"]][sev] = min(
            CAPS[sev], scores[finding["identity_id"]][sev] + WEIGHTS[sev]
        )
    for bands in scores.values():
        bands["total"] = min(100, sum(bands.values()))
    vals = [x["total"] for x in scores.values()]
    org = min(100, round(0.6 * max(vals, default=0) + 0.4 * (sum(vals) / len(vals) if vals else 0)))
    grade = "A" if org < 20 else "B" if org < 40 else "C" if org < 60 else "D" if org < 80 else "F"
    return scores, org, grade


def remediation_plan(findings):
    actions = []
    for f in findings:
        tier = f["remediation_tier"]
        if tier == "T3":
            action = "review_evidence"
        elif tier == "T1" and f["auto_revocation_allowed"]:
            action = "revoke_grant (dry-run only)"
        else:
            action = "request_access_review"
        actions.append(
            {
                "action": action,
                "target": {
                    "identity_id": f["identity_id"],
                    "permission_id": f.get("permission_id"),
                    "asset_id": f.get("asset_id"),
                },
                "finding_id": f["finding_id"],
                "tier": tier,
                "approver_required": tier != "T1",
                "rollback_note": "No change was executed. Restore the grant through the source system if an approved change is reversed.",
            }
        )
    return sorted(actions, key=lambda x: (x["tier"], x["finding_id"]))


class RemediationExecutor:
    def create_plan(self, findings):
        raise NotImplementedError


class DryRunExecutor(RemediationExecutor):
    def create_plan(self, findings):
        return remediation_plan(findings)
