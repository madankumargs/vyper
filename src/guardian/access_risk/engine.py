"""Deterministic rules for provider-neutral access snapshots."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .scoring import remediation_plan, score_findings

DEFAULTS = {
    "stale_days": 45,
    "unused_days": 60,
    "min_group_size": 4,
    "peer_rarity_ratio": 0.2,
    "recent_days": 14,
    "baseline_days": 60,
    "min_baseline_events": 10,
    "broad_tokens": ["*", "admin", "owner", "delete-all", "write-all", "domain-wide"],
    "access_control_detectors": [
        "unprotected_state_change",
        "tx_origin_auth",
        "unprotected_selfdestruct",
        "dangerous_delegatecall",
    ],
    "cross_layer_multiplier": 1.5,
}
WEIGHTS = {"INFO": 1, "LOW": 5, "MEDIUM": 10, "HIGH": 20, "CRITICAL": 30}
DISCLAIMER = "This score reflects detected access risk from the supplied evidence only. It does not certify that an organization is secure."
CROSS_WORDING = "The linked contract has an access-control finding, which raises the priority of this user's access. It does not establish that the contract is exploitable."


def _dt(v):
    return datetime.fromisoformat(v.replace("Z", "+00:00"))


def _id(rule, user, permission):
    return hashlib.sha256(f"{rule}\0{user}\0{permission or ''}".encode()).hexdigest()[:16]


def _finding(
    rule,
    user,
    permission,
    severity,
    title,
    evidence,
    recommendation,
    confidence=0.9,
    tier="T2",
    asset=None,
    insufficient=False,
):
    return {
        "finding_id": _id(rule, user, permission),
        "rule_id": rule,
        "severity": severity,
        "confidence": round(float(confidence), 2),
        "identity_id": user,
        "permission_id": permission,
        "asset_id": asset,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
        "remediation_tier": tier,
        "auto_revocation_allowed": tier == "T1",
        "priority_score": WEIGHTS[severity],
        "priority_reasons": [],
        "insufficient_evidence": insufficient,
        "explanation_source": None,
    }


def analyze(
    data: dict[str, Any], as_of: str | None = None, contract_reports: list[str] | None = None
) -> dict[str, Any]:
    data = dict(data)
    policy = {**DEFAULTS, **data.get("policy", {})}
    now = _dt(as_of or data["as_of"])
    identities = {x["user_id"]: x for x in data.get("identities", [])}
    permissions = {x["permission_id"]: x for x in data.get("permissions", [])}
    grants = data.get("grants", [])
    events = data.get("events", [])
    findings = []

    def ev(t, **kw):
        return {
            "evidence_id": hashlib.sha256(json.dumps([t, kw], sort_keys=True).encode()).hexdigest()[
                :12
            ],
            "type": t,
            **kw,
        }

    active = [g for g in grants if not g.get("expires_at") or _dt(g["expires_at"]) > now]
    for g in active:
        u = identities[g["user_id"]]
        p = permissions[g["permission_id"]]
        days = (now - _dt(g["granted_at"])).days
        if u["status"] in {"disabled", "terminated"}:
            sev = "CRITICAL" if p["sensitive"] or p["capability"] in {"deploy", "admin"} else "HIGH"
            findings.append(
                _finding(
                    "stale_identity",
                    u["user_id"],
                    p["permission_id"],
                    sev,
                    "Disabled or terminated identity retains active access",
                    [
                        ev("identity_status", status=u["status"]),
                        ev("active_grant", granted_at=g["granted_at"], permission=p["name"]),
                    ],
                    "Confirm ownership, then remove or formally transfer the grant.",
                    tier="T1"
                    if u["status"] == "terminated"
                    and not p["sensitive"]
                    and p["capability"] not in {"deploy", "admin"}
                    else "T2",
                    asset=p.get("controls_asset_id"),
                )
            )
        elif (
            u["status"] in {"active", "inactive"}
            and u.get("last_active_at")
            and (now - _dt(u["last_active_at"])).days > policy["stale_days"]
        ):
            sev = "HIGH" if p["sensitive"] else "MEDIUM"
            findings.append(
                _finding(
                    "stale_identity",
                    u["user_id"],
                    p["permission_id"],
                    sev,
                    "Identity activity is older than the configured review window",
                    [
                        ev(
                            "last_activity",
                            last_active_at=u["last_active_at"],
                            stale_days=(now - _dt(u["last_active_at"])).days,
                        ),
                        ev("active_grant", granted_at=g["granted_at"]),
                    ],
                    "Ask the manager or application owner to confirm continuing need.",
                    tier="T2",
                    asset=p.get("controls_asset_id"),
                )
            )
        if days >= policy["unused_days"]:
            coverage = next(
                (
                    c
                    for c in data.get("log_coverage", [])
                    if c["application"] == p["application"] and p["event_type"] in c["event_types"]
                ),
                None,
            )
            covered = bool(
                coverage
                and _dt(coverage["window_start"]) <= now - timedelta(days=policy["unused_days"])
                and _dt(coverage["window_end"]) >= now
            )
            used = any(
                e.get("user_id") == u["user_id"]
                and (
                    e.get("permission_id") == p["permission_id"]
                    or (
                        e.get("application") == p["application"]
                        and e.get("action") == p["event_type"]
                    )
                )
                and e.get("success", True)
                for e in events
            )
            if used:
                continue
            if not covered:
                reason = (
                    "no matching coverage declaration"
                    if not coverage
                    else "coverage does not include the event type or full lookback window"
                )
                findings.append(
                    _finding(
                        "unused_permission",
                        u["user_id"],
                        p["permission_id"],
                        "INFO",
                        "Insufficient evidence to determine whether access is unused",
                        [
                            ev(
                                "coverage_gap",
                                application=p["application"],
                                event_type=p["event_type"],
                                reason=reason,
                            )
                        ],
                        "Improve or verify log coverage before deciding whether to remove this access.",
                        confidence=0.4,
                        tier="T3",
                        asset=p.get("controls_asset_id"),
                        insufficient=True,
                    )
                )
            else:
                findings.append(
                    _finding(
                        "unused_permission",
                        u["user_id"],
                        p["permission_id"],
                        p["risk_level"].upper(),
                        "No use observed during the covered review window",
                        [
                            ev(
                                "unused_window",
                                granted_at=g["granted_at"],
                                lookback_days=policy["unused_days"],
                                application=p["application"],
                                event_type=p["event_type"],
                            )
                        ],
                        "Confirm with the owner before removing this grant.",
                        tier="T2",
                        asset=p.get("controls_asset_id"),
                    )
                )
    tokens = [str(x).lower() for x in policy["broad_tokens"]]
    for g in active:
        p = permissions[g["permission_id"]]
        u = identities[g["user_id"]]
        text = " ".join(str(p.get(k, "")) for k in ("name", "action", "resource")).lower()
        broad = any(
            (tok == "*" and "*" in text)
            or (tok != "*" and re.search(r"(?<![a-z0-9])" + re.escape(tok) + r"(?![a-z0-9])", text))
            for tok in tokens
        )
        if not broad and not p["external_sharing"]:
            continue
        sev = (
            "CRITICAL"
            if broad and p["sensitive"] and p["external_sharing"]
            else "HIGH"
            if broad and p["sensitive"]
            else "MEDIUM"
            if broad
            else "LOW"
        )
        findings.append(
            _finding(
                "excessive_scope",
                u["user_id"],
                p["permission_id"],
                sev,
                "Broad or externally shared permission scope",
                [
                    ev(
                        "scope",
                        name=p["name"],
                        action=p["action"],
                        resource=p["resource"],
                        broad_match=broad,
                        external_sharing=p["external_sharing"],
                    )
                ],
                "Narrow the resource or sharing scope after confirming application-owner requirements.",
                tier="T2",
                asset=p.get("controls_asset_id"),
            )
        )
    held = {uid: {g["permission_id"] for g in active if g["user_id"] == uid} for uid in identities}
    groups = {}
    for uid, u in identities.items():
        groups.setdefault((u.get("team"), u.get("role")), []).append(uid)
    for group, members in groups.items():
        if len(members) < policy["min_group_size"]:
            for uid in members:
                findings.append(
                    _finding(
                        "peer_drift",
                        uid,
                        None,
                        "INFO",
                        "Insufficient peer-group size for comparison",
                        [
                            ev(
                                "peer_group_gap",
                                team=group[0],
                                role=group[1],
                                group_size=len(members),
                                required=policy["min_group_size"],
                            )
                        ],
                        "Collect a larger comparable peer group before evaluating permission differences.",
                        confidence=0.3,
                        tier="T3",
                        insufficient=True,
                    )
                )
            continue
        group_perms = {
            pid: sum(pid in held[u] for u in members)
            for pid in set().union(*(held[u] for u in members))
        }
        level_counts = {}
        for pid, count in group_perms.items():
            level = permissions[pid]["risk_level"].upper()
            level_counts[level] = level_counts.get(level, 0) + count
        common_level = (
            max(level_counts, key=lambda level: (level_counts[level], -WEIGHTS[level]))
            if level_counts
            else "LOW"
        )
        for uid in members:
            for pid in held[uid]:
                p = permissions[pid]
                peers = group_perms[pid]
                ratio = peers / len(members)
                if ratio > policy["peer_rarity_ratio"] or not (
                    p["sensitive"] or WEIGHTS[p["risk_level"].upper()] > WEIGHTS[common_level]
                ):
                    continue
                sev = (
                    "HIGH" if p["sensitive"] or p["capability"] in {"deploy", "admin"} else "MEDIUM"
                )
                findings.append(
                    _finding(
                        "peer_drift",
                        uid,
                        pid,
                        sev,
                        "Permission is an exception needing confirmation",
                        [
                            ev(
                                "peer_comparison",
                                team=group[0],
                                role=group[1],
                                group_size=len(members),
                                holders=peers,
                                ratio=round(ratio, 3),
                            )
                        ],
                        "Confirm this exception with the manager or app owner; peer difference alone is not evidence of misconduct.",
                        confidence=min(0.95, 0.55 + len(members) * 0.04),
                        tier="T2",
                        asset=p.get("controls_asset_id"),
                    )
                )
    for uid, u in identities.items():
        baseline = [
            e
            for e in events
            if e["user_id"] == uid
            and now - timedelta(days=policy["baseline_days"])
            <= _dt(e["timestamp"])
            < now - timedelta(days=policy["recent_days"])
        ]
        recent = [
            e
            for e in events
            if e["user_id"] == uid
            and now - timedelta(days=policy["recent_days"]) <= _dt(e["timestamp"]) <= now
        ]
        if len(baseline) < policy["min_baseline_events"]:
            findings.append(
                _finding(
                    "unusual_activity",
                    uid,
                    None,
                    "INFO",
                    "Insufficient evidence for an activity baseline",
                    [
                        ev(
                            "baseline_gap",
                            baseline_events=len(baseline),
                            required=policy["min_baseline_events"],
                        )
                    ],
                    "Collect more covered activity before assessing unusual behavior.",
                    confidence=0.35,
                    tier="T3",
                    insufficient=True,
                )
            )
            continue
        countries = {e["country"] for e in baseline}
        apps = {e["application"] for e in baseline}
        resources = {(e["application"], e["resource"]) for e in baseline}
        first_priv = {}
        for e in recent:
            pid = e.get("permission_id")
            p = permissions.get(pid)
            signals = []
            if e["country"] not in countries and e["country"] not in u.get("usual_countries", []):
                signals.append("new_country")
            if e["application"] not in apps and e["application"] not in u.get(
                "usual_applications", []
            ):
                signals.append("new_application")
            if (e["application"], e["resource"]) not in resources:
                signals.append("new_resource")
            if (
                p
                and p["capability"] in {"deploy", "admin"}
                and not any(x.get("permission_id") == pid for x in baseline)
            ):
                signals.append("first_privileged_use")
            if signals:
                first_priv.setdefault(_dt(e["timestamp"]).date().isoformat(), []).append(
                    (e, signals)
                )
        for day, rows in first_priv.items():
            signals = sorted({signal for _, signal_list in rows for signal in signal_list})
            severity = (
                "HIGH"
                if "new_country" in signals and "first_privileged_use" in signals
                else "MEDIUM"
            )
            findings.append(
                _finding(
                    "unusual_activity",
                    uid,
                    None,
                    severity,
                    "Recent activity differs from this user's observed baseline",
                    [
                        ev(
                            "activity_cluster",
                            date=day,
                            event_count=len(rows),
                            signals=signals,
                            countries=sorted({e["country"] for e, _ in rows}),
                            applications=sorted({e["application"] for e, _ in rows}),
                            resources=sorted({e["resource"] for e, _ in rows}),
                        )
                    ],
                    "Verify the activity with the user and application owner; do not infer intent from anomaly signals.",
                    tier="T2",
                )
            )
    # Correlation is deliberately best-effort; a broken report never suppresses SaaS findings.
    reports = list(contract_reports or [])
    correlation_notes = []
    boosted_assets = set()
    for asset in data.get("assets", []):
        path = asset.get("vyper_report_path")
        if path:
            reports.append(path)
    for report_path in sorted(set(reports)):
        try:
            report = json.loads(Path(report_path).read_text(encoding="utf-8"))
            rows = report["findings"]
            if not isinstance(rows, list):
                raise ValueError("findings is not a list")
        except Exception as exc:
            correlation_notes.append(
                {"type": "report_issue", "path": str(report_path), "reason": str(exc)[:300]}
            )
            continue
        contract_hits = [
            r
            for r in rows
            if r.get("detector") in policy["access_control_detectors"]
            and WEIGHTS.get(str(r.get("severity", "INFO")).upper(), 0) >= WEIGHTS["MEDIUM"]
        ]
        for p in data.get("permissions", []):
            aid = p.get("controls_asset_id")
            if not aid or p["capability"] not in {"deploy", "admin"}:
                continue
            asset = next((a for a in data["assets"] if a["asset_id"] == aid), None)
            if not asset:
                continue
            for g in active:
                if g["permission_id"] != p["permission_id"]:
                    continue
                prior = [
                    f
                    for f in findings
                    if f["identity_id"] == g["user_id"] and f["rule_id"] != "cross_layer_exposure"
                ]
                high_contract = any(
                    str(hit.get("severity", "INFO")).upper() in {"HIGH", "CRITICAL"}
                    for hit in contract_hits
                )
                sev = "CRITICAL" if high_contract and prior else "HIGH"
                evidence = [
                    ev(
                        "contract_finding",
                        detector=h.get("detector"),
                        severity=h.get("severity"),
                        asset_id=aid,
                    )
                    for h in contract_hits
                ]
                evidence.append(ev("correlation_note", text=CROSS_WORDING))
                findings.append(
                    _finding(
                        "cross_layer_exposure",
                        g["user_id"],
                        p["permission_id"],
                        sev,
                        "Privileged SaaS access is linked to a flagged contract",
                        evidence,
                        "Review this user's access and the contract finding with the contract owner.",
                        tier="T3",
                        asset=aid,
                    )
                )
                boost_key = (g["user_id"], aid)
                if boost_key not in boosted_assets:
                    for f in findings:
                        if f["identity_id"] == g["user_id"] and f.get("asset_id") == aid:
                            f["priority_score"] = min(
                                100,
                                round(
                                    f["priority_score"] * float(policy["cross_layer_multiplier"])
                                ),
                            )
                            if CROSS_WORDING not in f["priority_reasons"]:
                                f["priority_reasons"].append(CROSS_WORDING)
                    boosted_assets.add(boost_key)
    findings.sort(key=lambda f: (-f["priority_score"], -WEIGHTS[f["severity"]], f["finding_id"]))
    scores, org, grade = score_findings(findings, identities)
    report_inputs = []
    for report_path in sorted(set(reports)):
        try:
            report_hash = hashlib.sha256(Path(report_path).read_bytes()).hexdigest()
        except OSError:
            report_hash = None
        report_inputs.append({"path": str(report_path), "sha256": report_hash})
    input_material = {"snapshot": data, "contract_reports": report_inputs}
    input_hash = hashlib.sha256(
        json.dumps(
            input_material, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    ).hexdigest()
    return {
        "schema_version": "vyper-guard-access-risk/v1",
        "as_of": now.isoformat().replace("+00:00", "Z"),
        "input_sha256": input_hash,
        "tool_version": "0.7.0",
        "score_label": "Access Risk Score (higher = more risk)",
        "org_score": org,
        "org_grade": grade,
        "identity_scores": scores,
        "findings": findings,
        "remediation_plan": remediation_plan(findings),
        "cross_layer_note": CROSS_WORDING,
        "correlation_notes": correlation_notes,
        "limitations": [
            "Analysis depends on completeness and accuracy of supplied identities, grants, events, and log coverage.",
            "Rules indicate review priorities; they do not establish intent, misconduct, or exploitability.",
        ],
        "disclaimer": DISCLAIMER,
    }
