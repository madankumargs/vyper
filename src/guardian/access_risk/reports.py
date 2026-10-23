"""Deterministic access-risk renderers."""

from __future__ import annotations

import html
import json

from .engine import analyze
from .explainer import TemplateExplainer


def explain_report(report, mode="template", bedrock=None):
    explainer = bedrock if mode == "bedrock" and bedrock else TemplateExplainer()
    for finding in report["findings"]:
        finding["explanation"] = explainer.explain(finding)
        finding["explanation_source"] = (
            "bedrock"
            if mode == "bedrock" and bedrock and getattr(bedrock, "_last_ok", False)
            else "template"
        )
    return report


def projected_report(data, report):
    keys = {
        (x["identity_id"], x.get("permission_id"))
        for x in report["findings"]
        if x["remediation_tier"] == "T1" and x["auto_revocation_allowed"]
    }
    copy = dict(data)
    copy["grants"] = [
        g for g in data.get("grants", []) if (g["user_id"], g["permission_id"]) not in keys
    ]
    return analyze(copy)


def render_markdown(report):
    lines = [
        "# Vyper Guard Access Risk",
        f"**Access Risk Score (higher = more risk): {report['org_score']} / 100 — grade {report['org_grade']}**",
        f"As of: {report['as_of']} · Tool version: {report['tool_version']} · Input SHA-256: `{report['input_sha256']}`",
        "",
        report["disclaimer"],
        "",
        "## Per-identity scores",
    ]
    for uid, score in sorted(report["identity_scores"].items()):
        lines.append(f"- {uid}: {score['total']} / 100")
    lines += ["", "## Findings"]
    for f in report["findings"]:
        lines += [
            f"### {f['severity']} · {f['rule_id']} · {f['identity_id']} / {f.get('permission_id') or 'activity'}",
            f"{f['title']} (priority {f['priority_score']}; confidence {f['confidence']})",
            f"Recommendation: {f['recommendation']}",
        ]
        for e in f["evidence"]:
            lines.append(
                "- Evidence `"
                + e["type"]
                + "`: "
                + ", ".join(f"{k}={v}" for k, v in e.items() if k not in {"evidence_id", "type"})
            )
    lines += [
        "",
        "## Cross-layer correlation",
        report["cross_layer_note"],
    ]
    lines += [
        f"- Correlation note: {n['reason']} ({n['path']})"
        for n in report.get("correlation_notes", [])
    ]
    lines += [
        "",
        "## Remediation plan (dry-run only)",
    ]
    for p in report["remediation_plan"]:
        lines.append(
            f"- {p['action']} for {p['target']} ({p['tier']}; approver required: {p['approver_required']})"
        )
    lines += (
        ["", "## Limitations"]
        + [f"- {x}" for x in report["limitations"]]
        + ["", report["disclaimer"]]
    )
    return "\n".join(lines) + "\n"


def render_html(report, projected=None):
    cards = []
    for f in report["findings"]:
        ev = "".join(
            "<tr>"
            + "".join(f"<td>{html.escape(str(e.get(k, '')))}</td>" for k in ("type", "evidence_id"))
            + f"<td>{html.escape(json.dumps({k: v for k, v in e.items() if k not in {'type', 'evidence_id'}}, sort_keys=True))}</td></tr>"
            for e in f["evidence"]
        )
        cards.append(
            f"<article><h3>{html.escape(f['severity'])} · {html.escape(f['rule_id'])} · {html.escape(f['identity_id'])}</h3><p>{html.escape(f['title'])}</p><p>{html.escape(f['recommendation'])}</p><table><tr><th>Type</th><th>ID</th><th>Evidence</th></tr>{ev}</table></article>"
        )
    after = (
        ""
        if projected is None
        else f"<section><h2>Before / After (projected)</h2><p>Current findings: {len(report['findings'])}; projected findings after T1 plan: {len(projected['findings'])}. Projection is a simulation; no grant was changed.</p></section>"
    )

    def esc(x):
        return html.escape(str(x))

    return (
        "<!doctype html><html lang='en'><meta charset='utf-8'><title>Access Risk</title><style>body{font:16px system-ui;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#172033}article,section{border:1px solid #ccd;padding:1rem;margin:1rem 0}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccd;padding:.4rem;text-align:left}th{background:#eef}</style><body><h1>Vyper Guard Access Risk</h1><h2>Access Risk Score (higher = more risk): "
        + esc(report["org_score"])
        + " / 100 — grade "
        + esc(report["org_grade"])
        + "</h2><p>As of "
        + esc(report["as_of"])
        + " · Version "
        + esc(report["tool_version"])
        + " · Input SHA-256 "
        + esc(report["input_sha256"])
        + "</p><p>"
        + esc(report["disclaimer"])
        + "</p><section><h2>Per-identity scores</h2><ul>"
        + "".join(
            f"<li>{esc(uid)}: {esc(score['total'])}/100</li>"
            for uid, score in sorted(report["identity_scores"].items())
        )
        + "</ul></section><section><h2>Cross-layer correlation</h2><p>"
        + esc(report["cross_layer_note"])
        + "</p>"
        + "".join(
            f"<p>Correlation note: {esc(n['reason'])} ({esc(n['path'])})</p>"
            for n in report.get("correlation_notes", [])
        )
        + "</section><h2>Findings</h2>"
        + "".join(cards)
        + after
        + "<section><h2>Dry-run remediation plan</h2><pre>"
        + esc(json.dumps(report["remediation_plan"], indent=2, sort_keys=True))
        + "</pre></section><section><h2>Limitations</h2><ul>"
        + "".join(f"<li>{esc(x)}</li>" for x in report["limitations"])
        + "</ul><p>"
        + esc(report["disclaimer"])
        + "</p></section></body></html>\n"
    )


def render_cli(report):
    return (
        f"Access Risk Score (higher = more risk): {report['org_score']}/100 ({report['org_grade']})\n{len(report['findings'])} evidence-based findings; {sum(f['severity'] in {'HIGH', 'CRITICAL'} for f in report['findings'])} HIGH+\n"
        + "\n".join(
            f"{f['severity']:<8} {f['rule_id']:<24} {f['identity_id']} {f['title']}"
            for f in report["findings"]
        )
        + "\n\n"
        + report["disclaimer"]
        + "\n"
    )


def render_json(report):
    return json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
