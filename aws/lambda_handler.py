"""S3-triggered report generator. It never changes grants or logs raw evidence."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import PurePosixPath
from urllib.parse import unquote_plus

from guardian.access_risk.engine import analyze
from guardian.access_risk.explainer import BedrockExplainer
from guardian.access_risk.loader import load_input
from guardian.access_risk.reports import (
    explain_report,
    projected_report,
    render_html,
    render_json,
    render_markdown,
)

LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)


def handler(event, context=None, clients=None):
    if clients is None:
        import boto3

        clients = {"s3": boto3.client("s3"), "sns": boto3.client("sns")}
    s3 = clients["s3"]
    sns = clients["sns"]
    bucket = os.environ.get("REPORTS_BUCKET", "")
    topic = os.environ.get("ALERTS_TOPIC", "")
    results = []
    for record in event.get("Records", []):
        try:
            src = record["s3"]["bucket"]["name"]
            key = unquote_plus(record["s3"]["object"]["key"])
            if not key.lower().endswith(".json"):
                continue
            response = s3.get_object(Bucket=src, Key=key)
            raw = response["Body"].read()
            with tempfile.NamedTemporaryFile(suffix=".json") as f:
                f.write(raw)
                f.flush()
                data = load_input(f.name)
            report = analyze(data)
            prefix = str(PurePosixPath(key).with_suffix(""))
            mode = (
                "bedrock"
                if os.environ.get("ENABLE_BEDROCK", "false").lower() == "true"
                else "template"
            )
            explain_report(report, mode, BedrockExplainer() if mode == "bedrock" else None)
            outputs = {
                "json": render_json(report),
                "md": render_markdown(report),
                "html": render_html(report, projected_report(data, report)),
            }
            for ext, body in outputs.items():
                s3.put_object(
                    Bucket=bucket,
                    Key=f"{prefix}/access-risk.{ext}",
                    Body=body.encode(),
                    ContentType="text/html"
                    if ext == "html"
                    else "application/json"
                    if ext == "json"
                    else "text/markdown",
                    ServerSideEncryption="AES256",
                )
            high = [f for f in report["findings"] if f["severity"] in {"HIGH", "CRITICAL"}]
            if high and topic:
                counts = {
                    level: sum(f["severity"] == level for f in high)
                    for level in ("HIGH", "CRITICAL")
                }
                sns.publish(
                    TopicArn=topic,
                    Subject="Vyper Guard Access Risk alert",
                    Message=json.dumps(
                        {
                            "summary": "HIGH+ access findings need review",
                            "as_of": report["as_of"],
                            "org_score": report["org_score"],
                            "counts": counts,
                        }
                    ),
                )
            results.append(
                {
                    "input_key": key,
                    "finding_count": len(report["findings"]),
                    "report_prefix": prefix,
                }
            )
        except Exception as exc:
            # Exception text is constrained to loader/control errors; no evidence payload is logged.
            LOG.error("access-risk processing failed (%s): %s", type(exc).__name__, str(exc)[:300])
            raise
    return {"processed": results}
