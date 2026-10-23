from pathlib import Path

from aws.lambda_handler import handler
from aws.local_invoke import S3Stub, SNSStub, invoke

ROOT = Path(__file__).parents[2]


def test_local_invoke_writes_three_outputs_and_aggregate_alert(monkeypatch):
    monkeypatch.setenv("REPORTS_BUCKET", "local-reports")
    monkeypatch.setenv("ALERTS_TOPIC", "local-topic")
    result, objects, messages = invoke(ROOT / "examples/access_risk_demo.json")
    assert result["processed"][0]["finding_count"] > 0
    assert {k.rsplit(".", 1)[-1] for _, k in objects} == {"json", "md", "html"}
    assert messages and "HIGH+ access findings" in messages[0]["Message"]
    assert "user-01" not in messages[0]["Message"]


def test_handler_rejects_invalid_snapshot_without_leaking_payload(monkeypatch):
    monkeypatch.setenv("REPORTS_BUCKET", "r")
    monkeypatch.setenv("ALERTS_TOPIC", "")
    s3 = S3Stub("bad.json", b"{")
    event = {"Records": [{"s3": {"bucket": {"name": "in"}, "object": {"key": "bad.json"}}}]}
    try:
        handler(event, None, {"s3": s3, "sns": SNSStub()})
    except ValueError as exc:
        assert "cannot read input" in str(exc)
    else:
        raise AssertionError("invalid JSON should fail clearly")
