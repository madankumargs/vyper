import json

from guardian.access_risk.explainer import BedrockExplainer, TemplateExplainer

finding = {
    "finding_id": "f1",
    "rule_id": "unused_permission",
    "severity": "HIGH",
    "identity_id": "u1",
    "permission_id": "p1",
    "title": "No use observed",
    "recommendation": "Review the grant",
    "evidence": [{"evidence_id": "abc123", "type": "unused_window", "days": 60}],
}


class Stub:
    def __init__(self, text=None, error=None):
        self.text = text
        self.error = error
        self.calls = 0

    def converse(self, **kwargs):
        self.calls += 1
        if self.error:
            raise self.error
        return {"output": {"message": {"content": [{"text": self.text}]}}}


def response(**kw):
    return json.dumps(
        {
            "summary": "Evidence says unused",
            "business_impact": "Review",
            "recommended_action": "Ask owner",
            "manager_message": "Please review.",
        }
    )


def test_template_is_deterministic():
    x = TemplateExplainer().explain(finding)
    assert x == TemplateExplainer().explain(finding)


def test_bedrock_stub_success():
    stub = Stub(response())
    e = BedrockExplainer(stub, "model")
    assert e.explain(finding)["summary"] == "Evidence says unused" and e._last_ok
    assert stub.calls == 1


def test_invalid_schema_and_exception_fall_back():
    e = BedrockExplainer(Stub('{"summary":"x"}'), "model")
    assert e.explain(finding) == TemplateExplainer().explain(finding) and not e._last_ok
    e = BedrockExplainer(Stub(error=RuntimeError("offline")), "model")
    assert e.explain(finding) == TemplateExplainer().explain(finding)


def test_unknown_evidence_id_falls_back():
    payload = json.loads(response())
    payload["manager_message"] = "See evidence_id=ev_missing"
    e = BedrockExplainer(Stub(json.dumps(payload)), "model")
    assert e.explain(finding) == TemplateExplainer().explain(finding)
