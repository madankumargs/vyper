"""Evidence-bound explanations. Bedrock support is intentionally optional."""

from __future__ import annotations

import json
import os
from typing import Any, ClassVar


class Explainer:
    def explain(self, finding: dict[str, Any]) -> dict[str, str]:
        raise NotImplementedError


class TemplateExplainer(Explainer):
    def explain(self, finding):
        evidence = finding.get("evidence", [])
        facts = "; ".join(
            f"{e['type']}: "
            + ", ".join(
                f"{k}={v}" for k, v in sorted(e.items()) if k not in {"evidence_id", "type"}
            )
            for e in evidence
        )
        return {
            "summary": finding["title"],
            "business_impact": f"This {finding['severity'].lower()} access review signal is based on: {facts or 'the supplied access records'}.",
            "recommended_action": finding["recommendation"],
            "manager_message": f"Please review {finding['identity_id']}'s access to {finding.get('permission_id') or 'the relevant application'} using the attached evidence.",
        }


class BedrockExplainer(Explainer):
    """Advisory only; failures always fall back to the deterministic template."""

    fields: ClassVar[set[str]] = {
        "summary",
        "business_impact",
        "recommended_action",
        "manager_message",
    }

    def __init__(self, client=None, model_id=None, guardrail_id=None, fallback=None):
        self.client = client
        self.model_id = model_id or os.getenv("GUARDIAN_BEDROCK_MODEL_ID")
        self.guardrail_id = guardrail_id or os.getenv("GUARDIAN_BEDROCK_GUARDRAIL_ID")
        self.fallback = fallback or TemplateExplainer()

    def explain(self, finding):
        self._last_ok = False
        try:
            if self.client is None:
                import boto3

                self.client = boto3.client(
                    "bedrock-runtime",
                    config=__import__("botocore.config", fromlist=["Config"]).Config(
                        read_timeout=20, connect_timeout=5, retries={"max_attempts": 2}
                    ),
                )
            if not self.model_id:
                raise ValueError("missing Bedrock model id")
            payload = {
                k: finding.get(k)
                for k in ("finding_id", "rule_id", "severity", "evidence", "recommendation")
            }
            args = {
                "modelId": self.model_id,
                "system": [
                    {
                        "text": "Use only supplied structured evidence. Return JSON only with summary, business_impact, recommended_action, manager_message. Never propose severity changes."
                    }
                ],
                "messages": [
                    {"role": "user", "content": [{"text": json.dumps(payload, sort_keys=True)}]}
                ],
                "inferenceConfig": {"maxTokens": 350, "temperature": 0},
            }
            if self.guardrail_id:
                args["guardrailConfig"] = {
                    "guardrailIdentifier": self.guardrail_id,
                    "guardrailVersion": "DRAFT",
                }
            response = self.client.converse(**args)
            txt = response["output"]["message"]["content"][0]["text"]
            result = json.loads(txt)
            if set(result) != self.fields or not all(
                isinstance(result[x], str) for x in self.fields
            ):
                raise ValueError("invalid explanation schema")
            allowed = {e["evidence_id"] for e in finding.get("evidence", [])}
            if any(
                token.startswith("ev_") and token not in allowed
                for token in __import__("re").findall(r"ev_[A-Za-z0-9_-]+", json.dumps(result))
            ):
                raise ValueError("unknown evidence reference")
            self._last_ok = True
            return result
        except Exception:
            return self.fallback.explain(finding)
