"""Run the Lambda handler locally with in-memory S3/SNS stubs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

try:
    from .lambda_handler import handler
except ImportError:  # direct `python aws/local_invoke.py` invocation
    from lambda_handler import handler


class Body:
    def __init__(self, data):
        self.data = data

    def read(self):
        return self.data


class S3Stub:
    def __init__(self, key, data):
        self.key = key
        self.data = data
        self.objects = {}

    def get_object(self, **kwargs):
        return {"Body": Body(self.data)}

    def put_object(self, **kw):
        self.objects[(kw["Bucket"], kw["Key"])] = kw


class SNSStub:
    def __init__(self):
        self.messages = []

    def publish(self, **kw):
        self.messages.append(kw)


def invoke(path):
    import os

    os.environ.setdefault("REPORTS_BUCKET", "local-reports")
    os.environ.setdefault("ALERTS_TOPIC", "local-alerts")
    p = Path(path)
    s3 = S3Stub(p.name, p.read_bytes())
    sns = SNSStub()
    event = {"Records": [{"s3": {"bucket": {"name": "local-input"}, "object": {"key": p.name}}}]}
    result = handler(event, None, {"s3": s3, "sns": sns})
    return result, s3.objects, sns.messages


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    result, objects, messages = invoke(args.input)
    print(
        json.dumps(
            {
                "result": result,
                "written_reports": sorted(k for _, k in objects),
                "sns_messages": len(messages),
            },
            indent=2,
        )
    )
