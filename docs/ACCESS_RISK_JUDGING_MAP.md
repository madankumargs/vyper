# Hackathon judging map

The official rubric was not supplied; this is a best-guess mapping, not a claim about judging criteria.

| Likely criterion | Deliverable evidence |
|---|---|
| Impact | Identifies stale, unused, broad, and anomalous SaaS access with evidence and owner actions. |
| Technical execution | Typed schema, referential validation, six deterministic rules, scoring, CLI, four report formats, tests, and Lambda flow. |
| Innovation | Cross-layer prioritization ties deployment capability to a verified Vyper Guard access-control detector. |
| AWS usage | SAM input/report buckets, S3 event Lambda, scoped role, SNS aggregate alert, log retention, and local stub test; deployment not performed. |
| Explainability | Each finding exposes evidence, confidence, recommendation, priority reason, limitations, and dry-run status. |
| Responsible AI | Template is default; Bedrock is optional and advisory, schema-checked, and falls back locally. Rules alone decide findings and severity. |
| Security | Private encrypted/versioned buckets, narrow object permissions, no PII in SNS messages, no execution path, no secrets in fixtures. AWS policy was linted, not deployed. |
| Demo | Reproducible CLI commands, self-contained HTML, synthetic truth, verified contract report, and local AWS stubs. |
| Scalability | Provider-neutral snapshot input can accept future connectors; current ingestion is a single JSON file and no production scale claim is made. |
