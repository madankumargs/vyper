# Vyper Guard Access Risk status

## Current checkpoint

Phase 1 reconnaissance is complete. The working tree was clean before this task. There is no existing `guardian.access_risk` package and no existing `examples/` directory. The CLI is Typer based (`src/guardian/cli.py`), existing report schemas are in `guardian.reporting`, and the detector registry is implemented in `guardian.analyzer.vyper_detector`.

Baseline command: `.venv/bin/pytest tests/ -q --tb=short`

Baseline result: **475 passed**, 60 deprecation warnings, 34.88 seconds, Python 3.12.14. This run used the environment's existing compatible Typer 0.24.1 install.

The verified access-control detector IDs currently include `unprotected_state_change`, `tx_origin_auth`, `unprotected_selfdestruct`, and `dangerous_delegatecall`. They were read from `vyper-guard detectors`; contract-report schema verification remains pending.

## Plan

1. Add typed input models, strict JSON loader, deterministic synthetic datasets, and unit validation.
2. Add R1-R5 rules and their synthetic rule tests.
3. Add scoring, dry-run remediation plan, and analysis engine.
4. Add CLI command and deterministic JSON, Markdown, HTML, and CLI reports.
5. Verify contract JSON schema and add cross-layer correlation with a real analyzer-generated fixture.
6. Add demo/holdout evaluation, template explanations, AWS handler/artifacts/local stub path, docs, and final regression run.

## Results

Implementation results and verified commands will be appended as phases complete. AWS deployment is not authorized or possible in this environment and will not be represented as performed.

### Phase 2 — models, loader, demo inputs

Added typed `TypedDict` schema declarations and a strict JSON loader with timezone and referential-integrity checks. Added 24-identity fake demo and separate truth file, plus a differently named/dated synthetic holdout and truth file. Added an example Vyper contract and analyzer-generated JSON report. The real report includes verified `unprotected_state_change` (HIGH) and `unprotected_selfdestruct` (CRITICAL) detector IDs; this confirms the report uses top-level `findings[]` with `detector` and `severity` fields.

Validation: `.venv/bin/pytest tests/test_access_risk -q --tb=short` — **18 passed**. `vyper-guard analyze examples/access_risk_vulnerable_vault.vy --format json --output examples/access_risk_contract_report.json` — succeeded. No external services were called by tests.

### Phase 3 — R1–R5 rule engine

Implemented deterministic R1–R5 checks with stable SHA-256-derived finding IDs, evidence records, severity/confidence, recommendations, tier metadata, and INFO-level evidence-gap notes. Peer groups below the minimum and users without a sufficient activity baseline produce explicit insufficiency notes. The rare-permission comparison remains heuristic and should be reviewed before making policy decisions.

Validation: 18 focused tests pass, including positives, negatives/boundaries, log-coverage guard, peer-size guard, unusual activity, and the demo fixture. Cross-layer handling is present as a first implementation and will be further validated in its dedicated checkpoint.

### Phase 4 — scoring and dry-run plan

Added per-identity severity-band caps, the specified org formula and risk-grade bands, plus a dry-run executor that emits review actions and never has an execution method. T1 remains a policy marker only. Focused scoring/remediation tests: **3 passed**; combined engine/scoring tests: **13 passed**.

### Phase 5 — CLI and report formats

Added the `access-risk` Typer command with JSON, Markdown, HTML, and CLI renderers; fixed `--as-of`, policy overrides, repeated contract reports, severity exit thresholds, and optional dry-run plan export. Reports include run metadata, risk grade/formula inputs, identity scores, findings with evidence, plan, correlation wording, limitations, disclaimer, and a basic projected view. Added a lazy Bedrock adapter with deterministic-template fallback and the optional `aws` extra.

Validation: demo CLI JSON/Markdown/HTML generation succeeded; repeat-run JSON is byte-identical; HTML has inline CSS, disclaimer and projected section, and no external URLs. Focused access-risk tests: **25 passed**; Ruff check over new package/tests and CLI: passed.

### Phase 7 — synthetic evaluation

Added a separate holdout with 28 fake identities and more sparse-history rows, plus a script that reports overall/per-rule precision, recall, F1 and enumerates every FP/FN. No thresholds were changed for holdout. Results in `ACCESS_RISK_EVALUATION.md`: demo 15 TP / 0 FP / 0 FN; holdout 15 / 0 / 0; both show INFO evidence gaps (6 and 10 respectively). These are same-team synthetic fixtures and are not predictive of production accuracy.

### Phase 9 — AWS artifacts (deployment not performed)

Added a SAM template with private encrypted/versioned input and report buckets, optional create-time Object Lock, S3 JSON trigger, Lambda, least-privilege object/topic permissions, SNS aggregate alerts, log retention, optional Bedrock IAM, and parameters. Added the handler, a local in-memory S3/SNS invocation tool, and deployment/teardown guide. SNS contains only aggregate counts and score, not identities or evidence.

Validation: `python aws/local_invoke.py examples/access_risk_demo.json` wrote three stubbed report objects and emitted one aggregate alert; `tests/test_access_risk/test_lambda.py` — **2 passed**; `cfn-lint aws/template.yaml` (cfn-lint 1.58.0) — passed. AWS deployment, IAM behavior in an account, Bedrock access, and cloud costs were not tested.

### Phase 8 — explanations

Template explanations are the offline default. Bedrock Converse support is implemented as an optional lazy adapter with bounded output, timeout/retry configuration, a constrained schema, and deterministic fallback. Stubbed success, invalid-schema, unknown-evidence-reference, exception, and deterministic-template tests pass; no Bedrock call was made.

### Phase 10 — documentation and final verification

Added architecture/rules/scoring/remediation/limitations documentation, demo script, judging map, references inventory, README commands, and this status. CSV-directory ingestion and the optional Step Functions design artifact were cut. External citations were omitted because no external standard or paper was independently opened and checked. Ruff lint, cfn-lint, and local AWS stubs passed. Full suite: **508 passed**, 60 Typer/Click deprecation warnings, Python 3.12.14; baseline was 475 passed. The final full run was performed after the loader and correlation-priority fixes. Ruff format check still reports one pre-existing formatting difference at `src/guardian/analyzer/vyper_detector.py:2192`; the new command itself was formatted. AWS deployment was not performed.

## Remaining scope and risks

- Live AWS deployment remains unperformed. The Step Functions ASL is a design artifact and has not been validated or deployed; its callback Lambda ARN is intentionally a placeholder.
- Bedrock behavior was tested only against stubs; account credentials/model/guardrail configuration were not exercised.
- Synthetic evaluation labels were authored alongside the rules and cannot estimate production precision or recall.
- Review these assumptions before a demo: (1) snapshot providers identify grants, permissions, and event types consistently; (2) declared log coverage really spans the stated time and event types; (3) team/role groups and contract-to-deployer asset links are accurate and current.

### Follow-up — remaining locally addressable scope

Added CSV-directory input: `metadata.json` provides `as_of` and optional `policy`; each entity can be supplied as a same-named CSV, with JSON-encoded arrays and strict boolean parsing. CSV and JSON inputs use the same validation path. Added `aws/state_machine.asl.json` as an explicitly undeployed callback-approval design ending in a no-op decision record; it contains no revocation step. Updated the input and AWS design documentation.

Validation after this follow-up: `.venv/bin/pytest tests/test_access_risk/test_loader.py tests/test_access_risk/test_reports_cli.py -q --tb=short` — **10 passed**; `.venv/bin/pytest tests/ -q --tb=short` — **510 passed**, 60 warnings (baseline 475 passed); Ruff check and `git diff --check` passed; JSON syntax validation passed for the ASL artifact. A demo snapshot exported to CSV and run through `vyper-guard access-risk <directory> --format json --as-of 2026-10-23T00:00:00Z` produced 21 findings, matching the JSON input's result. Evaluation remains 15 TP / 0 FP / 0 FN on both synthetic sets, with the caveats recorded above.
