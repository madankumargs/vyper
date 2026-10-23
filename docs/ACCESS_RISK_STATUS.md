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
