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
