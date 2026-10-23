# Access Risk references

This implementation did not rely on external standards, research papers, or vendor documentation. No external citation is asserted here.

Repository sources inspected directly during implementation:

- `README.md` and `pyproject.toml` for project workflow, Python support, dependencies, and CLI entry point.
- `src/guardian/cli.py` for the Typer CLI and existing output conventions.
- `src/guardian/analyzer/vyper_detector.py` and the output of `vyper-guard detectors` for actual detector IDs.
- `tests/fixtures/sample_contracts/vulnerable_vault.vy` and the generated `examples/access_risk_contract_report.json` for the actual report schema and contract correlation fixture.
- `.github/workflows/ci.yml` for existing test/lint conventions.
