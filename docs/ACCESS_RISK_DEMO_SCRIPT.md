# 3–4 minute demo script

1. **Problem (15 seconds).** “People keep SaaS permissions after roles change. Access Risk finds evidence-backed review candidates and never revokes access automatically.”
2. **Run the snapshot (35 seconds).** From the repo root run:
   ```sh
   vyper-guard access-risk examples/access_risk_demo.json --format cli --contract-report examples/access_risk_contract_report.json
   vyper-guard access-risk examples/access_risk_demo.json --format json --contract-report examples/access_risk_contract_report.json --output /tmp/access-risk.json --remediation-plan /tmp/access-plan.json
   ```
   Show the terminated administrator, covered unused production permission, peer exception, unusual login, and external sharing.
3. **Open HTML (35 seconds).**
   ```sh
   vyper-guard access-risk examples/access_risk_demo.json --format html --contract-report examples/access_risk_contract_report.json --output /tmp/access-risk.html
   ```
   Open the local file in a browser and show one finding's evidence table, score direction, and limitations.
4. **Cross-layer (35 seconds).** Show `cross_layer_exposure` for `user-05` and read aloud: “The linked contract has an access-control finding, which raises the priority of this user's access. It does not establish that the contract is exploitable.” The report was generated with `vyper-guard analyze examples/access_risk_vulnerable_vault.vy --format json` and verified to contain `unprotected_state_change` and `unprotected_selfdestruct`.
5. **Dry run and projection (30 seconds).** Open `/tmp/access-plan.json`, explain that every item is a proposed review and no grant changed. In HTML point out the projected comparison is simulated only.
6. **AWS flow artifacts (30 seconds).** Explain `aws/template.yaml`, `aws/lambda_handler.py`, and `aws/local_invoke.py`. Run `python aws/local_invoke.py examples/access_risk_demo.json` to show stubbed S3 outputs and SNS aggregate. AWS was not deployed.
7. **Limitations (20 seconds).** State that input data and truth labels are synthetic, rule and fixtures were authored by the same team, and no real-world accuracy or compliance claim is made.

If live AWS is unavailable, use the local stub output above or a previously captured recording of that command. Do not present it as a cloud deployment.
