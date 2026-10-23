import json
from pathlib import Path

from typer.testing import CliRunner

from guardian.access_risk.engine import analyze
from guardian.access_risk.loader import load_input
from guardian.access_risk.reports import projected_report, render_html, render_json, render_markdown
from guardian.cli import app

ROOT = Path(__file__).parents[2]
runner = CliRunner()


def test_json_markdown_html_metadata_disclaimer_limitations():
    d = load_input(ROOT / "examples/access_risk_demo.json")
    r = analyze(d)
    j = json.loads(render_json(r))
    m = render_markdown(r)
    h = render_html(r, projected_report(d, r))
    assert (
        j["schema_version"] == "vyper-guard-access-risk/v1"
        and j["tool_version"]
        and j["input_sha256"]
    )
    assert "does not certify" in m and "Limitations" in m and "Cross-layer" in m
    assert "does not certify" in h and "Limitations" in h and "Before / After (projected)" in h
    assert "http://" not in h and "https://" not in h
    assert all("evidence" in f and "priority_score" in f for f in j["findings"])


def test_cli_repeatable_output_and_fail_on(tmp_path):
    inp = str(ROOT / "examples/access_risk_demo.json")
    args = ["access-risk", inp, "--format", "json", "--as-of", "2026-10-23T00:00:00Z"]
    a = runner.invoke(app, args)
    b = runner.invoke(app, args)
    assert a.exit_code == b.exit_code == 0 and a.stdout == b.stdout
    assert runner.invoke(app, ["access-risk", inp, "--fail-on", "critical"]).exit_code == 1


def test_cli_bad_input_message(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{")
    r = runner.invoke(app, ["access-risk", str(p)])
    assert r.exit_code == 2 and "access-risk:" in r.output
