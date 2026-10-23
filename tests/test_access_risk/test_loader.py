import csv
import json
from pathlib import Path

import pytest

from guardian.access_risk.loader import load_input, validate_input

DEMO = Path(__file__).parents[2] / "examples/access_risk_demo.json"


def test_demo_loads_and_links():
    data = load_input(DEMO)
    assert len(data["identities"]) == 24 and data["assets"][0]["asset_id"] == "asset-vault"


def test_bad_timestamp_names_field():
    d = json.loads(DEMO.read_text())
    d["as_of"] = "2026-10-23T00:00:00"
    with pytest.raises(ValueError, match=r"as_of.*timezone"):
        validate_input(d)


def test_dangling_grant_rejected():
    d = json.loads(DEMO.read_text())
    d["grants"][0]["user_id"] = "missing"
    with pytest.raises(ValueError, match="unknown user_id"):
        validate_input(d)


def test_missing_field_rejected():
    d = json.loads(DEMO.read_text())
    del d["permissions"][0]["application"]
    with pytest.raises(ValueError, match="application"):
        validate_input(d)


def test_event_bad_timezone_rejected():
    d = json.loads(DEMO.read_text())
    d["events"][0]["timestamp"] = "2026-10-01T00:00:00"
    with pytest.raises(ValueError, match="timezone"):
        validate_input(d)


def test_csv_directory_round_trip(tmp_path):
    source = json.loads(DEMO.read_text())
    (tmp_path / "metadata.json").write_text(
        json.dumps({"as_of": source["as_of"], "policy": source["policy"]})
    )
    for name in ("identities", "permissions", "grants", "events", "assets", "log_coverage"):
        rows = source[name]
        if not rows:
            continue
        headers = sorted({key for row in rows for key in row})
        with (tmp_path / f"{name}.csv").open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=headers)
            writer.writeheader()
            for row in rows:
                writer.writerow({
                    key: json.dumps(value) if isinstance(value, (list, dict)) else
                    "" if value is None else str(value).lower() if isinstance(value, bool) else value
                    for key, value in row.items()
                })
    loaded = load_input(tmp_path)
    assert len(loaded["identities"]) == len(source["identities"])

    def clean(rows):
        return [{key: value for key, value in row.items() if value is not None} for row in rows]

    for entity in ("permissions", "events"):
        assert clean(loaded[entity]) == clean(source[entity])


def test_csv_directory_reports_invalid_boolean(tmp_path):
    (tmp_path / "metadata.json").write_text(json.dumps({"as_of": "2026-10-23T00:00:00Z"}))
    (tmp_path / "permissions.csv").write_text(
        "permission_id,application,name,action,resource,risk_level,sensitive,external_sharing,event_type,capability\n"
        "p,app,name,read,repo,low,yes,false,read,none\n"
    )
    with pytest.raises(ValueError, match="sensitive: expected true or false"):
        load_input(tmp_path)
