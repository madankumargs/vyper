import copy, json
from pathlib import Path
import pytest
from guardian.access_risk.loader import load_input, validate_input

DEMO=Path(__file__).parents[2]/'examples/access_risk_demo.json'
def test_demo_loads_and_links():
    data=load_input(DEMO); assert len(data['identities'])==24 and data['assets'][0]['asset_id']=='asset-vault'
def test_bad_timestamp_names_field():
    d=json.loads(DEMO.read_text());d['as_of']='2026-10-23T00:00:00'
    with pytest.raises(ValueError,match='as_of.*timezone'): validate_input(d)
def test_dangling_grant_rejected():
    d=json.loads(DEMO.read_text());d['grants'][0]['user_id']='missing'
    with pytest.raises(ValueError,match='unknown user_id'): validate_input(d)
def test_missing_field_rejected():
    d=json.loads(DEMO.read_text());del d['permissions'][0]['application']
    with pytest.raises(ValueError,match='application'): validate_input(d)
def test_event_bad_timezone_rejected():
    d=json.loads(DEMO.read_text());d['events'][0]['timestamp']='2026-10-01T00:00:00'
    with pytest.raises(ValueError,match='timezone'): validate_input(d)
