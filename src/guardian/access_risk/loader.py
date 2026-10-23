"""Strict JSON ingestion for access-risk snapshots."""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any

ENTITIES = {
    "identities": {
        "user_id",
        "email",
        "team",
        "role",
        "status",
        "manager",
        "last_active_at",
        "usual_countries",
        "usual_applications",
    },
    "permissions": {
        "permission_id",
        "application",
        "name",
        "action",
        "resource",
        "risk_level",
        "sensitive",
        "external_sharing",
        "event_type",
        "capability",
    },
    "grants": {"user_id", "permission_id", "granted_at", "grant_source", "approver"},
    "events": {
        "event_id",
        "user_id",
        "application",
        "action",
        "resource",
        "timestamp",
        "country",
        "ip",
        "success",
    },
    "assets": {"asset_id", "name", "type", "criticality", "owners"},
    "log_coverage": {"application", "event_types", "window_start", "window_end"},
}


def _date(value: Any, field: str, record: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} in {record}: expected timezone-aware ISO-8601 timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} in {record}: invalid ISO-8601 timestamp") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError(f"{field} in {record}: timestamp must include a timezone")
    return result


def validate_input(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("input: expected a JSON object")
    if "as_of" not in data:
        raise ValueError("as_of: required timezone-aware ISO-8601 timestamp")
    _date(data["as_of"], "as_of", "input")
    normalized = dict(data)
    for collection, required in ENTITIES.items():
        rows = data.get(collection, [])
        if not isinstance(rows, list):
            raise ValueError(f"{collection}: expected an array")
        normalized[collection] = rows
        id_field = {
            "identities": "user_id",
            "permissions": "permission_id",
            "grants": "user_id",
            "events": "event_id",
            "assets": "asset_id",
            "log_coverage": "application",
        }[collection]
        seen: set[str] = set()
        for index, row in enumerate(rows):
            label = (
                str(row.get(id_field, f"{collection}[{index}]"))
                if isinstance(row, dict)
                else f"{collection}[{index}]"
            )
            if not isinstance(row, dict):
                raise ValueError(f"{label}: expected an object")
            missing = required - row.keys()
            # Events and grants can legitimately have no permission_id; permissions may omit asset link.
            if collection == "events":
                missing.discard("permission_id")
            if missing:
                raise ValueError(
                    f"{label}: missing required field(s): {', '.join(sorted(missing))}"
                )
            if id_field in row and collection != "grants" and collection != "log_coverage":
                key = str(row[id_field])
                if key in seen:
                    raise ValueError(f"{label}: duplicate {id_field}")
                seen.add(key)
            for field in {
                "as_of": [],
                "identities": ["last_active_at"],
                "grants": ["granted_at", "expires_at"],
                "events": ["timestamp"],
                "log_coverage": ["window_start", "window_end"],
            }.get(collection, []):
                if field in row and row[field] is not None:
                    _date(row[field], field, label)
            enum_fields = {
                "identities": {"status": {"active", "inactive", "disabled", "terminated"}},
                "permissions": {
                    "risk_level": {"low", "medium", "high", "critical"},
                    "capability": {"none", "deploy", "admin"},
                },
                "assets": {"type": {"smart_contract", "saas_app", "other"}},
            }.get(collection, {})
            for field, allowed in enum_fields.items():
                if row.get(field) not in allowed:
                    raise ValueError(
                        f"{field} in {label}: expected one of {', '.join(sorted(allowed))}"
                    )
            if collection == "permissions" and (
                not isinstance(row.get("sensitive"), bool)
                or not isinstance(row.get("external_sharing"), bool)
            ):
                raise ValueError(f"{label}: sensitive and external_sharing must be booleans")
            if collection == "events" and not isinstance(row.get("success"), bool):
                raise ValueError(f"success in {label}: expected boolean")
            nullable = {
                "identities": {"last_active_at"},
                "grants": {"expires_at"},
                "permissions": {"controls_asset_id"},
                "assets": {"vyper_report_path"},
            }
            for field in required:
                if field not in row or (
                    row[field] is None and field not in nullable.get(collection, set())
                ):
                    raise ValueError(f"{field} in {label}: required value is missing")
            string_fields = {
                "identities": {"user_id", "email", "team", "role", "status", "manager"},
                "permissions": {
                    "permission_id",
                    "application",
                    "name",
                    "action",
                    "resource",
                    "risk_level",
                    "event_type",
                    "capability",
                },
                "grants": {"user_id", "permission_id", "grant_source", "approver"},
                "events": {
                    "event_id",
                    "user_id",
                    "application",
                    "action",
                    "resource",
                    "country",
                    "ip",
                },
                "assets": {"asset_id", "name", "type", "criticality"},
                "log_coverage": {"application"},
            }
            for field in string_fields.get(collection, set()):
                if not isinstance(row.get(field), str):
                    raise ValueError(f"{field} in {label}: expected string")
            for field in {
                "identities": ["usual_countries", "usual_applications"],
                "assets": ["owners"],
                "log_coverage": ["event_types"],
            }.get(collection, []):
                if not isinstance(row.get(field), list) or any(
                    not isinstance(x, str) for x in row[field]
                ):
                    raise ValueError(f"{field} in {label}: expected array of strings")
    ids = {x["user_id"] for x in normalized["identities"]}
    perms = {x["permission_id"] for x in normalized["permissions"]}
    assets = {x["asset_id"] for x in normalized["assets"]}
    for grant in normalized["grants"]:
        if grant["user_id"] not in ids:
            raise ValueError(f"grant {grant['user_id']}/{grant['permission_id']}: unknown user_id")
        if grant["permission_id"] not in perms:
            raise ValueError(
                f"grant {grant['user_id']}/{grant['permission_id']}: unknown permission_id"
            )
    for permission in normalized["permissions"]:
        aid = permission.get("controls_asset_id")
        if aid and aid not in assets:
            raise ValueError(
                f"permission {permission['permission_id']}: unknown controls_asset_id {aid}"
            )
    for asset in normalized["assets"]:
        for owner in asset["owners"]:
            if owner not in ids:
                raise ValueError(f"asset {asset['asset_id']}: unknown owner {owner}")
    for coverage in normalized["log_coverage"]:
        if _date(coverage["window_start"], "window_start", coverage["application"]) > _date(
            coverage["window_end"], "window_end", coverage["application"]
        ):
            raise ValueError(
                f"log_coverage {coverage['application']}: window_start is after window_end"
            )
    for event in normalized["events"]:
        if event["user_id"] not in ids:
            raise ValueError(f"event {event['event_id']}: unknown user_id {event['user_id']}")
        pid = event.get("permission_id")
        if pid and pid not in perms:
            raise ValueError(f"event {event['event_id']}: unknown permission_id {pid}")
    normalized.setdefault("policy", {})
    if not isinstance(normalized["policy"], dict):
        raise ValueError("policy: expected an object")
    return normalized


def load_input(path: str | Path) -> dict[str, Any]:
    """Load a JSON snapshot or a directory of entity CSVs.

    CSV directories use ``metadata.json`` for ``as_of`` and optional ``policy``;
    each entity is represented by a same-named CSV file. Array values are JSON
    encoded in a cell, and nullable values may be blank.
    """
    source = Path(path)
    if source.is_dir():
        return validate_input(_load_csv_directory(source))
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read input {path}: {exc}") from exc
    return validate_input(data)


def _load_csv_directory(directory: Path) -> dict[str, Any]:
    metadata_path = directory / "metadata.json"
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read CSV metadata {metadata_path}: {exc}") from exc
    if not isinstance(metadata, dict) or "as_of" not in metadata:
        raise ValueError("metadata.json: expected an object containing as_of")

    arrays = {"usual_countries", "usual_applications", "owners", "event_types"}
    booleans = {"sensitive", "external_sharing", "success"}
    nullable = {
        "last_active_at",
        "expires_at",
        "controls_asset_id",
        "vyper_report_path",
        "permission_id",
    }
    data = {"as_of": metadata["as_of"], "policy": metadata.get("policy", {})}
    for entity in ENTITIES:
        csv_path = directory / f"{entity}.csv"
        if not csv_path.exists():
            data[entity] = []
            continue
        try:
            with csv_path.open(encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                if reader.fieldnames is None:
                    raise ValueError(f"{csv_path}: missing CSV header")
                rows = []
                for row_number, row in enumerate(reader, start=2):
                    record = {}
                    for field, value in row.items():
                        if value is None:
                            continue
                        value = value.strip()
                        if value == "" and field in nullable:
                            record[field] = None
                        elif field in arrays and value:
                            try:
                                decoded = json.loads(value)
                            except json.JSONDecodeError as exc:
                                raise ValueError(f"{csv_path}:{row_number} {field}: expected JSON array") from exc
                            if not isinstance(decoded, list):
                                raise ValueError(f"{csv_path}:{row_number} {field}: expected JSON array")
                            record[field] = decoded
                        elif field in booleans:
                            if value.lower() not in {"true", "false"}:
                                raise ValueError(f"{csv_path}:{row_number} {field}: expected true or false")
                            record[field] = value.lower() == "true"
                        elif value != "":
                            record[field] = value
                    rows.append(record)
                data[entity] = rows
        except OSError as exc:
            raise ValueError(f"cannot read CSV entity {csv_path}: {exc}") from exc
    return data
