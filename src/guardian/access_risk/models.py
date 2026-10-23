"""Typed provider-neutral schema declarations for access snapshots."""

from __future__ import annotations

from typing import NotRequired, TypedDict


class Identity(TypedDict):
    user_id: str
    email: str
    team: str
    role: str
    status: str
    manager: str
    last_active_at: str | None
    usual_countries: list[str]
    usual_applications: list[str]


class Permission(TypedDict):
    permission_id: str
    application: str
    name: str
    action: str
    resource: str
    risk_level: str
    sensitive: bool
    external_sharing: bool
    event_type: str
    capability: str
    controls_asset_id: NotRequired[str | None]


class Grant(TypedDict):
    user_id: str
    permission_id: str
    granted_at: str
    expires_at: NotRequired[str | None]
    grant_source: str
    approver: str


class Event(TypedDict):
    event_id: str
    user_id: str
    permission_id: NotRequired[str | None]
    application: str
    action: str
    resource: str
    timestamp: str
    country: str
    ip: str
    success: bool


class Asset(TypedDict):
    asset_id: str
    name: str
    type: str
    criticality: str
    owners: list[str]
    vyper_report_path: NotRequired[str | None]


class LogCoverage(TypedDict):
    application: str
    event_types: list[str]
    window_start: str
    window_end: str


class AccessSnapshot(TypedDict):
    as_of: str
    policy: dict
    identities: list[Identity]
    permissions: list[Permission]
    grants: list[Grant]
    events: list[Event]
    assets: list[Asset]
    log_coverage: list[LogCoverage]
