from datetime import datetime, timedelta, timezone

from scanpod_enterprise.db import SessionLocal
from scanpod_enterprise.models import CurrentExposure, HostObservation, InventoryScope, RunStatus, ScanProfile, ScanRun, ScanShard, ServiceObservation
from scanpod_enterprise.services import exposure_diff


def add_service(session, run, address, port, service, product=None, version=None):
    host = HostObservation(run_id=run.id, shard_id=f"shard-{run.id}", address=address, state="up")
    session.add(host)
    session.flush()
    session.add(ServiceObservation(host_observation_id=host.id, protocol="tcp", port=port, state="open", service=service, product=product, version=version))


def test_exposure_diff_reports_opened_closed_disappeared_and_changed_services():
    with SessionLocal() as session:
        scope = InventoryScope(name="diff-scope", cidr="10.80.0.0/24", zone="default", approved=True)
        profile = ScanProfile(name="diff-profile", version=1, ports="22,80,443", zone="default")
        session.add_all([scope, profile])
        session.flush()
        previous = ScanRun(inventory_scope_id=scope.id, profile_id=profile.id, requested_by="operator", status=RunStatus.completed, completed_at=datetime.now(timezone.utc) - timedelta(hours=1))
        current = ScanRun(inventory_scope_id=scope.id, profile_id=profile.id, requested_by="operator", status=RunStatus.completed, completed_at=datetime.now(timezone.utc))
        session.add_all([previous, current])
        session.flush()
        add_service(session, previous, "10.80.0.10", 22, "ssh", "OpenSSH", "8.0")
        add_service(session, previous, "10.80.0.10", 80, "http")
        add_service(session, previous, "10.80.0.20", 443, "https")
        add_service(session, current, "10.80.0.10", 22, "ssh", "OpenSSH", "9.0")
        add_service(session, current, "10.80.0.10", 8080, "http-proxy")
        add_service(session, current, "10.80.0.30", 443, "https")
        session.commit()

        observed, baseline, changes, coverage_complete = exposure_diff(session, scope.id, profile.id)

    assert (observed.id, baseline.id) == (current.id, previous.id)
    assert coverage_complete is True
    assert {(item["change_type"], item["address"], item.get("port")) for item in changes} == {
        ("host_disappeared", "10.80.0.20", None),
        ("port_opened", "10.80.0.10", 8080),
        ("port_opened", "10.80.0.30", 443),
        ("port_closed", "10.80.0.10", 80),
        ("service_changed", "10.80.0.10", 22),
    }
    changed = next(item for item in changes if item["change_type"] == "service_changed")
    assert (changed["previous_version"], changed["version"]) == ("8.0", "9.0")


def test_exposure_diff_withholds_changes_when_masscan_coverage_is_incomplete():
    with SessionLocal() as session:
        scope = InventoryScope(name="incomplete-scope", cidr="10.82.0.0/24", zone="default", approved=True)
        profile = ScanProfile(name="incomplete-profile", version=1, ports="443", zone="default", scanner_mode="masscan_then_nmap")
        session.add_all([scope, profile])
        session.flush()
        previous = ScanRun(inventory_scope_id=scope.id, profile_id=profile.id, requested_by="operator", status=RunStatus.completed, completed_at=datetime.now(timezone.utc) - timedelta(hours=1))
        current = ScanRun(inventory_scope_id=scope.id, profile_id=profile.id, requested_by="operator", status=RunStatus.completed, completed_at=datetime.now(timezone.utc))
        session.add_all([previous, current])
        session.flush()
        session.add(ScanShard(run_id=current.id, cidr="10.82.0.0/24", zone="default", discovery_artifact_key="runs/current/masscan.xml"))
        session.commit()

        observed, baseline, changes, coverage_complete = exposure_diff(session, scope.id, profile.id)

    assert (observed.id, baseline.id, changes, coverage_complete) == (current.id, previous.id, [], False)


def test_exposure_exports_apply_filters(client, auth_headers):
    with SessionLocal() as session:
        scope = InventoryScope(name="export-scope", cidr="10.81.0.0/24", zone="default", approved=True)
        profile = ScanProfile(name="export-profile", version=1, ports="443", zone="default")
        second_profile = ScanProfile(name="export-profile-alt", version=1, ports="443", zone="default")
        session.add_all([scope, profile, second_profile])
        session.flush()
        run = ScanRun(inventory_scope_id=scope.id, profile_id=profile.id, requested_by="operator", status=RunStatus.completed, completed_at=datetime.now(timezone.utc))
        second_run = ScanRun(inventory_scope_id=scope.id, profile_id=second_profile.id, requested_by="operator", status=RunStatus.completed, completed_at=datetime.now(timezone.utc))
        session.add_all([run, second_run])
        session.flush()
        session.add_all([
            CurrentExposure(inventory_scope_id=scope.id, profile_id=profile.id, latest_run_id=run.id, zone="default", address="10.81.0.10", protocol="tcp", port=443, service="https", scan_count=2),
            CurrentExposure(inventory_scope_id=scope.id, profile_id=second_profile.id, latest_run_id=second_run.id, zone="default", address="10.81.0.10", protocol="tcp", port=443, service="https", scan_count=3),
            CurrentExposure(inventory_scope_id=scope.id, profile_id=profile.id, latest_run_id=run.id, zone="default", address="10.81.0.11", protocol="tcp", port=22, service="ssh"),
        ])
        session.commit()

    csv_response = client.get("/v1/exposures/export?format=csv&port=443", headers=auth_headers)
    json_response = client.get("/v1/exposures/export?format=json&host=10.81.0.11", headers=auth_headers)

    assert csv_response.status_code == 200
    assert csv_response.headers["content-type"].startswith("text/csv")
    assert "10.81.0.10" in csv_response.text and "10.81.0.11" not in csv_response.text
    assert json_response.status_code == 200
    assert json_response.json()[0]["service"] == "ssh"
    exposures = client.get("/v1/exposures", headers=auth_headers).json()
    https = next(item for item in exposures if item["address"] == "10.81.0.10")
    assert len([item for item in exposures if item["address"] == "10.81.0.10"]) == 1
    assert https["scan_count"] == 5
