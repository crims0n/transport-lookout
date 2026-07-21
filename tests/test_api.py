from scanpod_enterprise.db import SessionLocal
from scanpod_enterprise.models import DiscoveryObservation, RunStatus, ScanRun, ScanShard
from scanpod_enterprise.worker import celery


def create_scope(client, headers, cidr="10.42.0.0/16"):
    response = client.post(
        "/v1/inventory/scopes",
        headers=headers,
        json={"name": "test-network", "cidr": cidr, "zone": "default"},
    )
    assert response.status_code == 201
    return response.json()


def approve_scope(client, headers, scope_id):
    response = client.post(f"/v1/inventory/scopes/{scope_id}/approve", headers=headers)
    assert response.status_code == 200


def create_profile(client, headers, zone="default"):
    response = client.post(
        "/v1/scan-profiles",
        headers=headers,
        json={
            "name": "limited-tcp",
            "ports": "22,443",
            "max_rate": 100,
            "timeout_seconds": 120,
            "zone": zone,
        },
    )
    assert response.status_code == 201
    return response.json()


def test_bootstrap_authentication_is_required(client):
    assert client.get("/v1/me").status_code == 401
    response = client.get("/v1/me", headers={"Authorization": "Bearer wrong-token"})
    assert response.status_code == 401
    # Identity headers supplied by a caller are never trusted as authentication.
    assert client.get("/v1/me", headers={"X-Forwarded-User": "bootstrap-admin"}).status_code == 401


def test_liveness_and_metrics_are_available(client):
    assert client.get("/healthz").json() == {"status": "ok"}
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "transport_lookout_api_requests_total" in response.text


def test_admin_can_provision_an_oidc_subject(client, auth_headers):
    response = client.put(
        "/v1/users/alice@example.com",
        headers=auth_headers,
        json={"subject": "alice@example.com", "role": "scan_operator"},
    )
    assert response.status_code == 200
    assert response.json() == {"subject": "alice@example.com", "role": "scan_operator"}


def test_unreferenced_scope_and_profile_can_be_deleted(client, auth_headers):
    scope = create_scope(client, auth_headers, "10.60.0.0/24")
    profile = create_profile(client, auth_headers)
    assert client.delete(f"/v1/inventory/scopes/{scope['id']}", headers=auth_headers).status_code == 204
    assert client.delete(f"/v1/scan-profiles/{profile['id']}", headers=auth_headers).status_code == 204


def test_csv_import_creates_pending_scopes_atomically(client, auth_headers):
    response = client.post(
        "/v1/inventory/scopes/import",
        headers={**auth_headers, "Content-Type": "text/csv"},
        content="name,cidr,zone\nbranch-a,10.62.0.0/24,default\nbranch-b,10.62.1.0/24,isolated\n",
    )
    assert response.status_code == 201
    assert [(scope["name"], scope["approved"], scope["zone"]) for scope in response.json()] == [
        ("branch-a", False, "default"), ("branch-b", False, "isolated"),
    ]

    invalid = client.post(
        "/v1/inventory/scopes/import",
        headers={**auth_headers, "Content-Type": "text/csv"},
        content="name,cidr\nvalid-row,10.63.0.0/24\nbad-row,10.63.0.1/24\n",
    )
    assert invalid.status_code == 422
    assert [item["name"] for item in client.get("/v1/inventory/scopes", headers=auth_headers).json()] == ["branch-a", "branch-b"]


def test_referenced_scope_cannot_be_deleted(client, auth_headers, monkeypatch):
    monkeypatch.setattr(celery, "send_task", lambda *_, **__: None)
    scope = create_scope(client, auth_headers, "10.61.0.0/24")
    approve_scope(client, auth_headers, scope["id"])
    profile = create_profile(client, auth_headers)
    client.post("/v1/scan-runs", headers=auth_headers, json={"inventory_scope_id": scope["id"], "profile_id": profile["id"]})
    response = client.delete(f"/v1/inventory/scopes/{scope['id']}", headers=auth_headers)
    assert response.status_code == 409


def test_scope_cannot_be_run_until_approved(client, auth_headers):
    scope = create_scope(client, auth_headers)
    profile = create_profile(client, auth_headers)

    response = client.post(
        "/v1/scan-runs",
        headers=auth_headers,
        json={"inventory_scope_id": scope["id"], "profile_id": profile["id"]},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "inventory scope is not approved"


def test_run_is_sharded_and_dispatched_after_approval(client, auth_headers, monkeypatch):
    dispatched = []
    monkeypatch.setattr(celery, "send_task", lambda name, args: dispatched.append((name, args)))
    scope = create_scope(client, auth_headers)
    approve_scope(client, auth_headers, scope["id"])
    profile = create_profile(client, auth_headers)

    response = client.post(
        "/v1/scan-runs",
        headers=auth_headers,
        json={"inventory_scope_id": scope["id"], "profile_id": profile["id"]},
    )

    assert response.status_code == 202
    run = response.json()
    assert len(run["shards"]) == 256
    assert all(shard["cidr"].endswith("/24") for shard in run["shards"])
    assert len(dispatched) == 4
    assert sum(shard["status"] == "leased" for shard in run["shards"]) == 4
    assert sum(shard["status"] == "queued" for shard in run["shards"]) == 252
    assert all(name == "scanpod_enterprise.worker.execute_shard" for name, _ in dispatched)


def test_zone_mismatch_rejects_run(client, auth_headers):
    scope = create_scope(client, auth_headers, "10.43.0.0/16")
    approve_scope(client, auth_headers, scope["id"])
    profile = create_profile(client, auth_headers, zone="isolated")
    response = client.post(
        "/v1/scan-runs",
        headers=auth_headers,
        json={"inventory_scope_id": scope["id"], "profile_id": profile["id"]},
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "profile and inventory scope must use the same worker zone"


def test_invalid_profile_ports_are_rejected(client, auth_headers):
    response = client.post(
        "/v1/scan-profiles",
        headers=auth_headers,
        json={"name": "unsafe", "ports": "22;--script=vuln"},
    )
    assert response.status_code == 422


def test_profile_can_enable_controlled_masscan_discovery(client, auth_headers):
    response = client.post(
        "/v1/scan-profiles",
        headers=auth_headers,
        json={"name": "perimeter-tcp", "ports": "80,443", "scanner_mode": "masscan_then_nmap", "max_rate": 500, "timeout_seconds": 900, "zone": "default"},
    )
    assert response.status_code == 201
    assert response.json()["scanner_mode"] == "masscan_then_nmap"

    udp = client.post(
        "/v1/scan-profiles",
        headers=auth_headers,
        json={"name": "udp-discovery", "ports": "U:53", "scanner_mode": "masscan_then_nmap", "max_rate": 500, "timeout_seconds": 900, "zone": "default"},
    )
    assert udp.status_code == 422


def test_run_masscan_results_are_available_for_review(client, auth_headers):
    with SessionLocal() as session:
        run = ScanRun(inventory_scope_id="scope", profile_id="profile", requested_by="operator", status=RunStatus.completed)
        session.add(run)
        session.flush()
        shard = ScanShard(run_id=run.id, cidr="10.90.0.0/24", zone="default")
        session.add(shard)
        session.flush()
        session.add(DiscoveryObservation(run_id=run.id, shard_id=shard.id, address="10.90.0.10", protocol="tcp", port=443))
        session.commit()

    response = client.get(f"/v1/scan-runs/{run.id}/masscan-results", headers=auth_headers)
    assert response.status_code == 200
    assert response.json() == [{"shard_id": shard.id, "cidr": "10.90.0.0/24", "address": "10.90.0.10", "protocol": "tcp", "port": 443}]


def test_cancelled_run_marks_queued_shards_cancelled(client, auth_headers, monkeypatch):
    monkeypatch.setattr(celery, "send_task", lambda *_, **__: None)
    scope = create_scope(client, auth_headers, "10.44.0.0/24")
    approve_scope(client, auth_headers, scope["id"])
    profile = create_profile(client, auth_headers)
    run = client.post(
        "/v1/scan-runs",
        headers=auth_headers,
        json={"inventory_scope_id": scope["id"], "profile_id": profile["id"]},
    ).json()

    response = client.post(f"/v1/scan-runs/{run['id']}/cancel", headers=auth_headers)

    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"
    assert response.json()["shards"][0]["status"] == "cancelled"
