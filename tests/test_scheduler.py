from datetime import datetime, timedelta, timezone

from scanpod_enterprise.scheduler import dispatch_due_schedules

from test_api import approve_scope, create_profile, create_scope


def test_due_schedule_dispatches_once_and_advances(client, auth_headers, monkeypatch):
    scope = create_scope(client, auth_headers, "10.50.0.0/24")
    approve_scope(client, auth_headers, scope["id"])
    profile = create_profile(client, auth_headers)
    now = datetime.now(timezone.utc)
    response = client.post(
        "/v1/schedules",
        headers=auth_headers,
        json={"name": "daily-lab", "inventory_scope_id": scope["id"], "profile_id": profile["id"], "interval_minutes": 60, "timezone": "UTC", "first_run_at": (now - timedelta(minutes=1)).isoformat()},
    )
    assert response.status_code == 201
    calls = []
    monkeypatch.setattr("scanpod_enterprise.scheduler.create_run", lambda *args: calls.append(args))

    assert dispatch_due_schedules(now) == 1
    assert len(calls) == 1
    assert dispatch_due_schedules(now) == 0
