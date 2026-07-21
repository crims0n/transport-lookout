import csv
import io
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func
from sqlalchemy.orm import Session
from pydantic import ValidationError

from .auth import current_user, require_roles
from .config import settings
from .db import get_session
from .db import engine
from .metrics import API_DURATION, API_REQUESTS, render_metrics
from .models import AuditEvent, CurrentExposure, DiscoveryObservation, HostObservation, InventoryScope, Role, ScanProfile, ScanRun, ScanSchedule, ScanShard, ServiceObservation, User
from .schemas import AuditEventRead, DiscoveryResultRead, ExposureDiffRead, ExposureRead, ExposureSummary, HostRead, ProfileCreate, ProfileRead, RunCreate, RunRead, ScheduleCreate, ScheduleRead, ScopeCreate, ScopeRead, ServiceRead, UserProvision, UserRead
from .services import audit, cancel_run, create_run, exposure_diff, parse_approved_cidr


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield


app = FastAPI(title="Transport Lookout API", version="0.1.0", lifespan=lifespan)
if settings.cors_origins:
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins.split(","), allow_credentials=True, allow_methods=["GET", "POST", "DELETE"], allow_headers=["Authorization", "Content-Type"])


@app.middleware("http")
async def observe_request(request: Request, call_next):
    started = time.perf_counter()
    response = await call_next(request)
    route = getattr(request.scope.get("route"), "path", request.url.path)
    API_REQUESTS.labels(method=request.method, route=route, status=response.status_code).inc()
    API_DURATION.labels(method=request.method, route=route).observe(time.perf_counter() - started)
    return response


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/readyz")
def readyz():
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")
        from .worker import celery
        with celery.connection_for_read() as connection:
            connection.ensure_connection(max_retries=0)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="dependency unavailable") from exc
    return {"status": "ready"}


@app.get("/metrics", include_in_schema=False)
def metrics(session: Session = Depends(get_session)):
    body, media_type = render_metrics(session)
    return Response(content=body, media_type=media_type)


@app.get("/v1/me", response_model=UserRead)
def me(user: User = Depends(current_user)):
    return user


@app.get("/v1/users", response_model=list[UserRead])
def list_users(session: Session = Depends(get_session), _: User = Depends(require_roles(Role.platform_admin))):
    return session.query(User).order_by(User.subject).all()


@app.put("/v1/users/{subject}", response_model=UserRead)
def provision_user(subject: str, payload: UserProvision, session: Session = Depends(get_session), user: User = Depends(require_roles(Role.platform_admin))):
    if subject != payload.subject:
        raise HTTPException(status_code=422, detail="subject path and body must match")
    target = session.query(User).filter_by(subject=subject).one_or_none()
    if target is None:
        target = User(subject=subject, role=payload.role)
        session.add(target)
    else:
        target.role = payload.role
    session.flush()
    audit(session, user.subject, "user.provisioned", "user", target.id, subject=target.subject, role=target.role.value)
    session.commit()
    return target


@app.post("/v1/inventory/scopes", response_model=ScopeRead, status_code=status.HTTP_201_CREATED)
def add_scope(payload: ScopeCreate, session: Session = Depends(get_session), user: User = Depends(require_roles(Role.platform_admin, Role.inventory_manager))):
    network = parse_approved_cidr(payload.cidr)
    if session.query(InventoryScope).filter((InventoryScope.name == payload.name) | (InventoryScope.cidr == str(network))).first():
        raise HTTPException(status_code=409, detail="scope name or CIDR already exists")
    scope = InventoryScope(name=payload.name, cidr=str(network), zone=payload.zone)
    session.add(scope)
    session.flush()
    audit(session, user.subject, "inventory_scope.created", "inventory_scope", scope.id, cidr=scope.cidr)
    session.commit()
    session.refresh(scope)
    return scope


@app.post("/v1/inventory/scopes/import", response_model=list[ScopeRead], status_code=status.HTTP_201_CREATED)
async def import_scopes_csv(request: Request, session: Session = Depends(get_session), user: User = Depends(require_roles(Role.platform_admin, Role.inventory_manager))):
    """Atomically import pending inventory scopes from a UTF-8 CSV file.

    Required columns are ``name,cidr``; the optional ``zone`` column defaults to
    ``default``. Imported scopes always require a separate approval action.
    """
    try:
        source = (await request.body()).decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(source))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise HTTPException(status_code=422, detail="CSV must be UTF-8 encoded with a header row") from exc
    if not reader.fieldnames or not {"name", "cidr"}.issubset(reader.fieldnames):
        raise HTTPException(status_code=422, detail="CSV must include name and cidr columns")
    rows = list(reader)
    if not rows:
        raise HTTPException(status_code=422, detail="CSV contains no inventory scopes")
    if len(rows) > settings.inventory_import_max_rows:
        raise HTTPException(status_code=422, detail=f"CSV exceeds the {settings.inventory_import_max_rows} row limit")

    candidates: list[ScopeCreate] = []
    names: set[str] = set()
    cidrs: set[str] = set()
    for row_number, row in enumerate(rows, start=2):
        try:
            candidate = ScopeCreate(name=(row.get("name") or "").strip(), cidr=(row.get("cidr") or "").strip(), zone=(row.get("zone") or "default").strip() or "default")
            network = parse_approved_cidr(candidate.cidr)
        except (ValidationError, HTTPException) as exc:
            detail = exc.detail if isinstance(exc, HTTPException) else str(exc.errors()[0]["msg"])
            raise HTTPException(status_code=422, detail=f"CSV row {row_number}: {detail}") from exc
        candidate.cidr = str(network)
        if candidate.name in names or candidate.cidr in cidrs:
            raise HTTPException(status_code=409, detail=f"CSV row {row_number}: duplicate name or CIDR in file")
        names.add(candidate.name)
        cidrs.add(candidate.cidr)
        candidates.append(candidate)
    if session.query(InventoryScope).filter((InventoryScope.name.in_(names)) | (InventoryScope.cidr.in_(cidrs))).first():
        raise HTTPException(status_code=409, detail="one or more scope names or CIDRs already exist")

    scopes = [InventoryScope(name=item.name, cidr=item.cidr, zone=item.zone) for item in candidates]
    session.add_all(scopes)
    session.flush()
    for scope in scopes:
        audit(session, user.subject, "inventory_scope.imported", "inventory_scope", scope.id, cidr=scope.cidr, zone=scope.zone)
    session.commit()
    return scopes


@app.get("/v1/inventory/scopes", response_model=list[ScopeRead])
def list_scopes(session: Session = Depends(get_session), _: User = Depends(current_user)):
    return session.query(InventoryScope).order_by(InventoryScope.name).all()


@app.post("/v1/inventory/scopes/{scope_id}/approve", response_model=ScopeRead)
def approve_scope(scope_id: str, session: Session = Depends(get_session), user: User = Depends(require_roles(Role.platform_admin))):
    scope = session.get(InventoryScope, scope_id)
    if not scope:
        raise HTTPException(status_code=404, detail="scope not found")
    scope.approved = True
    audit(session, user.subject, "inventory_scope.approved", "inventory_scope", scope.id)
    session.commit()
    return scope


@app.delete("/v1/inventory/scopes/{scope_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scope(scope_id: str, session: Session = Depends(get_session), user: User = Depends(require_roles(Role.platform_admin, Role.inventory_manager))):
    scope = session.get(InventoryScope, scope_id)
    if not scope:
        raise HTTPException(status_code=404, detail="scope not found")
    has_runs = session.query(ScanRun).filter_by(inventory_scope_id=scope.id).first()
    has_schedules = session.query(ScanSchedule).filter_by(inventory_scope_id=scope.id).first()
    if has_runs or has_schedules:
        raise HTTPException(status_code=409, detail="scope cannot be deleted while runs or schedules reference it")
    audit(session, user.subject, "inventory_scope.deleted", "inventory_scope", scope.id, name=scope.name, cidr=scope.cidr)
    session.delete(scope)
    session.commit()


@app.post("/v1/scan-profiles", response_model=ProfileRead, status_code=status.HTTP_201_CREATED)
def add_profile(payload: ProfileCreate, session: Session = Depends(get_session), user: User = Depends(require_roles(Role.platform_admin))):
    latest = session.query(ScanProfile).filter_by(name=payload.name).order_by(ScanProfile.version.desc()).first()
    profile = ScanProfile(**payload.model_dump(), version=(latest.version + 1 if latest else 1))
    session.add(profile)
    session.flush()
    audit(session, user.subject, "scan_profile.created", "scan_profile", profile.id, version=profile.version)
    session.commit()
    return profile


@app.get("/v1/scan-profiles", response_model=list[ProfileRead])
def list_profiles(session: Session = Depends(get_session), _: User = Depends(current_user)):
    return session.query(ScanProfile).order_by(ScanProfile.name, ScanProfile.version.desc()).all()


@app.delete("/v1/scan-profiles/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_profile(profile_id: str, session: Session = Depends(get_session), user: User = Depends(require_roles(Role.platform_admin))):
    profile = session.get(ScanProfile, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="profile not found")
    has_runs = session.query(ScanRun).filter_by(profile_id=profile.id).first()
    has_schedules = session.query(ScanSchedule).filter_by(profile_id=profile.id).first()
    if has_runs or has_schedules:
        raise HTTPException(status_code=409, detail="profile cannot be deleted while runs or schedules reference it")
    audit(session, user.subject, "scan_profile.deleted", "scan_profile", profile.id, name=profile.name, version=profile.version)
    session.delete(profile)
    session.commit()


@app.post("/v1/schedules", response_model=ScheduleRead, status_code=status.HTTP_201_CREATED)
def add_schedule(payload: ScheduleCreate, session: Session = Depends(get_session), user: User = Depends(require_roles(Role.platform_admin, Role.scan_operator))):
    try:
        ZoneInfo(payload.timezone)
    except ZoneInfoNotFoundError as exc:
        raise HTTPException(status_code=422, detail="unknown IANA timezone") from exc
    scope = session.get(InventoryScope, payload.inventory_scope_id)
    profile = session.get(ScanProfile, payload.profile_id)
    if not scope or not profile:
        raise HTTPException(status_code=404, detail="scope or profile not found")
    if not scope.approved or scope.zone != profile.zone:
        raise HTTPException(status_code=422, detail="schedule requires an approved scope and matching profile zone")
    if session.query(ScanSchedule).filter_by(name=payload.name).first():
        raise HTTPException(status_code=409, detail="schedule name already exists")
    first_run = payload.first_run_at or datetime.now(timezone.utc)
    schedule = ScanSchedule(name=payload.name, inventory_scope_id=scope.id, profile_id=profile.id, interval_minutes=payload.interval_minutes, timezone=payload.timezone, next_run_at=first_run, created_by=user.subject)
    session.add(schedule)
    session.flush()
    audit(session, user.subject, "schedule.created", "scan_schedule", schedule.id, interval_minutes=schedule.interval_minutes)
    session.commit()
    return schedule


@app.get("/v1/schedules", response_model=list[ScheduleRead])
def list_schedules(session: Session = Depends(get_session), _: User = Depends(current_user)):
    return session.query(ScanSchedule).order_by(ScanSchedule.next_run_at).all()


@app.post("/v1/schedules/{schedule_id}/disable", response_model=ScheduleRead)
def disable_schedule(schedule_id: str, session: Session = Depends(get_session), user: User = Depends(require_roles(Role.platform_admin, Role.scan_operator))):
    schedule = session.get(ScanSchedule, schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="schedule not found")
    schedule.enabled = False
    audit(session, user.subject, "schedule.disabled", "scan_schedule", schedule.id)
    session.commit()
    return schedule


def to_run_read(session: Session, run: ScanRun) -> RunRead:
    return RunRead(id=run.id, inventory_scope_id=run.inventory_scope_id, profile_id=run.profile_id, status=run.status, requested_by=run.requested_by, created_at=run.created_at, started_at=run.started_at, completed_at=run.completed_at, shards=session.query(ScanShard).filter_by(run_id=run.id).all())


@app.post("/v1/scan-runs", response_model=RunRead, status_code=status.HTTP_202_ACCEPTED)
def add_run(payload: RunCreate, session: Session = Depends(get_session), user: User = Depends(require_roles(Role.platform_admin, Role.scan_operator))):
    scope = session.get(InventoryScope, payload.inventory_scope_id)
    profile = session.get(ScanProfile, payload.profile_id)
    if not scope or not profile:
        raise HTTPException(status_code=404, detail="scope or profile not found")
    return to_run_read(session, create_run(session, scope, profile, user.subject))


@app.get("/v1/scan-runs/{run_id}", response_model=RunRead)
def get_run(run_id: str, session: Session = Depends(get_session), _: User = Depends(current_user)):
    run = session.get(ScanRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    return to_run_read(session, run)


@app.get("/v1/scan-runs", response_model=list[RunRead])
def list_runs(limit: int = 50, session: Session = Depends(get_session), _: User = Depends(current_user)):
    limit = min(max(limit, 1), 200)
    runs = session.query(ScanRun).order_by(ScanRun.created_at.desc()).limit(limit).all()
    return [to_run_read(session, run) for run in runs]


@app.get("/v1/audit-events", response_model=list[AuditEventRead])
def list_audit_events(limit: int = 100, session: Session = Depends(get_session), _: User = Depends(require_roles(Role.platform_admin, Role.auditor))):
    return session.query(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(min(max(limit, 1), 500)).all()


def filtered_exposures(session: Session, scope_id: str | None, host: str | None, port: int | None, service: str | None):
    query = session.query(CurrentExposure)
    if scope_id:
        query = query.filter(CurrentExposure.inventory_scope_id == scope_id)
    if host:
        query = query.filter(CurrentExposure.address == host)
    if port:
        query = query.filter(CurrentExposure.port == port)
    if service:
        query = query.filter(CurrentExposure.service.ilike(f"%{service}%"))
    return query


def deduplicated_exposures(session: Session, scope_id: str | None = None, host: str | None = None, port: int | None = None, service: str | None = None):
    """Present one global row per host/protocol/port/service across scan profiles."""
    partition = [CurrentExposure.address, CurrentExposure.protocol, CurrentExposure.port, CurrentExposure.service]
    ranked = filtered_exposures(session, scope_id, host, port, service).with_entities(
        CurrentExposure.id, CurrentExposure.inventory_scope_id, CurrentExposure.profile_id, CurrentExposure.latest_run_id,
        CurrentExposure.zone, CurrentExposure.address, CurrentExposure.protocol, CurrentExposure.port,
        CurrentExposure.service, CurrentExposure.product, CurrentExposure.version,
        func.row_number().over(partition_by=partition, order_by=CurrentExposure.last_seen_at.desc()).label("row_rank"),
        func.min(CurrentExposure.first_seen_at).over(partition_by=partition).label("first_seen_at"),
        func.max(CurrentExposure.last_seen_at).over(partition_by=partition).label("last_seen_at"),
        func.sum(CurrentExposure.scan_count).over(partition_by=partition).label("scan_count"),
    ).subquery()
    return session.query(ranked).filter(ranked.c.row_rank == 1).order_by(ranked.c.address, ranked.c.port)


def to_exposure_read(item) -> ExposureRead:
    return ExposureRead(
        id=item.id, inventory_scope_id=item.inventory_scope_id, profile_id=item.profile_id, latest_run_id=item.latest_run_id,
        zone=item.zone, address=item.address, protocol=item.protocol, port=item.port, service=item.service,
        product=item.product, version=item.version, first_seen_at=item.first_seen_at, last_seen_at=item.last_seen_at,
        scan_count=item.scan_count,
    )


@app.get("/v1/exposures", response_model=list[ExposureRead])
def list_exposures(scope_id: str | None = None, host: str | None = None, port: int | None = None, service: str | None = None, limit: int = 100, offset: int = 0, session: Session = Depends(get_session), _: User = Depends(current_user)):
    items = deduplicated_exposures(session, scope_id, host, port, service).offset(max(offset, 0)).limit(min(max(limit, 1), 500)).all()
    return [to_exposure_read(item) for item in items]


@app.get("/v1/exposures/export")
def export_exposures(format: str = "csv", scope_id: str | None = None, host: str | None = None, port: int | None = None, service: str | None = None, session: Session = Depends(get_session), _: User = Depends(current_user)):
    items = deduplicated_exposures(session, scope_id, host, port, service).limit(10_000).all()
    rows = [to_exposure_read(item).model_dump(mode="json") for item in items]
    if format == "json":
        return Response(content=json.dumps(jsonable_encoder(rows)), media_type="application/json", headers={"Content-Disposition": "attachment; filename=transport-lookout-exposures.json"})
    if format != "csv":
        raise HTTPException(status_code=422, detail="format must be csv or json")
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(ExposureRead.model_fields))
    writer.writeheader()
    writer.writerows(rows)
    return Response(content=output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=transport-lookout-exposures.csv"})


@app.get("/v1/exposure-diffs", response_model=ExposureDiffRead)
def get_exposure_diff(scope_id: str, profile_id: str, session: Session = Depends(get_session), _: User = Depends(current_user)):
    current, previous, changes, coverage_complete = exposure_diff(session, scope_id, profile_id)
    return ExposureDiffRead(current_run_id=current.id if current else None, previous_run_id=previous.id if previous else None, coverage_complete=coverage_complete, coverage_note=None if coverage_complete else "Masscan discovery coverage was incomplete; changes are withheld to avoid false closures.", changes=changes)


@app.get("/v1/exposures/summary", response_model=ExposureSummary)
def exposure_summary(session: Session = Depends(get_session), _: User = Depends(current_user)):
    exposures = deduplicated_exposures(session).subquery()
    open_hosts, open_services, unique_ports, latest = session.query(func.count(func.distinct(exposures.c.address)), func.count(exposures.c.id), func.count(func.distinct(exposures.c.port)), func.max(exposures.c.last_seen_at)).one()
    return ExposureSummary(open_hosts=open_hosts, open_services=open_services, unique_ports=unique_ports, latest_observation_at=latest)


@app.get("/v1/scan-runs/{run_id}/hosts", response_model=list[HostRead])
def get_run_hosts(run_id: str, limit: int = 100, offset: int = 0, session: Session = Depends(get_session), _: User = Depends(current_user)):
    if not session.get(ScanRun, run_id):
        raise HTTPException(status_code=404, detail="run not found")
    limit = min(max(limit, 1), 500)
    hosts = session.query(HostObservation).filter_by(run_id=run_id).order_by(HostObservation.address).offset(offset).limit(limit).all()
    return [HostRead(id=host.id, address=host.address, state=host.state, hostname=host.hostname, services=[ServiceRead.model_validate(item) for item in session.query(ServiceObservation).filter_by(host_observation_id=host.id).order_by(ServiceObservation.port).all()]) for host in hosts]


@app.get("/v1/scan-runs/{run_id}/masscan-results", response_model=list[DiscoveryResultRead])
def get_masscan_results(run_id: str, limit: int = 100, offset: int = 0, session: Session = Depends(get_session), _: User = Depends(current_user)):
    if not session.get(ScanRun, run_id):
        raise HTTPException(status_code=404, detail="run not found")
    limit = min(max(limit, 1), 500)
    rows = session.query(DiscoveryObservation, ScanShard).join(ScanShard, ScanShard.id == DiscoveryObservation.shard_id).filter(DiscoveryObservation.run_id == run_id).order_by(DiscoveryObservation.address, DiscoveryObservation.port).offset(max(offset, 0)).limit(limit).all()
    return [DiscoveryResultRead(shard_id=item.shard_id, cidr=shard.cidr, address=item.address, protocol=item.protocol, port=item.port) for item, shard in rows]


@app.post("/v1/scan-runs/{run_id}/cancel", response_model=RunRead)
def cancel(run_id: str, session: Session = Depends(get_session), user: User = Depends(require_roles(Role.platform_admin, Role.scan_operator))):
    run = session.get(ScanRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    return to_run_read(session, cancel_run(session, run, user.subject))
