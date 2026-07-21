# Transport Lookout

Transport Lookout is a policy-governed network exposure platform for security operations teams. It runs in customer-managed infrastructure, schedules only authorized scans, and turns Nmap output into a current inventory of open hosts and services.

## Current capabilities

- OIDC authentication, role-based access control, and local development bootstrap access
- Approved inventory scopes (including atomic CSV import) and controlled, versioned scan profiles—operators cannot submit arbitrary targets or Nmap arguments
- Scheduled and on-demand scans, with `/16` networks deterministically sharded into `/24` work units
- RabbitMQ/Celery workers with bounded concurrency, durable outbox delivery, leases, heartbeats, retry backoff, dead-letter state, and active-scan cancellation
- PostgreSQL-backed run, shard, audit, host, and service history with Alembic migrations
- Current Exposure Inventory: a deduplicated view of currently observed open host/port combinations, including first- and last-seen times
- Historical exposure diffs between completed scans: opened and closed ports, disappeared hosts, and changed service fingerprints
- Filtered current-exposure exports in CSV or JSON
- React Operator Console for CSV inventory import and approval, profiles, schedules, runs, result review, audit events, exposure filtering, exports, and change review

## Local development

Requirements: Docker Compose, Python 3.12+, and Node.js 20+ for the operator console.

```sh
cp .env.example .env
docker compose up --build
```

The control-plane API is available at `http://localhost:8080/docs`. The development `.env` enables a local bootstrap administrator; do not enable that mode in production.

```sh
curl -H "Authorization: Bearer $SCANPOD_BOOTSTRAP_TOKEN" \
  http://localhost:8080/v1/scan-runs
```

Start the operator console separately:

```sh
cd ui
npm install
npm run dev
```

Connect the console to `http://localhost:8080` with the configured bearer token. The console supports current exposure filters by scope, host, port, and service.

Run the fast checks while developing:

```sh
ruff check .
pytest -q
cd ui && npm run build
```

## Operator workflow

1. Add a scope manually or import a UTF-8 CSV with `name,cidr,zone` columns. `zone` is optional and defaults to `default`.
2. Review and approve each inventory scope. CSV imports are atomic and create only pending scopes.
3. Create a controlled scan profile, then start an on-demand run or attach the scope/profile pair to a schedule.
4. Review run hosts and shard outcomes. Use Exposure Inventory to filter the current perimeter, export the filtered view as CSV/JSON, or compare the latest two completed runs for a scope/profile.

The exposure comparison reports newly opened and closed ports, hosts that were no longer observed as up, and changes in service/product/version fingerprints.

## Production notes

Production deployments must disable bootstrap access and configure OIDC issuer, audience, and JWKS settings. Deploy the control plane, scheduler, publisher, and workers with the provided Helm chart as a starting point; isolate scanning workers in dedicated network zones and node pools.

The chart runs Alembic as a pre-install/pre-upgrade Job and expects a pre-created Secret containing `database-url` and `amqp-url`. Point `env.existingSecret` at that Secret; do not place production URLs in committed values files. It includes a service account that can be annotated for workload identity when using S3 artifacts. `networkPolicy` is intentionally opt-in because ingress-controller and monitoring namespace labels vary by cluster.

Raw scan XML uses filesystem storage by default, which keeps local Docker Compose testing self-contained. For durable production storage set `SCANPOD_ARTIFACT_BACKEND=s3` and provide `SCANPOD_ARTIFACT_S3_BUCKET`; optionally configure `SCANPOD_ARTIFACT_S3_PREFIX`, `SCANPOD_ARTIFACT_S3_REGION`, and `SCANPOD_ARTIFACT_S3_ENDPOINT_URL` for an S3-compatible service. Credentials come from the worker's standard AWS SDK credential chain.

## Operations endpoints

- `GET /healthz` — process liveness
- `GET /readyz` — PostgreSQL and RabbitMQ readiness
- `GET /metrics` — Prometheus-compatible application and scanning metrics; restrict access at the ingress or network-policy layer in production
- `GET /v1/exposures/export?format=csv|json` — filtered current exposure export
- `GET /v1/exposure-diffs?scope_id=...&profile_id=...` — comparison of the latest two completed runs

## Deployment maturity

Local Docker Compose is the supported path for development and feature testing. The Helm chart now includes migrations, API, workers, scheduler, publisher, secret references, resource defaults, optional monitoring resources, and an opt-in API NetworkPolicy. Before production, validate it in an isolated staging environment with a limited approved scope and a dedicated worker network zone; large-scope throughput, broker/database failure behavior, artifact retention, and cluster-specific policy settings require that environment.

## Monitoring integration

The Helm chart can create a Prometheus Operator `ServiceMonitor`, a `PrometheusRule` alert set, and a Grafana dashboard ConfigMap. Enable them only in a cluster where those CRDs and Grafana dashboard sidecar conventions are installed:

```yaml
monitoring:
  enabled: true
  alerts:
    enabled: true
  dashboard:
    enabled: true
```

The included alerts cover outbox backlog, stale workers, dead-letter shards, stale runs, and overdue schedules.

## License

Transport Lookout is licensed under the [GNU General Public License v3.0](LICENSE).
