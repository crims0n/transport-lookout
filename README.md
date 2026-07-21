# Transport Lookout

Transport Lookout is a policy-governed network exposure platform for security operations teams. It runs in customer-managed infrastructure, schedules only authorized scans, and turns Nmap output into a current inventory of open hosts and services.

## Current capabilities

- OIDC authentication, role-based access control, and local development bootstrap access
- Approved inventory scopes and controlled, versioned scan profiles—operators cannot submit arbitrary targets or Nmap arguments
- Scheduled and on-demand scans, with `/16` networks deterministically sharded into `/24` work units
- RabbitMQ/Celery workers with bounded concurrency, durable outbox delivery, leases, heartbeats, retry backoff, dead-letter state, and active-scan cancellation
- PostgreSQL-backed run, shard, audit, host, and service history with Alembic migrations
- Current Exposure Inventory: a deduplicated view of currently observed open host/port combinations, including first- and last-seen times
- React Operator Console for inventory approval, profiles, schedules, runs, result review, audit events, and exposure filtering

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

## Production notes

Production deployments must disable bootstrap access and configure OIDC issuer, audience, and JWKS settings. Deploy the control plane, scheduler, publisher, and workers with the provided Helm chart as a starting point; isolate scanning workers in dedicated network zones and node pools.

Transport Lookout currently retains raw artifacts on local worker storage. S3-compatible artifact storage, operational metrics/dashboards, and scale validation remain the next production-hardening milestones.

## Operations endpoints

- `GET /healthz` — process liveness
- `GET /readyz` — PostgreSQL and RabbitMQ readiness
- `GET /metrics` — Prometheus-compatible application and scanning metrics; restrict access at the ingress or network-policy layer in production

## License

Transport Lookout is licensed under the [GNU General Public License v3.0](LICENSE).
