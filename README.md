# ScanPod Enterprise

An authorized, policy-governed network scanning platform for customer-managed Kubernetes.

The initial implementation provides a FastAPI control plane with inventory allowlists, immutable scan profiles, CIDR sharding, durable scan-run records, role checks, and audit events. Workers execute only the shards created by the scheduler; operators cannot submit arbitrary Nmap targets or arguments.

## Local development

```sh
cp .env.example .env
docker compose up --build
```

The API is available at `http://localhost:8080/docs`. Set `SCANPOD_BOOTSTRAP_TOKEN` in `.env`, then use it as a bearer token. The bootstrap user has the `platform_admin` role only in local bootstrap mode.

```sh
curl -H "Authorization: Bearer $SCANPOD_BOOTSTRAP_TOKEN" http://localhost:8080/v1/inventory/scopes
```

Production deployments must disable bootstrap authentication and configure OIDC validation at the ingress/control plane boundary.

