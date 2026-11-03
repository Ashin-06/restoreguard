# Runbook

How to deploy and operate the workbench as a service. Commands assume the repository root.

## Deploy

```bash
docker build -t restoreguard:1.1.0 .
python -m restoreguard.ops keygen          # one key per person; repeat for each
docker run -d --name restoreguard -p 8766:8766 -v restoreguard-data:/data \
  -e RESTOREGUARD_KEYS_FILE=/run/secrets/restoreguard-keys.json \
  -e RESTOREGUARD_ALLOWED_HOSTS=lab.example.org \
  restoreguard:1.1.0
curl -fsS http://127.0.0.1:8766/readyz
```

The image has no third-party packages, runs as a non-root user and keeps runs in `/data`. It
refuses to start, and says why, without hashed API keys. Put it behind a TLS-terminating proxy and
list the proxy's public name in `RESTOREGUARD_ALLOWED_HOSTS`. The native OpenBao workflow stays a
command-line step on a machine with the verified OpenBao binary.

## Configure

| Variable | Required in production | Meaning |
|---|---|---|
| `RESTOREGUARD_ENV` | — | `development` (default) or `production` |
| `RESTOREGUARD_API_KEYS` / `RESTOREGUARD_KEYS_FILE` | yes | JSON `{"sha256:<hex>": {"user": "...", "role": "..."}}`. Roles: `analyst` (run, read), `viewer` (read), `monitor` (metrics), `admin` |
| `RESTOREGUARD_HOST`, `RESTOREGUARD_PORT` | — | default `127.0.0.1:8766`; the image uses `0.0.0.0` |
| `RESTOREGUARD_ALLOWED_HOSTS` | when reached by name | comma-separated host names clients use (with or without a port) |
| `RESTOREGUARD_DATA_DIR` | — | run storage; `/data` in the image |
| `RESTOREGUARD_RATE_LIMIT` | — | requests per minute per client, default 120 |
| `RESTOREGUARD_LOG_LEVEL` | — | default `INFO` |

## Watch

- `GET /healthz` (process up), `GET /readyz` (data directory usable), `GET /metrics` (role
  `monitor`): `http_requests_total`, `http_request_duration_seconds`,
  `restoreguard_decisions_total{decision="matrix_run_vulnerable|matrix_run_protected|selection_minimized|scenarios_run"}`.
- Logs are JSON lines on stdout with a request ID; they hold no results.

## Rotate keys

Add the new key's hash, restart, hand over the key, remove the old hash, restart.

## Back up and restore

Runs are plain folders with a SHA-256 manifest. Back up the volume; after a restore, run
`python -m restoreguard verify <run folder>` on any run you rely on. (A tool about restores that
revive old state is a good reminder: a restored key file brings back removed keys too.)

## Incidents

1. **Leaked key.** Remove its hash and restart; review the access log for that user.
2. **A run fails `verify`.** Treat it as altered; re-run the matrix.
