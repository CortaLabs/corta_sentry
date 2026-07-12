# Operations

## Credential recovery

The browser restores a valid session automatically. On the login screen, choose the local `data/admin.token` file instead of copying its contents. If the file is missing or does not match the database, run `cortasentry token rotate`; this revokes all previous admin tokens and browser sessions and writes a replacement file with mode `0600`. Treat that file as a password and never commit or upload it.

## Backup and restore

Stop CortaSentry or use SQLite's online backup tooling. Copy the database plus configuration and rules to encrypted storage. Do not copy only a live WAL database file without its `-wal`/`-shm` companions. Restore into a 0700 data directory, validate config, then start and check `/readyz`.

Use `PRAGMA integrity_check` during planned maintenance. Never edit migration records manually. Upgrades apply forward migrations and refuse databases newer than the binary.

## Authentication and proxying

`cortasentry token rotate` revokes existing administrator tokens and browser sessions, writes the new token file mode 0600, and shows it once. Store it in a password manager and restrict the data directory.

The server binds `127.0.0.1:8088`. For remote access, terminate TLS at a maintained reverse proxy, add strong network access controls, preserve request limits/timeouts, and explicitly set `unsafe_public_bind: true` only after reviewing the exposure. Set `secure_cookies: true` (or `CORTASENTRY_SECURE_COOKIES=true`) when browsers reach the service over HTTPS. Docker Compose binds the published host port to loopback while explicitly allowing the container-internal bind.

## Logs, metrics, and rules

Server logs are structured JSON and redact secrets by omission. Prometheus metrics are at `/metrics`; health and readiness are `/healthz` and `/readyz`. No telemetry leaves the host. Treat rules as code: review diffs, test fixtures, deploy atomically, and retain prior digests.

## Safe scanning

Keep active scanning disabled until CIDRs and ports are reviewed. Prefer narrow prefixes, use deny entries for infrastructure, maintain conservative concurrency/rates, monitor audit events, and cancel unexpected jobs. Never enable public targets for routine inventory.
