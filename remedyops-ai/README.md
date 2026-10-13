# RemedyOps AI Web v0.3 (development prototype)

Browser-based asset management, sandbox remediation/rollback, PostgreSQL deployment, and opt-in **read-only** SSH diagnostics.

## Start with PostgreSQL

```bash
cd remedyops-ai
cp .env.example .env
# Replace both placeholder secrets in .env
docker compose up --build -d
```

Open http://127.0.0.1:8000, click **API 토큰 입력**, and enter the value of REMEDYOPS_API_TOKEN from your local .env file.

PostgreSQL persists asset metadata and audit events. Sandbox change/backup files are stored in a Docker volume. The app is bound to 127.0.0.1 only.

## Read-only SSH diagnostics (advanced, disabled by default)

The endpoint `POST /api/diagnose` accepts `{"asset_id":1}` and requires `X-API-Token`.

To enable, explicitly provision an SSH private key and known_hosts file on the controller, set:
- `REMEDYOPS_ENABLE_SSH_DIAGNOSTICS=true`
- `REMEDYOPS_ALLOWED_CIDRS=192.168.10.0/24` (replace with your approved subnet)
- `REMEDYOPS_SSH_KEY_PATH=/secure/path/id_ed25519`
- `REMEDYOPS_KNOWN_HOSTS_PATH=/secure/path/known_hosts`

For containers, these files must be mounted read-only and available to the non-root application user. Do not store keys in Git, DB, or .env. The default Docker Compose deployment **does not** mount SSH credentials or enable SSH diagnostics.

Fixed commands: `cat /etc/os-release`, `uname -r`, `uptime`, `getenforce`, `sshd -T`. No arbitrary remote command API exists.

## Limitations

**Do not use in production.** There is no SSO/RBAC, automated remote remediation, independent watchdog, encrypted backups, or full security test suite. The API token is a development-only control; use TLS and proper authentication before any multi-user deployment. See [SECURITY.md](SECURITY.md).
