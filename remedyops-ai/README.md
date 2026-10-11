# RemedyOps AI Web MVP v0.2

Web + SQL database prototype for vulnerability remediation and selective rollback.

## Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8000
```

Visit http://127.0.0.1:8000. Swagger API: http://127.0.0.1:8000/docs.

SQLite is the default DB (`remedyops.db`). PostgreSQL: install `psycopg[binary]` and set `DATABASE_URL=postgresql+psycopg://...`.

## Implemented
- Browser UI, server asset metadata management and DB persistence
- Sandbox-only security findings and allowlisted remediation
- Change-level backups, integrity hashes and selective rollback
- Audit log, high-risk SSH changes blocked

## Not implemented
Real SSH access, AI parsing, remote remediation, watchdog, login/RBAC, report exports. **Never expose this prototype to a network or use with production secrets.**
