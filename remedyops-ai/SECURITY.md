# Security scope and limitations

- v0.3 is a development prototype, not an audited security product.
- Docker Compose binds port 8000 to loopback only. Do not expose publicly.
- Set a long random REMEDYOPS_API_TOKEN. Header: X-API-Token.
- The API token is a temporary development control, **not** multi-user authentication or RBAC.
- PostgreSQL stores asset metadata and audit events, not SSH private keys.
- SSH diagnostics are disabled by default. Enable only in a trusted isolated controller environment.
- SSH diagnostics require REMEDYOPS_ALLOWED_CIDRS, REMEDYOPS_SSH_KEY_PATH and REMEDYOPS_KNOWN_HOSTS_PATH. Provision private keys outside Git.
- SSH diagnostic commands are fixed and read-only; no remote remediation is implemented.
- Backups are unencrypted local demo files. Never place sensitive production configurations into sandbox.
- Production requirements: SSO/RBAC, secret vault, TLS, network egress policy, job isolation, change approvals, backup encryption, independent rollback watchdog, full test coverage and security review.
