# OmniEsol SSH hardening (2026-11-09)

Security-only building block for Windows OpenSSH. Does **not** connect to a server or install ERP.

- Strict host key validation; pre-provisioned known_hosts required. Never use StrictHostKeyChecking=no.
- Batch key-only authentication; SSH arguments passed as a list with subprocess.run(..., shell=False).
- Host/user/port validation; remote commands restricted to a fixed read-only allowlist.
- No credentials in logs, shell commands or persisted configuration.
- Tests: python -m unittest discover -s tests -p 'test_ssh_policy.py'

Limitations: This module is not yet integrated with MVP GUI. Key/known_hosts file content and OS ACLs must be verified separately; Windows OpenSSH -F none support must be validated on target builds. Host key enrollment must occur out-of-band with trusted fingerprint verification. No Windows/RHEL integration test was run.
