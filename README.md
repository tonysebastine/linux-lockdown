# Linux Lockdown

A safety-first Linux server hardening dashboard and CLI for small VPSs and dedicated servers.

## Modes

- **Audit**: read-only checks; default.
- **Dry run**: emits a proposed plan only; makes no system changes.
- **Execute**: reserved for a future reviewed remediation engine. The web UI deliberately blocks execution until change-specific allowlists, backup/rollback tests, SSH recovery checks, and post-change verification are implemented. Do not treat the button as permission to run arbitrary shell commands.

## Current MVP (v0.2.0)

- Responsive dashboard with mode and scope selection.
- Scoped read-only host audit endpoint (`all`, `ssh`, `firewall`, `web`, `system`).
- SSH syntax/effective-setting checks, including SSH drop-in files and `Match`/`Include` markers.
- Best-effort detection of Fail2ban, CrowdSec, and SSHGuard; Fail2ban jail status when its CLI is available.
- Read-only UFW/firewalld/nftables/iptables inspection and a bounded recent SSH authentication-failure count.
- Best-effort hosting-panel marker and running web/application service detection.
- No arbitrary command execution, no package installation, no firewall/SSH edits, no service restarts.
- Authentication required for dashboard/API.
- Bind to localhost behind a TLS reverse proxy.

## Audit coverage and limits

The CLI accepts an optional scope, for example `bash linux-lockdown-audit.sh ssh` or `bash linux-lockdown-audit.sh firewall`. The default is `all`. Supported scopes are `all`, `ssh`, `firewall`, `web`, and `system`. The dashboard passes the selected scope to the audit script.

The audit only reports whether brute-force protection is detected and, where possible, reads its current status. It does **not** install, configure, enable, disable, or restart Fail2ban, CrowdSec, SSHGuard, SSH, or firewall services. A missing CLI does not prove a package/service is absent. SSH authentication counts are best-effort log-line counts, not a compromise verdict. Firewall ruleset output is bounded to avoid excessive reports.

## Requirements

- Python 3.11+
- Linux
- `bash`, `uname`, `id`, `awk`, `ss` (some checks optional)

## Local setup

The CLI audit does not need the Python dashboard dependencies. To install the dashboard dependencies safely into an isolated `.venv` without `sudo` or system-wide package changes, run as an unprivileged user:

```bash
bash scripts/install-deps.sh
source .venv/bin/activate

export LOCKDOWN_USERNAME=admin
export LOCKDOWN_PASSWORD='use-a-long-unique-password'
export LOCKDOWN_BIND=127.0.0.1
export LOCKDOWN_PORT=8088
uvicorn app:app --host "$LOCKDOWN_BIND" --port "$LOCKDOWN_PORT"
```

Open the service only through a configured HTTPS reverse proxy. Do not expose Uvicorn directly to the public internet.

## Nginx example

See `deploy/nginx-lockdown.conf.example`. Configure TLS using your existing certificate automation and verify DNS for `lockdown.thbtz.in` before enabling the site.

## systemd

See `deploy/linux-lockdown.service.example`. Adjust the service user and paths to your deployment. The current service needs no root privileges for its web UI; some host checks will be incomplete as an unprivileged user.

## Security notes

- Use a unique strong password and protect `.env`/service environment files.
- Add network-level access restrictions or an identity-aware proxy if available.
- Do not run this service as root.
- Never execute shell commands assembled from HTTP input.
- Keep audit reports private; they can disclose host details.
- `execute` mode is intentionally disabled until a reviewed, per-control remediation engine exists.

## Deployment outline

1. Clone this repository to `/opt/linux-lockdown`.
2. Create a dedicated unprivileged service account and Python virtual environment.
3. Install dependencies and set credentials via a root-readable environment file.
4. Run Uvicorn bound to `127.0.0.1:8088` using systemd.
5. Configure Nginx or an existing reverse proxy for `lockdown.thbtz.in` with HTTPS.
6. Verify DNS, TLS, authentication, logs and the audit endpoint before use.

This MVP has not been deployed to your server and does not verify that the domain points to it.