# Linux Lockdown

A safety-first Linux server hardening dashboard and CLI for small VPSs and dedicated servers.

## One entry point

Use `linux-lockdown` as the single CLI entry point. It calls the audit engine, keeping the implementation modular while giving you one consistent command.

```bash
# Full read-only audit
bash linux-lockdown

# Scope-specific audit
bash linux-lockdown audit ssh
bash linux-lockdown audit firewall
bash linux-lockdown audit web
bash linux-lockdown audit system

# Print a cautious review plan and run the audit (no changes)
bash linux-lockdown plan all
bash linux-lockdown dry-run firewall

# Check shell syntax and run the full audit
bash linux-lockdown verify

# Intentionally refuses to run
bash linux-lockdown apply
```

The default command is `audit`; supported scopes are `all`, `ssh`, `firewall`, `web`, and `system`. You can also run `bash linux-lockdown help`.

## Modes and safety

- **Audit**: read-only checks; default.
- **Plan / dry-run**: prints a cautious review checklist and the audit report; makes no system changes.
- **Verify**: checks local shell syntax, then runs the full read-only audit.
- **Apply**: deliberately exits without making changes. A reviewed remediation engine is not implemented yet.

No CLI mode installs packages, edits SSH or firewall configuration, or restarts services. The unified entry point is not yet a one-file standalone bundle: it requires `linux-lockdown-audit.sh` beside it. This separation makes the audit engine independently testable.

## Current MVP (v0.3.0)

- Unified CLI entry point for audit, plan, dry-run, verify, and a guarded apply refusal.
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

The audit reports whether brute-force protection is detected and, where possible, reads its current status. It does **not** install, configure, enable, disable, or restart Fail2ban, CrowdSec, SSH, SSHGuard, or firewall services. A missing CLI does not prove a package/service is absent. SSH authentication counts are best-effort log-line counts, not a compromise verdict. Firewall ruleset output is bounded to avoid excessive reports.

Detection is best-effort: unknown panels, custom paths, containers, and application stacks may be missed. Plan output is a generic review checklist, not a claim that each listed issue exists. Do not blindly apply recommendations to a production host.

## Requirements

- CLI: Linux and Bash; optional checks use common system utilities.
- Dashboard: Python 3.11+.

## Local setup

The CLI does not need Python dashboard dependencies. To install dashboard dependencies safely into an isolated `.venv` without `sudo` or system-wide package changes, run as an unprivileged user:

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

- Use a unique strong password and protect service environment files.
- Add network-level access restrictions or an identity-aware proxy if available.
- Do not run the dashboard as root.
- Never execute shell commands assembled from HTTP input.
- Keep audit reports private; they can disclose host details.
- Execute/apply mode remains disabled until a reviewed, per-control remediation engine exists.

## Deployment outline

1. Clone this repository to a working directory such as `/opt/linux-lockdown`.
2. Use `bash linux-lockdown` for the CLI audit, or create a dedicated unprivileged account for the dashboard.
3. For the dashboard, create a Python virtual environment and install dependencies.
4. Run Uvicorn bound to `127.0.0.1:8088` using systemd.
5. Configure Nginx or an existing reverse proxy for `lockdown.thbtz.in` with HTTPS.
6. Verify DNS, TLS, authentication, logs and the audit endpoint before use.

The dashboard has not been deployed to your server and this repository does not verify that the domain points to it.
