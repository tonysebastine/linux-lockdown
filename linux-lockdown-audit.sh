#!/usr/bin/env bash
# Linux Lockdown read-only audit engine. Never changes host configuration.
set -uo pipefail
umask 077
VERSION=0.2.0
SCOPE="${1:-all}"
case "$SCOPE" in
  all|ssh|firewall|web|system) ;;
  *) printf 'Invalid scope: %s\nValid scopes: all, ssh, firewall, web, system\n' "$SCOPE" >&2; exit 2 ;;
esac

have() { command -v "$1" >/dev/null 2>&1; }
section() { printf '\n===== %s =====\n' "$1"; }
run_readonly() {
  # Run a read-only diagnostic and report unavailable/error states without aborting.
  "$@" 2>&1 || true
}

printf 'Linux Lockdown Audit v%s\n' "$VERSION"
printf 'Mode: READ-ONLY AUDIT\nScope: %s\n' "$SCOPE"
printf 'Timestamp UTC: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo unknown)"
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  printf 'OS: %s (%s %s)\n' "${PRETTY_NAME:-unknown}" "${ID:-unknown}" "${VERSION_ID:-unknown}"
else
  printf 'OS: unknown (no readable /etc/os-release)\n'
fi
printf 'Kernel: %s\nArchitecture: %s\nUID: %s\n' "$(uname -r 2>/dev/null || echo unknown)" "$(uname -m 2>/dev/null || echo unknown)" "$(id -u 2>/dev/null || echo unknown)"

if [[ "$SCOPE" == all || "$SCOPE" == system || "$SCOPE" == web ]]; then
  section "Detected command-line components"
  found=0
  for c in nginx apache2 httpd caddy php python3 node java docker podman ufw firewall-cmd nft iptables fail2ban-client fail2ban-server cscli sshguard sshd ss; do
    if have "$c"; then printf ' - %s: present\n' "$c"; found=1; fi
  done
  [[ "$found" -eq 1 ]] || printf ' - No allowlisted component commands detected\n'

  section "Hosting panel markers (best-effort)"
  panel_found=0
  for marker in /usr/local/cpanel /usr/local/psa /usr/local/CyberCP /usr/local/ispconfig /usr/local/directadmin /usr/local/1panel /opt/1panel; do
    if [[ -e "$marker" ]]; then printf ' - marker present: %s\n' "$marker"; panel_found=1; fi
  done
  [[ "$panel_found" -eq 1 ]] || printf ' - No known panel marker paths detected (not proof that no panel is installed)\n'

  section "Running web/application services (best-effort)"
  if have systemctl; then
    units="$(systemctl --no-pager --type=service --state=running list-units 2>/dev/null | grep -Ei 'nginx|apache|httpd|caddy|litespeed|lsws|php.*fpm|docker|podman|tomcat|gunicorn|uvicorn|fail2ban|crowdsec|sshguard' || true)"
    [[ -n "$units" ]] && printf '%s\n' "$units" || printf ' - No matching running service names detected\n'
  else
    printf ' - systemctl unavailable; service inspection skipped\n'
  fi
fi

if [[ "$SCOPE" == all || "$SCOPE" == ssh ]]; then
  section "SSH configuration"
  if have sshd; then
    if sshd -t >/dev/null 2>&1; then
      printf ' - sshd syntax validation: PASS\n'
    else
      printf ' - sshd syntax validation: FAIL or config unreadable; inspect sshd -t manually\n'
    fi
    printf ' - Effective settings from sshd -T (read-only):\n'
    sshd -T 2>/dev/null | awk '$1 ~ /^(port|listenaddress|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|authenticationmethods|maxauthtries|logingracetime|allowusers|allowgroups)$/ {print "   " $0}' || printf '   unavailable\n'
  else
    printf ' - sshd command not found; effective settings unavailable\n'
  fi
  printf ' - Main config directives and include/match markers:\n'
  if [[ -r /etc/ssh/sshd_config ]]; then
    awk 'tolower($1)=="include" || tolower($1)=="match" || tolower($1)=="port" || tolower($1)=="permitrootlogin" || tolower($1)=="passwordauthentication" || tolower($1)=="pubkeyauthentication" || tolower($1)=="kbdinteractiveauthentication" || tolower($1)=="authenticationmethods" || tolower($1)=="allowusers" || tolower($1)=="allowgroups" {print "   " $0}' /etc/ssh/sshd_config
  else
    printf '   Main SSH config not readable by this user\n'
  fi
  if [[ -d /etc/ssh/sshd_config.d ]]; then
    printf ' - SSH drop-in files:\n'
    find /etc/ssh/sshd_config.d -maxdepth 1 -type f -name '*.conf' -printf '   %f\n' 2>/dev/null | sort
  fi
  printf ' - Listening TCP/UDP socket count: '
  if have ss; then ss -H -lntu 2>/dev/null | wc -l | tr -d ' '; else printf 'unavailable'; fi
  printf '\n'

  section "Brute-force protection"
  protection_found=0
  if have fail2ban-client; then
    protection_found=1
    printf ' - Fail2ban client present\n'
    run_readonly fail2ban-client status
    run_readonly fail2ban-client status sshd
  else
    printf ' - Fail2ban client not found\n'
  fi
  if have cscli; then
    protection_found=1
    printf ' - CrowdSec CLI present\n'
    run_readonly cscli metrics
  else
    printf ' - CrowdSec CLI not found\n'
  fi
  if have sshguard; then
    protection_found=1
    printf ' - SSHGuard command present\n'
  else
    printf ' - SSHGuard command not found\n'
  fi
  if [[ "$protection_found" -eq 0 ]]; then
    printf ' - No recognized brute-force protection CLI found; service/package checks may still be needed\n'
  fi
  if have journalctl; then
    failures="$(journalctl -u ssh -u sshd --since '24 hours ago' --no-pager -o cat 2>/dev/null | grep -Eic 'Failed password|authentication failure|Invalid user' || true)"
    printf ' - Matching SSH failure/invalid-user log lines in last 24h: %s (best-effort count)\n' "${failures:-0}"
  else
    printf ' - journalctl unavailable; recent SSH failure count skipped\n'
  fi
fi

if [[ "$SCOPE" == all || "$SCOPE" == firewall ]]; then
  section "Firewall status"
  if have ufw; then
    printf ' - UFW status (read-only):\n'
    ufw status verbose 2>&1 || true
  else
    printf ' - UFW not found\n'
  fi
  if have firewall-cmd; then
    printf ' - firewalld state (read-only):\n'
    firewall-cmd --state 2>&1 || true
    firewall-cmd --get-active-zones 2>&1 || true
  else
    printf ' - firewall-cmd not found\n'
  fi
  if have nft; then
    printf ' - nftables ruleset summary (up to 80 lines; read-only):\n'
    nft list ruleset 2>&1 | head -80 || true
  else
    printf ' - nft not found\n'
  fi
  if have iptables; then
    printf ' - iptables IPv4 filter rules (up to 60 lines; read-only):\n'
    iptables -S 2>&1 | head -60 || true
  else
    printf ' - iptables not found\n'
  fi
  printf ' - Tool presence alone does not prove that a firewall policy is active or correct.\n'
fi

section "Safety and limitations"
printf '%s\n' ' - Read-only checks only: no packages installed, files changed, firewall rules changed, or services restarted.'
printf '%s\n' ' - Best-effort host inspection; some commands may be unavailable or require elevated privileges.'
printf '%s\n' ' - SSH effective settings are more authoritative than reading sshd_config alone, but Match rules can vary by connection context.'
printf '%s\n' ' - Hosting panel detection uses a small set of marker paths and can miss custom installations.'
printf '%s\n' ' - Audit output can disclose host configuration; store and share it carefully.'
