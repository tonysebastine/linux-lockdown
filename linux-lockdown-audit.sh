#!/usr/bin/env bash
# Linux Lockdown read-only audit engine. Never changes host configuration.
set -uo pipefail
umask 077
VERSION=0.1.0
printf 'Linux Lockdown Audit v%s\n' "$VERSION"
printf 'Mode: READ-ONLY AUDIT\n'
printf 'Timestamp UTC: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo unknown)"
if [[ -r /etc/os-release ]]; then . /etc/os-release; printf 'OS: %s (%s %s)\n' "${PRETTY_NAME:-unknown}" "${ID:-unknown}" "${VERSION_ID:-unknown}"; else printf 'OS: unknown (no readable /etc/os-release)\n'; fi
printf 'Kernel: %s\nArchitecture: %s\nUID: %s\n' "$(uname -r 2>/dev/null || echo unknown)" "$(uname -m 2>/dev/null || echo unknown)" "$(id -u 2>/dev/null || echo unknown)"
printf '\nDetected command-line components:\n'
found=0
for c in nginx apache2 httpd caddy php python3 node java docker podman ufw firewall-cmd nft iptables fail2ban sshd ss; do
  if command -v "$c" >/dev/null 2>&1; then printf ' - %s: present\n' "$c"; found=1; fi
done
[[ "$found" -eq 1 ]] || printf ' - No allowlisted component commands detected\n'
printf '\nSSH configuration (main file only):\n'
if [[ -r /etc/ssh/sshd_config ]]; then
  awk 'tolower($1)=="permitrootlogin" || tolower($1)=="passwordauthentication" || tolower($1)=="pubkeyauthentication" {print " - " $1 " " $2}' /etc/ssh/sshd_config
else printf ' - Main SSH config not readable by this user\n'; fi
printf '\nListening socket count: '
if command -v ss >/dev/null 2>&1; then ss -H -lntu 2>/dev/null | wc -l | tr -d ' '; else printf 'unavailable'; fi
printf '\nFirewall tooling:\n'
fw=0
for c in ufw firewall-cmd nft iptables; do if command -v "$c" >/dev/null 2>&1; then printf ' - %s present (presence does not prove active policy)\n' "$c"; fw=1; fi; done
[[ "$fw" -eq 1 ]] || printf ' - No common firewall CLI detected; check provider firewall manually\n'
printf '\nLimitations: best-effort, read-only checks; main sshd_config only; command presence is not proof of secure configuration.\n'
