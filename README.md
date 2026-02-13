# vps-harden

[![CI](https://github.com/ranjith-src/vps-harden/actions/workflows/ci.yml/badge.svg)](https://github.com/ranjith-src/vps-harden/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![ShellCheck](https://img.shields.io/badge/ShellCheck-passing-brightgreen)](https://www.shellcheck.net/)

Idempotent VPS security hardening script for Debian/Ubuntu. Run it once on a fresh VPS or repeatedly to verify and fix drift.

## Quick Start

**Install:**

```bash
curl -fsSL https://raw.githubusercontent.com/ranjith-src/vps-harden/main/install.sh | bash
```

**First run (dry run):**

```bash
sudo vps-harden --username deploy \
  --ssh-key "ssh-ed25519 AAAA..." \
  --dry-run
```

**Apply:**

```bash
sudo vps-harden --username deploy \
  --ssh-key "ssh-ed25519 AAAA..." \
  --ssh-safety-ip 203.0.113.10 \
  --timezone UTC
```

## Parameters

| Flag | Required | Description |
|------|----------|-------------|
| `--username USER` | Yes | Non-root user to create/harden |
| `--ssh-key KEY` | Yes | SSH public key (file path or inline `ssh-*` string) |
| `--ssh-safety-ip IP` | No | IP to always allow SSH from (safety net before tightening) |
| `--netbird-key KEY` | No | Netbird setup key for mesh VPN (skips VPN module if omitted) |
| `--timezone TZ` | No | System timezone (e.g. `Europe/Amsterdam`, `UTC`) |
| `--hostname NAME` | No | Set system hostname |
| `--auto-reboot` | No | Enable automatic reboot after kernel updates |
| `--skip MOD[,MOD]` | No | Comma-separated modules to skip |
| `--only MOD[,MOD]` | No | Run only specified modules |
| `--dry-run` | No | Preview changes without applying them |
| `--config FILE` | No | Load parameters from a `KEY=VALUE` file |
| `--no-color` | No | Disable colored output (useful for logging) |
| `--verbose` | No | Show command output instead of redirecting to log |
| `--version` | No | Print version and exit |
| `-h`, `--help` | No | Show usage help |

## Modules

Modules run in this order. Each is idempotent — safe to re-run.

| Module | What it does |
|--------|-------------|
| `prereqs` | Installs curl, wget, jq, htop, tree, unzip, ufw, fail2ban |
| `user` | Creates non-root user, adds to sudo group, deploys SSH keys |
| `ssh` | Writes `/etc/ssh/sshd_config.d/00-hardening.conf` — disables root login, sets MaxAuthTries 3, AllowUsers, banner. Includes lockout protection with automatic rollback. |
| `firewall` | Configures UFW: deny incoming, allow outgoing, allow SSH |
| `fail2ban` | Configures fail2ban with UFW integration (3 retries, 3h ban) |
| `sysctl` | Kernel hardening: SYN cookies, disable ICMP redirects/source routing, martian logging, reverse path filtering |
| `netbird` | Installs Netbird mesh VPN and connects with setup key (skipped if no key) |
| `firewall_tighten` | Allows traffic on VPN tunnel, restricts SSH to safety IP, removes broad SSH rules |
| `sops` | Installs SOPS + age for encrypted secrets management, generates keypair |
| `upgrades` | Enables unattended-upgrades, optional auto-reboot |
| `monitoring` | Installs auditd + logwatch, deploys audit rules, installs [`server-report`](#server-report) CLI, adds sudoers NOPASSWD rule |
| `shell` | Sets umask 027, configures bash history, scans for plaintext secrets |
| `misc` | Sets timezone/hostname, locks root password, restricts `su` to sudo group |
| `verify` | Runs all checks and prints a security scorecard |

## Security Scorecard

The `verify` module prints a scorecard at the end:

```
====================================================================
               VPS SECURITY SCORECARD
====================================================================
  [PASS] PermitRootLogin = no
  [PASS] MaxAuthTries = 3
  [PASS] UFW active, default deny
  [PASS] fail2ban sshd jail active
  [WARN] Netbird installed but wt0 not up
  ...
--------------------------------------------------------------------
  SCORE: 18 PASSED | 2 WARNING | 0 FAILED
--------------------------------------------------------------------
```

- **PASS** — correctly configured
- **WARN** — not critical but should be reviewed
- **FAIL** — security issue that needs fixing

## server-report

The `monitoring` module installs a companion CLI for quick health checks:

```bash
sudo server-report summary   # Uptime, load, memory, disk, SSH, services, updates
sudo server-report auth       # Failed/successful logins, sessions, banned IPs
sudo server-report audit      # Audit events by key (ssh_config, user_db, etc.)
sudo server-report full       # Full logwatch report (today)
```

All output is plain text with no colors — safe for piping, logging, or chatbot consumption. Commands degrade gracefully if tools (auditd, logwatch, fail2ban) are not installed.

## Config File

Instead of passing flags, use a config file:

```bash
sudo vps-harden --config config.env
```

See [`examples/config.env`](examples/config.env) for the format.

## Requirements

- **OS:** Debian 11+ or Ubuntu 20.04+
- **Access:** Root (via `sudo`)
- **Network:** Outbound internet access (for package installs)

## Lockout Protection

The SSH module includes multiple safeguards:

1. Validates `sshd` config syntax before restarting
2. Verifies SSH keys exist in `authorized_keys`
3. Checks `AllowUsers` includes the target user
4. Confirms UFW has an SSH allow rule
5. Rolls back config automatically if any check fails

## Contributing

1. Fork the repo
2. Create a feature branch
3. Ensure `shellcheck vps-harden.sh` passes
4. Submit a pull request

## License

[MIT](LICENSE)
