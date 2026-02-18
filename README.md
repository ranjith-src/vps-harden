# vps-harden

**One script. No dependencies. Dry-run first. Lockout protection built in.**

Idempotent Bash script to harden an Ubuntu VPS. Run it once on a fresh server or repeatedly to verify and fix drift. Every change is previewed before it's applied, and SSH lockout protection rolls back automatically if something goes wrong.

[![CI](https://github.com/ranjith-src/vps-harden/actions/workflows/ci.yml/badge.svg)](https://github.com/ranjith-src/vps-harden/actions/workflows/ci.yml)
[![ShellCheck](https://img.shields.io/badge/ShellCheck-passing-brightgreen)](https://www.shellcheck.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/ranjith-src/vps-harden)](https://github.com/ranjith-src/vps-harden/releases)
[![GitHub stars](https://img.shields.io/github/stars/ranjith-src/vps-harden?style=social)](https://github.com/ranjith-src/vps-harden)

---

## Table of Contents

- [Why vps-harden](#why-vps-harden)
- [Quick Start](#quick-start)
- [What It Does](#what-it-does)
- [Security Scorecard](#security-scorecard)
- [server-report](#server-report)
- [Parameters](#parameters)
- [Config File](#config-file)
- [Lockout Protection](#lockout-protection)
- [Compatibility](#compatibility)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

---

## Why vps-harden

Most VPS hardening guides are long checklists you follow manually. Most scripts are interactive, not idempotent, and will break if you run them twice. This tool is different:

- **Idempotent** — checks current state before every action. Safe to re-run anytime.
- **Dry-run mode** — preview every change before applying. Nothing is modified until you're ready.
- **Modular** — run all 18 modules or pick only what you need with `--skip` and `--only`.
- **Lockout protection** — validates SSH config, keys, firewall rules, and AllowUsers before restarting. Auto-rolls back on failure.
- **Interactive or CLI** — setup wizard for first runs, fully non-interactive CLI for automation.
- **Single file, zero dependencies** — just Bash. No Python, no Ansible, no agents.

---

## Quick Start

**Install:**

```bash
curl -fsSL https://raw.githubusercontent.com/ranjith-src/vps-harden/main/install.sh | bash
```

**Interactive wizard (recommended for first run):**

```bash
sudo vps-harden
```

The wizard auto-detects SSH keys, your IP, and timezone — then offers a dry run before applying.

**Or use CLI flags directly:**

```bash
sudo vps-harden --username deploy \
  --ssh-key "ssh-ed25519 AAAA..." \
  --ssh-safety-ip 203.0.113.10 \
  --timezone UTC \
  --dry-run
```

> **New to VPS security?** The [Getting Started guide](docs/getting-started.md) walks you through everything step by step, including why each module matters.

---

## What It Does

18 modules run in order. Each is idempotent — safe to re-run. The first 14 are OS-level hardening; the last 4 are agent-specific and require `--agent-dir`.

| Module | What it does | Why |
|--------|-------------|-----|
| `prereqs` | Installs curl, wget, jq, htop, tree, unzip, ufw, fail2ban | Foundation packages for the rest of the script |
| `user` | Creates non-root user, adds to sudo, deploys SSH keys | Running as root is dangerous — sudo gives the same power with an audit trail |
| `ssh` | Disables root login, disables password auth, MaxAuthTries 3, AllowUsers, banner | SSH is the #1 attack surface. Bots find your server within minutes |
| `firewall` | UFW: deny incoming, allow outgoing, allow SSH | Default-deny means only services you explicitly allow are reachable |
| `fail2ban` | 3 retries, 3h ban, UFW integration | Stops brute-force bots from hammering your auth log |
| `sysctl` | SYN cookies, disable ICMP redirects/source routing, martian logging, RP filtering | Kernel-level protection against floods, routing attacks, spoofed packets |
| `netbird` | Installs Netbird mesh VPN, connects with setup key | Hide SSH from the public internet — only VPN peers can reach it |
| `firewall_tighten` | Allows VPN tunnel traffic, restricts SSH to safety IP, removes broad rules | Once VPN is up, close the public SSH door |
| `sops` | Installs SOPS + age, generates encryption keypair | Encrypted-at-rest secrets management for API keys and credentials |
| `upgrades` | Enables unattended-upgrades, optional auto-reboot | Most breaches exploit known vulnerabilities with patches already available |
| `monitoring` | Installs auditd + logwatch, deploys audit rules, installs [`server-report`](#server-report) | You can't protect what you can't see |
| `shell` | umask 027, bash history with timestamps, plaintext secret scanning | Prevents accidental world-readable files, aids forensics |
| `misc` | Timezone, hostname, lock root password, restrict `su` | Locks down remaining escalation paths |
| `agent_secrets` | Scans agent workspace for plaintext secrets, checks SOPS encryption, deploys helper | API keys in config files are the #1 agent security risk |
| `agent_webhook_auth` | Verifies webhook listener, UFW rules, TLS proxy, auth, rate limiting | Webhooks are unauthenticated HTTP endpoints by default |
| `agent_logging` | Creates log directory, logrotate, append-only flags, auditd rules | Tamper-evident logs for agent actions and API calls |
| `agent_data` | Checks data directory permissions, gitignore, git history, encryption | Health data, user data, and PII need restricted access |
| `verify` | Runs all checks, prints security scorecard | Single view of your security posture |

---

## Security Scorecard

The `verify` module prints a grouped scorecard at the end of every run. Section headers explain what each group does:

```
====================================================================
               VPS SECURITY SCORECARD
====================================================================

  ── SSH Hardening — Locks down remote access ──
  [PASS] PermitRootLogin = no
  [PASS] PasswordAuthentication = no
  [PASS] MaxAuthTries = 3
  ...
  [PASS] SSH banner configured

  ── Firewall — Controls network traffic ──
  [PASS] UFW active, default deny
  [PASS] SSH restricted (not open to 0.0.0.0)

  ── Intrusion Prevention — Blocks brute-force attacks ──
  [PASS] fail2ban sshd jail active

  ── Kernel Hardening — Prevents network-level attacks ──
  [PASS] SYN cookies enabled
  [PASS] ICMP redirects disabled
  ...

  ── Monitoring — Tracks system activity and threats ──
  [PASS] auditd active
  [PASS] Audit rules loaded (13 rules)
  [PASS] logwatch installed
  [PASS] server-report installed

  ── Network — Secure mesh VPN tunnel ──
  [WARN] Netbird not installed

  ── Secrets — Encrypted credential management ──
  [PASS] SOPS + age installed

  ── System — OS-level security hygiene ──
  [PASS] Unattended upgrades enabled
  [PASS] Root password locked
  [PASS] No plaintext secrets in .bashrc
  [PASS] authorized_keys permissions 600

  ── Agent Security — AI agent workspace hardening ──
  [PASS] No plaintext secrets in agent workspace
  [PASS] SOPS-encrypted secrets file present
  [PASS] Webhook listener active on port 5000
  [PASS] Agent logs directory exists (750)
  [PASS] Data directory permissions 700 (owner-only)
--------------------------------------------------------------------
  SCORE: 29 PASSED | 1 WARNING | 0 FAILED
--------------------------------------------------------------------
```

After a real run, the scorecard shows **next steps** — an SSH verification warning (test key-based login before closing your session), a ready-to-paste `~/.ssh/config` block, and conditional guidance for any WARN/FAIL items.

In **dry-run mode**, items that would be fixed on a real run are annotated with `← will fix`.

Run the scorecard anytime to check for drift:

```bash
sudo vps-harden --username deploy --ssh-key ~/.ssh/authorized_keys --only verify
```

---

## server-report

The `monitoring` module installs a companion CLI for quick health checks:

```bash
sudo server-report summary   # Uptime, load, memory, disk, SSH attempts, services, updates
sudo server-report auth       # Failed/successful logins (48h), sessions, banned IPs
sudo server-report audit      # Audit events by key (ssh_config, user_db, sudoers, etc.)
sudo server-report full       # Full logwatch report (today)
```

All output is plain text — no colors, no control codes. Safe for piping, logging, or chatbot consumption. Commands degrade gracefully if tools (auditd, logwatch, fail2ban) are not installed.

**OpenClaw bot integration:** Add `--openclaw-skill` to automatically configure server-report as a chatbot skill, so your bot can answer "how's the server?" on demand.

---

## Parameters

| Flag | Required | Description |
|------|----------|-------------|
| `--username USER` | Yes* | Non-root user to create/harden |
| `--ssh-key KEY` | Yes* | SSH public key (file path or inline `ssh-*` string) |
| `--interactive` | No | Force interactive setup wizard |

\* Not required when using the interactive wizard (`sudo vps-harden` with no args).
| `--ssh-safety-ip IP` | No | IP to always allow SSH from (safety net before tightening) |
| `--netbird-key KEY` | No | Netbird setup key for mesh VPN (skips VPN module if omitted) |
| `--timezone TZ` | No | System timezone (e.g. `Europe/Amsterdam`, `UTC`) |
| `--hostname NAME` | No | Set system hostname |
| `--auto-reboot` | No | Enable automatic reboot after kernel updates |
| `--openclaw-skill` | No | Add `server-report` skill to an OpenClaw bot |
| `--agent-dir DIR` | No | AI agent workspace directory (enables agent modules) |
| `--webhook-port PORT` | No | Webhook listener port (default: `5000`) |
| `--agent-data-dir DIR` | No | Sensitive data directory to protect |
| `--skip MOD[,MOD]` | No | Comma-separated modules to skip |
| `--only MOD[,MOD]` | No | Run only specified modules |
| `--dry-run` | No | Preview changes without applying them |
| `--config FILE` | No | Load parameters from a `KEY=VALUE` file |
| `--no-color` | No | Disable colored output |
| `--verbose` | No | Show command output instead of redirecting to log |
| `--version` | No | Print version and exit |
| `-h`, `--help` | No | Show usage help |

---

## Config File

Instead of passing flags, use a config file for repeatable setups:

```bash
sudo vps-harden --config /root/harden.env
```

See [`examples/config.env`](examples/config.env) for the format.

---

## Lockout Protection

The SSH module includes multiple safeguards to prevent you from losing access:

1. Validates `sshd` config syntax before restarting
2. Verifies SSH keys exist in `authorized_keys`
3. Checks `AllowUsers` includes the target user
4. Confirms UFW has an SSH allow rule
5. Rolls back config automatically if any check fails

If something goes wrong, your current SSH session stays alive and the config is reverted.

---

## Compatibility

| OS | Version | Status |
|----|---------|--------|
| Ubuntu | 24.04 LTS | Tested |
| Ubuntu | 22.04 LTS | Tested |
| Ubuntu | 20.04 LTS | Tested |
| Debian | 12 (Bookworm) | Untested (should work) |
| Debian | 11 (Bullseye) | Untested (should work) |

**Architecture:** amd64, arm64

**Requirements:** Root access (via `sudo`), outbound internet for package installs.

---

## Documentation

- **[Getting Started](docs/getting-started.md)** — Step-by-step onboarding guide with prerequisites, module explanations, troubleshooting
- **[Changelog](https://github.com/ranjith-src/vps-harden/releases)** — Release notes for each version
- **[Config Example](examples/config.env)** — Sample configuration file

---

## Contributing

1. Fork the repo
2. Create a feature branch
3. Ensure `shellcheck vps-harden.sh` passes
4. Submit a pull request

See open issues labeled [`good-first-issue`](https://github.com/ranjith-src/vps-harden/labels/good%20first%20issue) for ideas.

---

## License

[MIT](LICENSE)
