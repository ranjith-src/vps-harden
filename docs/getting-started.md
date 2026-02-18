# Getting Started

This guide walks you through hardening a fresh VPS from first SSH login to a fully verified setup. It takes about 10 minutes.

## What you'll need

Before you start, have these ready:

| Item | Required | Where to get it |
|------|----------|-----------------|
| A VPS running **Ubuntu 20.04+** | Yes | Any provider (Hetzner, DigitalOcean, Linode, etc.) |
| **Root access** (root password or sudo) | Yes | Your VPS provider's dashboard |
| An **SSH key pair** | Yes | See [Generate an SSH key](#generate-an-ssh-key) below |
| Your **current public IP** | Recommended | Run `curl -s ifconfig.me` on your local machine |
| A **Netbird setup key** | Optional | [netbird.io](https://netbird.io) — free for personal use |

### Generate an SSH key

If you don't already have one, run this on your **local machine** (not the VPS):

```bash
ssh-keygen -t ed25519 -C "your-email@example.com"
```

Your public key will be at `~/.ssh/id_ed25519.pub`. You'll need its contents in the steps below.

## Step 1: Connect to your fresh VPS

Most providers give you a root password or console access. SSH in:

```bash
ssh root@YOUR_VPS_IP
```

> If your provider uses a different initial user (e.g. `ubuntu`), SSH as that user and prefix commands with `sudo`.

## Step 2: Install vps-harden

```bash
curl -fsSL https://raw.githubusercontent.com/ranjith-src/vps-harden/main/install.sh | bash
```

This downloads the script to `/usr/local/bin/vps-harden` (or `~/.local/bin/` if not root).

Verify it's installed:

```bash
vps-harden --version
```

## Step 3: Run the setup wizard

The easiest way to get started is the interactive wizard. Just run:

```bash
sudo vps-harden
```

The wizard will:
1. Ask for a username (auto-detects your current user)
2. Find your SSH key (checks `authorized_keys`, or fetches from GitHub, or lets you paste one)
3. Detect your IP for the safety-net SSH rule
4. Detect your timezone
5. Ask for an optional Netbird VPN key
6. **Offer a dry run first** (recommended — shows what would change before touching anything)

> **Prefer CLI flags?** You can skip the wizard and pass everything directly:
>
> ```bash
> sudo vps-harden --username deploy \
>   --ssh-key "ssh-ed25519 AAAA..." \
>   --ssh-safety-ip YOUR_LOCAL_IP \
>   --timezone UTC \
>   --dry-run
> ```

## Step 4: Apply

If you chose dry run in the wizard, review the output — every change is listed. Then run again without dry run to apply. The wizard prints the exact CLI command to re-run at the end.

Here's what each module does and why:

| Step | Module | What it does | Why |
|------|--------|-------------|-----|
| 1 | `prereqs` | Installs foundational packages (curl, wget, jq, htop, ufw, fail2ban) | These are dependencies for the rest of the script and useful for day-to-day admin |
| 2 | `user` | Creates a non-root user with sudo access and deploys your SSH key | Running as root is dangerous — a typo can destroy the system. A dedicated user with sudo gives you the same power with an audit trail |
| 3 | `ssh` | Disables root login, disables password auth, limits auth attempts to 3, restricts SSH to your user only, adds a warning banner | SSH is the #1 attack surface on any VPS. Brute-force bots will find your server within minutes of it going online |
| 4 | `firewall` | Enables UFW with deny-all-incoming, allow-all-outgoing, and an SSH exception | Without a firewall, every open port is exposed. Default-deny means only services you explicitly allow are reachable |
| 5 | `fail2ban` | Bans IPs after 3 failed SSH attempts for 3 hours | Even with key-only SSH, bots hammering your auth log wastes resources and clutters logs. fail2ban stops them early |
| 6 | `sysctl` | Enables SYN cookies, disables ICMP redirects and source routing, enables martian logging | Kernel-level protections against SYN floods, routing attacks, and spoofed packets. These are low-cost, high-value hardening |
| 7 | `netbird` | Installs Netbird mesh VPN and connects with your setup key (skipped if no key provided) | A VPN lets you hide SSH from the public internet entirely — only devices on your mesh network can reach it |
| 8 | `firewall_tighten` | Allows traffic on VPN tunnel, restricts SSH to safety IP, removes the broad SSH rule | Once VPN is up, there's no reason for SSH to be publicly reachable. This closes that door |
| 9 | `sops` | Installs SOPS + age and generates an encryption keypair | Gives you encrypted-at-rest secrets management. API keys, tokens, and credentials can be stored encrypted in your repo |
| 10 | `upgrades` | Enables unattended-upgrades for automatic security patches | Most breaches exploit known vulnerabilities with patches already available. Auto-updates close that window |
| 11 | `monitoring` | Installs auditd (kernel audit framework), logwatch (log summarizer), and the `server-report` CLI | You can't protect what you can't see. Auditd tracks config changes, privilege escalation, and auth events. server-report gives you a quick health overview on demand |
| 12 | `shell` | Sets umask 027, increases bash history with timestamps, scans for plaintext secrets | umask prevents accidental world-readable files. History timestamps help with incident forensics. Secret scanning catches accidental credential leaks |
| 13 | `misc` | Sets timezone/hostname, locks root password, restricts `su` to sudo group | Locking root prevents password-based root login entirely. Restricting `su` means even if an attacker gets a shell, they can't escalate via `su` |
| 14 | `verify` | Runs all checks and prints a security scorecard | A single view of your security posture. Run it anytime to check for drift |

**Agent modules** (15–18, require `--agent-dir`):

| Step | Module | What it does | Why |
|------|--------|-------------|-----|
| 15 | `agent_secrets` | Scans for plaintext API keys, checks SOPS encryption, deploys load-secrets helper | API keys in config files are the #1 agent security risk |
| 16 | `agent_webhook_auth` | Checks webhook listener, UFW exposure, TLS proxy, auth, rate limiting | Webhooks are unauthenticated HTTP endpoints by default |
| 17 | `agent_logging` | Creates log dir, logrotate, append-only flags, auditd rules | Tamper-evident logs for agent actions and API calls |
| 18 | `agent_data` | Checks data dir permissions, gitignore, git history, encryption | Health data, user data, and PII need restricted access |

> **Tip:** If a module fails, the script will continue with the remaining modules (except for the critical `user` and `ssh` modules, which abort on failure to prevent lockout).

## Step 5: Test SSH access (important!)

**Before closing your current session**, open a **new terminal** and test. The script prints the exact command in the **Next Steps** section:

```bash
ssh -i ~/.ssh/id_ed25519 deploy@YOUR_VPS_IP
```

If you have multiple SSH keys, the `-i` flag ensures the correct one is used. The script also prints a ready-to-paste `~/.ssh/config` block you can add on your local machine:

```
Host my-vps
    HostName YOUR_VPS_IP
    User deploy
    IdentityFile ~/.ssh/id_ed25519
```

Then connect with just `ssh my-vps`.

If this works, you're good. If it doesn't, you still have your original session to fix things.

Once confirmed:
- You can now `sudo` as `deploy` for any admin tasks
- Direct root SSH login is disabled
- Password authentication is disabled (key-only)

## Step 6: Read the scorecard

At the end of the run, you'll see a grouped scorecard with section headers:

```
====================================================================
               VPS SECURITY SCORECARD
====================================================================

  ── SSH Hardening — Locks down remote access ──
  [PASS] PermitRootLogin = no
  [PASS] PasswordAuthentication = no
  [PASS] MaxAuthTries = 3
  ...

  ── Firewall — Controls network traffic ──
  [PASS] UFW active, default deny
  [PASS] SSH restricted (not open to 0.0.0.0)

  ── Intrusion Prevention — Blocks brute-force attacks ──
  [PASS] fail2ban sshd jail active

  ── Kernel Hardening — Prevents network-level attacks ──
  [PASS] SYN cookies enabled
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
--------------------------------------------------------------------
  SCORE: 24 PASSED | 1 WARNING | 0 FAILED
--------------------------------------------------------------------

  NEXT STEPS:

  ⚠  IMPORTANT — Verify SSH access before closing this session!
     ...

  • Add this to ~/.ssh/config on your LOCAL machine:
     ...
```

- **PASS** — correctly configured, no action needed
- **WARN** — not critical, but review (e.g. Netbird not set up is fine if you don't need VPN)
- **FAIL** — something needs fixing. The label explains what's wrong

In **dry-run mode**, items that would be fixed on a real run are annotated with `← will fix`.

## Step 7: Optional — Set up Netbird VPN

If you want to access your VPS over a mesh VPN (recommended for hiding SSH from the public internet):

1. Sign up at [netbird.io](https://netbird.io) and create a setup key
2. Re-run with the Netbird key:

```bash
sudo vps-harden \
  --username deploy \
  --ssh-key ~/.ssh/authorized_keys \
  --ssh-safety-ip YOUR_LOCAL_IP \
  --netbird-key "nbs-XXXX..."
```

This will:
- Install Netbird and connect to your mesh network
- Allow all traffic on the VPN tunnel interface (`wt0`)
- Add a safety-net SSH rule for your IP
- **Remove the broad SSH rule** — SSH is now only reachable via VPN + safety IP

> **Important:** Ensure you can SSH via the Netbird tunnel IP before relying on it exclusively. Test: `ssh deploy@NETBIRD_VPS_IP`

## Step 8: Using server-report

After installation, you have a health monitoring CLI:

```bash
sudo server-report summary    # Quick health overview
sudo server-report auth        # Login attempts and bans
sudo server-report audit       # Audit trail (config changes, privilege escalation)
sudo server-report full        # Full logwatch report
```

## Step 9: Agent Workspace Hardening (optional)

If you run an AI agent on your VPS (e.g. an LLM chatbot, webhook receiver, or data pipeline), vps-harden can apply zero-trust hardening to the agent workspace. This is gated behind `--agent-dir` — users without agents are completely unaffected.

The 4 agent modules check for:
- **Plaintext secrets** in config files (API keys, tokens, credentials)
- **Webhook security** (TLS proxy, auth verification, rate limiting, firewall exposure)
- **Structured logging** (log directory permissions, logrotate, append-only flags, auditd rules)
- **Data protection** (directory permissions, gitignore, git history leaks, encryption at rest)

### Run agent hardening

```bash
sudo vps-harden --username deploy \
  --ssh-key ~/.ssh/authorized_keys \
  --agent-dir /home/deploy/.my-agent \
  --webhook-port 5050 \
  --agent-data-dir /home/deploy/.my-agent/data \
  --dry-run
```

This adds an "Agent Security" section to the scorecard:

```
  ── Agent Security — AI agent workspace hardening ──
  [PASS] No plaintext secrets in agent workspace
  [PASS] SOPS-encrypted secrets file present
  [PASS] Webhook listener active on port 5050
  [PASS] Agent logs directory exists (750)
  [PASS] Data directory permissions 700 (owner-only)
```

### Run only agent modules

```bash
sudo vps-harden --username deploy \
  --ssh-key ~/.ssh/authorized_keys \
  --agent-dir /home/deploy/.my-agent \
  --only agent_secrets,agent_webhook_auth,agent_logging,agent_data,verify
```

### Config file

You can also set agent parameters in your config file:

```bash
# /root/harden.env
agent_dir=/home/deploy/.my-agent
webhook_port=5050
agent_data_dir=/home/deploy/.my-agent/data
```

> **Note:** All agent module checks are advisory — they report PASS/WARN/FAIL on the scorecard but never block execution. If `--agent-dir` is not provided, all 4 modules silently skip.

## Ongoing maintenance

### Re-run to check for drift

vps-harden is idempotent. Run it periodically to verify nothing has drifted:

```bash
sudo vps-harden \
  --username deploy \
  --ssh-key ~/.ssh/authorized_keys \
  --only verify
```

This runs only the verification module and prints a fresh scorecard.

### Run specific modules

If you only need to re-apply one area:

```bash
sudo vps-harden \
  --username deploy \
  --ssh-key ~/.ssh/authorized_keys \
  --only firewall,fail2ban
```

### Using a config file

For repeated runs, save your parameters to a file:

```bash
# /root/harden.env
username=deploy
ssh_key=/home/deploy/.ssh/authorized_keys
ssh_safety_ip=203.0.113.10
timezone=UTC
```

Then:

```bash
sudo vps-harden --config /root/harden.env
```

## Troubleshooting

### "Unit sshd.service not found"

Some Ubuntu versions use `ssh.service` instead of `sshd.service`. The script auto-detects this, but if you hit this error on an older version, please [open an issue](https://github.com/ranjith-src/vps-harden/issues).

### Locked out after SSH hardening

The script has multiple lockout safeguards (config validation, key checks, automatic rollback). But if you do get locked out:

1. Use your VPS provider's **web console** (available in most dashboards)
2. Log in as root
3. Remove the hardening config: `rm /etc/ssh/sshd_config.d/00-hardening.conf`
4. Restart SSH: `systemctl restart ssh`
5. Fix the issue and re-run

### apt install hangs

If a module seems stuck during package installation, it may be waiting for an interactive prompt (e.g. postfix configuration). The script sets `DEBIAN_FRONTEND=noninteractive` to prevent this, but if you're running an older version, update to the latest.

### Netbird tunnel not coming up

After running the Netbird module, if `wt0` doesn't appear:

1. Check status: `netbird status`
2. Check logs: `journalctl -u netbird -n 50`
3. Ensure the setup key hasn't expired in your Netbird dashboard
4. Try reconnecting: `sudo netbird up --setup-key "nbs-XXXX..."`

## Optional: OpenClaw integration

If you run OpenClaw on your VPS, you can give your bot access to `server-report` so it can answer questions like "how's the server?" or "any attacks?" directly in chat.

The `--openclaw-skill` flag handles everything automatically — it adds `server-report` to the exec allowlist, creates the skill with a decision guide, documents it in your workspace, and restarts the gateway:

```bash
sudo vps-harden \
  --username deploy \
  --ssh-key ~/.ssh/authorized_keys \
  --only monitoring \
  --openclaw-skill
```

This will:
1. Ensure the monitoring stack is installed (auditd, logwatch, server-report)
2. Add `server-report` to `tools.exec.safeBins` in `openclaw.json`
3. Create a skill at `~/.openclaw/workspace/skills/server-report/SKILL.md` that teaches the bot when to use each subcommand
4. Add documentation to `~/.openclaw/workspace/TOOLS.md`
5. Restart the OpenClaw gateway to pick up the changes

After this, your bot will respond to messages like:
- "How's the server?" — runs `summary`, sends output directly
- "Any attacks?" — runs `auth`, summarizes key findings
- "Any suspicious config changes?" — runs `audit`, summarizes by key

> **Note:** Requires OpenClaw to be installed and configured at `~/.openclaw/` for the target user. The flag is silently skipped if OpenClaw is not found.

## What's next

- Use your [SOPS + age](https://github.com/getsops/sops) keypair for encrypted secrets (the script installed both and generated a keypair for you — check `~/.config/sops/age/keys.txt`)
- Configure logwatch to email daily reports (edit `/etc/logwatch/conf/logwatch.conf`, set `Output = mail` and `MailTo = you@example.com`)
- Set up a backup strategy for your VPS configuration
- Review the [README](../README.md) for the full parameter and module reference
