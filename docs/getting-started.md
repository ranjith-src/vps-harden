# Getting Started

This guide walks you through hardening a fresh VPS from first SSH login to a fully verified setup. It takes about 10 minutes.

## What you'll need

Before you start, have these ready:

| Item | Required | Where to get it |
|------|----------|-----------------|
| A VPS running **Debian 11+** or **Ubuntu 20.04+** | Yes | Any provider (Hetzner, DigitalOcean, Linode, etc.) |
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

## Step 3: Dry run first

**Always preview before applying.** The dry run shows exactly what would change without touching anything:

```bash
sudo vps-harden \
  --username deploy \
  --ssh-key "ssh-ed25519 AAAA... your-email@example.com" \
  --ssh-safety-ip YOUR_LOCAL_IP \
  --timezone UTC \
  --dry-run
```

Replace:
- `deploy` with your preferred non-root username
- `ssh-ed25519 AAAA...` with your actual public key (or a path to the file)
- `YOUR_LOCAL_IP` with your current IP (from `curl -s ifconfig.me`)

You'll see output like:

```
[DRY] Would: run: apt-get install -y -qq tree unzip fail2ban
[DRY] Would: write /etc/ssh/sshd_config.d/00-hardening.conf (mode=644)
[DRY] Would: run: ufw --force enable
...
```

Review this output. Every change is listed. Nothing has been modified yet.

## Step 4: Apply

Once you're comfortable with the dry run output, run it for real:

```bash
sudo vps-harden \
  --username deploy \
  --ssh-key "ssh-ed25519 AAAA... your-email@example.com" \
  --ssh-safety-ip YOUR_LOCAL_IP \
  --timezone UTC
```

Here's what each module does and why:

| Step | Module | What it does | Why |
|------|--------|-------------|-----|
| 1 | `prereqs` | Installs foundational packages (curl, wget, jq, htop, ufw, fail2ban) | These are dependencies for the rest of the script and useful for day-to-day admin |
| 2 | `user` | Creates a non-root user with sudo access and deploys your SSH key | Running as root is dangerous — a typo can destroy the system. A dedicated user with sudo gives you the same power with an audit trail |
| 3 | `ssh` | Disables root login, limits auth attempts to 3, restricts SSH to your user only, adds a warning banner | SSH is the #1 attack surface on any VPS. Brute-force bots will find your server within minutes of it going online |
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

> **Tip:** If a module fails, the script will continue with the remaining modules (except for the critical `user` and `ssh` modules, which abort on failure to prevent lockout).

## Step 5: Test SSH access (important!)

**Before closing your current session**, open a **new terminal** and test:

```bash
ssh deploy@YOUR_VPS_IP
```

If this works, you're good. If it doesn't, you still have your original session to fix things.

Once confirmed:
- You can now `sudo` as `deploy` for any admin tasks
- Direct root SSH login is disabled
- Password authentication is disabled (key-only)

## Step 6: Read the scorecard

At the end of the run, you'll see something like:

```
====================================================================
               VPS SECURITY SCORECARD
====================================================================
  [PASS] PermitRootLogin = no
  [PASS] MaxAuthTries = 3
  [PASS] UFW active, default deny
  [PASS] fail2ban sshd jail active
  [PASS] SYN cookies enabled
  [PASS] auditd active
  [PASS] Audit rules loaded (13 rules)
  [PASS] logwatch installed
  [PASS] server-report installed
  [WARN] Netbird not installed
  ...
--------------------------------------------------------------------
  SCORE: 20 PASSED | 2 WARNING | 0 FAILED
--------------------------------------------------------------------
```

- **PASS** — correctly configured, no action needed
- **WARN** — not critical, but review (e.g. Netbird not set up is fine if you don't need VPN)
- **FAIL** — something needs fixing. The label explains what's wrong

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
