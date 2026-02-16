#!/usr/bin/env bash
# vps-harden.sh — Idempotent VPS security hardening script
# https://github.com/ranjith-src/vps-harden
# Usage: sudo ./vps-harden.sh --username USER --ssh-key KEY [options]
set -euo pipefail

# ── Constants ────────────────────────────────────────────────────────────────
readonly SCRIPT_VERSION="1.3.0"
LOG_FILE="/var/log/vps-harden-$(date +%Y%m%d-%H%M%S).log"
readonly LOG_FILE
readonly ALL_MODULES="prereqs user ssh firewall fail2ban sysctl netbird firewall_tighten sops upgrades monitoring shell misc verify"
readonly SOPS_FALLBACK_VERSION="3.9.4"

# ── Color output ─────────────────────────────────────────────────────────────
USE_COLOR="true"
RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; NC=''
setup_colors() {
    if [[ "$USE_COLOR" == "true" ]] && [[ -t 1 ]]; then
        RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
        CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
    else
        RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; NC=''
    fi
}

# ── Scorecard tracking ──────────────────────────────────────────────────────
declare -a SC_LABELS=()
declare -a SC_RESULTS=()
SC_PASS=0; SC_WARN=0; SC_FAIL=0

sc_add() {
    local result="$1" label="$2"
    SC_LABELS+=("$label")
    SC_RESULTS+=("$result")
    case "$result" in
        PASS) ((SC_PASS++)) ;;
        WARN) ((SC_WARN++)) ;;
        FAIL) ((SC_FAIL++)) ;;
    esac
}

# ── Logging ──────────────────────────────────────────────────────────────────
log_init() {
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
    log_info "vps-harden.sh v${SCRIPT_VERSION} started at $(date -Iseconds)"
    log_info "Log file: $LOG_FILE"
}

log_raw() { echo "$1" >> "$LOG_FILE"; }

log_info()  { echo -e "${GREEN}[+]${NC} $1"; log_raw "[+] $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; log_raw "[!] $1"; }
log_fail()  { echo -e "${RED}[-]${NC} $1"; log_raw "[-] $1"; }
log_header(){ echo -e "\n${BOLD}${CYAN}=== $1 ===${NC}"; log_raw "=== $1 ==="; }
log_dry()   { echo -e "${CYAN}[DRY]${NC} Would: $1"; log_raw "[DRY] $1"; }

die() { log_fail "$1"; exit 1; }

# ── Detect SSH client IP ─────────────────────────────────────────────────
detect_ssh_client_ip() {
    local ip=""
    # Method 1: SSH_CLIENT env var (often stripped by sudo env_reset)
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        ip=$(echo "$SSH_CLIENT" | awk '{print $1}')
    fi
    # Method 2: who am i (works through sudo on most systems)
    if [[ -z "$ip" ]]; then
        ip=$(who am i 2>/dev/null | grep -oE '\(([0-9]{1,3}\.){3}[0-9]{1,3}\)' | tr -d '()' || true)
    fi
    # Method 3: ss — query kernel socket table for established SSH connections
    if [[ -z "$ip" ]]; then
        ip=$(ss -tnp 2>/dev/null | grep ":22 " | grep "ESTAB" | awk '{print $5}' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true)
    fi
    echo "$ip"
}

# ── Trap handler ─────────────────────────────────────────────────────────────
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        echo ""
        echo -e "${RED}Aborted.${NC} Log file: ${LOG_FILE}"
    fi
    exit "$exit_code"
}
trap cleanup SIGINT SIGTERM ERR

# ── Dry-run wrappers ────────────────────────────────────────────────────────
VERBOSE="false"

run_cmd() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log_dry "run: $*"
        return 0
    fi
    log_raw "[CMD] $*"
    if [[ "$VERBOSE" == "true" ]]; then
        DEBIAN_FRONTEND=noninteractive "$@" 2>&1 | tee -a "$LOG_FILE"
    else
        DEBIAN_FRONTEND=noninteractive "$@" >> "$LOG_FILE" 2>&1
    fi
}

write_file() {
    local dest="$1" mode="${2:-644}" owner="${3:-root:root}"
    local content
    content=$(cat)
    if [[ "$DRY_RUN" == "true" ]]; then
        log_dry "write $dest (mode=$mode owner=$owner)"
        echo "$content" | head -5 | while IFS= read -r line; do
            log_dry "  $line"
        done
        [[ $(echo "$content" | wc -l) -gt 5 ]] && log_dry "  ... (truncated)"
        return 0
    fi
    echo "$content" > "$dest"
    chmod "$mode" "$dest"
    chown "$owner" "$dest"
    log_info "Wrote $dest (mode=$mode owner=$owner)"
}

# ── Defaults ─────────────────────────────────────────────────────────────────
USERNAME=""
SSH_KEY=""
SSH_SAFETY_IP=""
NETBIRD_KEY=""
TIMEZONE=""
SET_HOSTNAME=""
AUTO_REBOOT="false"
OPENCLAW_SKILL="false"
SKIP_MODULES=""
ONLY_MODULES=""
DRY_RUN="false"
INTERACTIVE="false"
CONFIG_FILE=""
SSH_KEY_CONTENT=""

# ── Distro detection ────────────────────────────────────────────────────────
check_distro() {
    if [[ ! -f /etc/os-release ]]; then
        die "Cannot detect distro: /etc/os-release not found"
    fi
    # shellcheck source=/dev/null
    source /etc/os-release
    case "${ID:-}" in
        ubuntu|debian)
            log_info "Detected distro: ${PRETTY_NAME:-$ID}"
            ;;
        *)
            die "Unsupported distro: ${PRETTY_NAME:-$ID}. This script supports Debian and Ubuntu only."
            ;;
    esac
}

# ── Architecture detection ──────────────────────────────────────────────────
detect_arch() {
    local machine
    machine=$(uname -m)
    case "$machine" in
        x86_64)  echo "amd64" ;;
        aarch64) echo "arm64" ;;
        *)       die "Unsupported architecture: $machine" ;;
    esac
}

# ── SSH service detection ───────────────────────────────────────────────────
detect_ssh_service() {
    if systemctl list-unit-files ssh.service &>/dev/null && systemctl cat ssh.service &>/dev/null; then
        echo "ssh"
    elif systemctl list-unit-files sshd.service &>/dev/null && systemctl cat sshd.service &>/dev/null; then
        echo "sshd"
    else
        echo "ssh"  # fallback
    fi
}

# ── Argument parsing ────────────────────────────────────────────────────────
usage() {
    cat <<'USAGE'
Usage: sudo vps-harden [options]
       sudo vps-harden --username USER --ssh-key KEY [options]

If run without --username and --ssh-key, an interactive setup wizard
guides you through each step with auto-detection and sensible defaults.

Required (or use interactive wizard):
  --username USER        Non-root user to create/harden
  --ssh-key KEY          SSH public key (file path or inline string)

Optional:
  --interactive          Force interactive setup wizard
  --ssh-safety-ip IP     IP to always allow SSH from (safety net)
  --netbird-key KEY      Netbird setup key (skip VPN if omitted)
  --timezone TZ          Set system timezone (e.g. Europe/Amsterdam)
  --hostname NAME        Set hostname
  --auto-reboot          Enable auto-reboot for kernel updates
  --openclaw-skill       Add server-report skill to OpenClaw bot
  --skip MOD[,MOD]       Comma-separated modules to skip
  --only MOD[,MOD]       Only run specified modules (comma-separated)
  --dry-run              Show what would change, change nothing
  --config FILE          Read params from KEY=VALUE file
  --no-color             Disable colored output
  --verbose              Show command output instead of redirecting to log
  --version              Print version and exit
  -h, --help             Show this help

Modules (execution order):
  prereqs user ssh firewall fail2ban sysctl netbird firewall_tighten
  sops upgrades monitoring shell misc verify

Examples:
  # Interactive wizard (recommended for first run):
  sudo ./vps-harden.sh

  # New VPS:
  sudo vps-harden --username deploy \
    --ssh-key "ssh-ed25519 AAAA..." --netbird-key "nbs-XXXX" \
    --ssh-safety-ip 203.0.113.10 --timezone Europe/Amsterdam

  # Existing VPS (verify/fix):
  sudo vps-harden --username deploy \
    --ssh-key ~/.ssh/authorized_keys

  # Dry run:
  sudo vps-harden --username deploy \
    --ssh-key ~/.ssh/authorized_keys --dry-run

  # Add server-report to OpenClaw bot:
  sudo vps-harden --username deploy \
    --ssh-key ~/.ssh/authorized_keys --only monitoring --openclaw-skill
USAGE
    exit 0
}

parse_config_file() {
    local file="$1"
    [[ -f "$file" ]] || die "Config file not found: $file"
    while IFS='=' read -r key value; do
        [[ -z "$key" || "$key" =~ ^# ]] && continue
        key=$(echo "$key" | tr -d '[:space:]')
        value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed 's/^["'\'']//;s/["'\'']$//')
        case "$key" in
            username)       USERNAME="$value" ;;
            ssh_key)        SSH_KEY="$value" ;;
            ssh_safety_ip)  SSH_SAFETY_IP="$value" ;;
            netbird_key)    NETBIRD_KEY="$value" ;;
            timezone)       TIMEZONE="$value" ;;
            hostname)       SET_HOSTNAME="$value" ;;
            auto_reboot)    AUTO_REBOOT="$value" ;;
            openclaw_skill) OPENCLAW_SKILL="$value" ;;
            skip)           SKIP_MODULES="$value" ;;
            only)           ONLY_MODULES="$value" ;;
        esac
    done < "$file"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --username)       USERNAME="$2"; shift 2 ;;
            --ssh-key)        SSH_KEY="$2"; shift 2 ;;
            --ssh-safety-ip)  SSH_SAFETY_IP="$2"; shift 2 ;;
            --netbird-key)    NETBIRD_KEY="$2"; shift 2 ;;
            --timezone)       TIMEZONE="$2"; shift 2 ;;
            --hostname)       SET_HOSTNAME="$2"; shift 2 ;;
            --auto-reboot)    AUTO_REBOOT="true"; shift ;;
            --openclaw-skill) OPENCLAW_SKILL="true"; shift ;;
            --skip)           SKIP_MODULES="$2"; shift 2 ;;
            --only)           ONLY_MODULES="$2"; shift 2 ;;
            --interactive)    INTERACTIVE="true"; shift ;;
            --dry-run)        DRY_RUN="true"; shift ;;
            --config)         CONFIG_FILE="$2"; shift 2 ;;
            --no-color)       USE_COLOR="false"; shift ;;
            --verbose)        VERBOSE="true"; shift ;;
            --version)        echo "vps-harden v${SCRIPT_VERSION}"; exit 0 ;;
            -h|--help)        usage ;;
            *) die "Unknown argument: $1" ;;
        esac
    done
}

validate_args() {
    [[ $(id -u) -eq 0 ]] || die "This script must be run as root (use sudo)"
    [[ -n "$USERNAME" ]] || die "--username is required"
    [[ -n "$SSH_KEY" ]] || die "--ssh-key is required"

    # Resolve SSH key — could be a file path or inline key
    # Skip if the wizard already resolved SSH_KEY_CONTENT
    if [[ -z "$SSH_KEY_CONTENT" ]]; then
        if [[ -f "$SSH_KEY" ]]; then
            SSH_KEY_CONTENT=$(cat "$SSH_KEY")
        else
            SSH_KEY_CONTENT="$SSH_KEY"
        fi
    fi
    [[ "$SSH_KEY_CONTENT" =~ ^ssh- ]] || die "--ssh-key must be a file with SSH keys or an inline ssh-* public key"
}

should_run() {
    local mod="$1"
    if [[ -n "$ONLY_MODULES" ]]; then
        echo ",$ONLY_MODULES," | grep -q ",$mod," && return 0 || return 1
    fi
    if [[ -n "$SKIP_MODULES" ]]; then
        echo ",$SKIP_MODULES," | grep -q ",$mod," && return 1 || return 0
    fi
    return 0
}

# ── SSH lockout protection ──────────────────────────────────────────────────
verify_ssh_access() {
    local user="$1"
    local errors=0

    # Check authorized_keys exist
    local auth_keys="/home/${user}/.ssh/authorized_keys"
    if [[ -f "$auth_keys" ]] && [[ -s "$auth_keys" ]]; then
        log_info "SSH keys present in $auth_keys"
    else
        log_fail "No SSH keys found in $auth_keys — aborting to prevent lockout"
        ((errors++))
    fi

    # Validate sshd config
    if sshd -t 2>/dev/null; then
        log_info "sshd config syntax OK"
    else
        log_fail "sshd config syntax error — aborting to prevent lockout"
        ((errors++))
    fi

    # Check AllowUsers includes our user (if AllowUsers is set)
    local effective_allow
    effective_allow=$(sshd -T 2>/dev/null | grep "^allowusers " | awk '{print $2}' || true)
    if [[ -n "$effective_allow" ]]; then
        if echo "$effective_allow" | grep -qw "$user"; then
            log_info "AllowUsers includes $user"
        else
            log_fail "AllowUsers is set but does not include $user — aborting to prevent lockout"
            ((errors++))
        fi
    fi

    # Check UFW has at least one SSH rule (if UFW is active)
    if command -v ufw &>/dev/null && ufw status | grep -q "^Status: active"; then
        if ufw status | grep -qE "22/(tcp|udp)|OpenSSH"; then
            log_info "UFW has SSH allow rule"
        else
            log_fail "UFW is active but no SSH rule found — aborting to prevent lockout"
            ((errors++))
        fi
    fi

    [[ $errors -eq 0 ]] && return 0 || return 1
}

# ── Module: prereqs ─────────────────────────────────────────────────────────
mod_prereqs() {
    log_header "Module: prereqs"
    local pkgs=(curl wget jq htop tree unzip ufw fail2ban)
    local to_install=()

    for pkg in "${pkgs[@]}"; do
        if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            log_info "$pkg already installed"
        else
            to_install+=("$pkg")
        fi
    done

    if [[ ${#to_install[@]} -gt 0 ]]; then
        log_info "Installing: ${to_install[*]}"
        run_cmd apt-get update -qq
        run_cmd apt-get install -y -qq "${to_install[@]}"
    else
        log_info "All prerequisite packages already installed"
    fi
}

# ── Module: user ─────────────────────────────────────────────────────────────
mod_user() {
    log_header "Module: user"

    if id "$USERNAME" &>/dev/null; then
        log_info "User $USERNAME already exists"
    else
        log_info "Creating user $USERNAME"
        run_cmd useradd -m -s /bin/bash "$USERNAME"
    fi

    # Ensure sudo group membership
    if groups "$USERNAME" | grep -qw sudo; then
        log_info "$USERNAME already in sudo group"
    else
        log_info "Adding $USERNAME to sudo group"
        run_cmd usermod -aG sudo "$USERNAME"
    fi

    # Deploy SSH keys
    local ssh_dir="/home/${USERNAME}/.ssh"
    local auth_file="${ssh_dir}/authorized_keys"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_dry "Ensure $ssh_dir exists, deploy SSH key to $auth_file"
    else
        mkdir -p "$ssh_dir"
        chmod 700 "$ssh_dir"

        # Append keys that aren't already present
        touch "$auth_file"
        while IFS= read -r key_line; do
            [[ -z "$key_line" || "$key_line" =~ ^# ]] && continue
            if grep -qF "$key_line" "$auth_file" 2>/dev/null; then
                log_info "SSH key already in authorized_keys ($(echo "$key_line" | awk '{print $NF}'))"
            else
                echo "$key_line" >> "$auth_file"
                log_info "Added SSH key ($(echo "$key_line" | awk '{print $NF}'))"
            fi
        done <<< "$SSH_KEY_CONTENT"

        chmod 600 "$auth_file"
        chown -R "${USERNAME}:${USERNAME}" "$ssh_dir"
    fi
}

# ── Module: ssh ──────────────────────────────────────────────────────────────
mod_ssh() {
    log_header "Module: ssh"

    local ssh_svc
    ssh_svc=$(detect_ssh_service)
    local conf="/etc/ssh/sshd_config.d/00-hardening.conf"
    local banner="/etc/ssh/banner.txt"
    local needs_restart=false

    # Remove old 99-hardening.conf if it exists (renamed to 00-)
    if [[ -f "/etc/ssh/sshd_config.d/99-hardening.conf" ]]; then
        log_info "Removing old 99-hardening.conf (renamed to 00-hardening.conf)"
        rm -f "/etc/ssh/sshd_config.d/99-hardening.conf"
        needs_restart=true
    fi

    # Write hardening config
    local desired_config
    desired_config=$(cat <<SSHEOF
# VPS hardening — managed by vps-harden.sh
PermitRootLogin no
MaxAuthTries 3
AllowUsers ${USERNAME}
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 3
PermitEmptyPasswords no
MaxSessions 3
LoginGraceTime 30
Banner /etc/ssh/banner.txt
SSHEOF
)

    if [[ -f "$conf" ]] && diff -q <(echo "$desired_config") "$conf" &>/dev/null; then
        log_info "SSH hardening config already correct"
    else
        echo "$desired_config" | write_file "$conf" 644
        needs_restart=true
    fi

    # Write SSH banner
    local banner_text
    banner_text=$(cat <<'BANEOF'
*******************************************************************
  NOTICE: This system is for authorized use only.
  All activity is monitored and logged.
*******************************************************************
BANEOF
)

    if [[ -f "$banner" ]] && diff -q <(echo "$banner_text") "$banner" &>/dev/null; then
        log_info "SSH banner already correct"
    else
        echo "$banner_text" | write_file "$banner" 644
        needs_restart=true
    fi

    # Validate before restarting
    if [[ "$needs_restart" == "true" && "$DRY_RUN" != "true" ]]; then
        if sshd -t 2>/dev/null; then
            log_info "sshd config syntax OK — restarting $ssh_svc"
            if ! verify_ssh_access "$USERNAME"; then
                log_fail "Lockout protection triggered — rolling back SSH config"
                rm -f "$conf"
                systemctl reload "$ssh_svc" 2>/dev/null || true
                die "SSH config rolled back to prevent lockout"
            fi
            run_cmd systemctl reload "$ssh_svc"
        else
            log_fail "sshd config syntax error — rolling back"
            rm -f "$conf"
            die "SSH config had syntax errors, removed $conf"
        fi
    fi
}

# ── Module: firewall ─────────────────────────────────────────────────────────
mod_firewall() {
    log_header "Module: firewall"

    # Set defaults
    run_cmd ufw default deny incoming
    run_cmd ufw default allow outgoing

    # Ensure SSH is allowed before enabling
    if ufw status | grep -qE "22/tcp.*ALLOW"; then
        log_info "SSH (22/tcp) already allowed"
    else
        log_info "Allowing SSH (22/tcp)"
        run_cmd ufw allow 22/tcp
    fi

    # Enable UFW
    if ufw status | grep -q "^Status: active"; then
        log_info "UFW already active"
    else
        log_info "Enabling UFW"
        if [[ "$DRY_RUN" == "true" ]]; then
            log_dry "ufw --force enable"
        else
            ufw --force enable >> "$LOG_FILE" 2>&1
        fi
    fi
}

# ── Module: fail2ban ─────────────────────────────────────────────────────────
mod_fail2ban() {
    log_header "Module: fail2ban"

    local jail_conf="/etc/fail2ban/jail.local"
    local desired_jail
    desired_jail=$(cat <<'F2BEOF'
# VPS hardening — managed by vps-harden.sh
[DEFAULT]
banaction = ufw

[sshd]
enabled  = true
maxretry = 3
bantime  = 3h
findtime = 10m
F2BEOF
)

    if ! command -v fail2ban-client &>/dev/null; then
        log_info "Installing fail2ban"
        run_cmd apt-get install -y -qq fail2ban
    else
        log_info "fail2ban already installed"
    fi

    if [[ -f "$jail_conf" ]] && diff -q <(echo "$desired_jail") "$jail_conf" &>/dev/null; then
        log_info "fail2ban jail config already correct"
    else
        echo "$desired_jail" | write_file "$jail_conf" 644
        if [[ "$DRY_RUN" != "true" ]]; then
            run_cmd systemctl enable fail2ban
            run_cmd systemctl restart fail2ban
        fi
    fi
}

# ── Module: sysctl ───────────────────────────────────────────────────────────
mod_sysctl() {
    log_header "Module: sysctl"

    local sysctl_conf="/etc/sysctl.d/99-zz-hardening.conf"

    # Remove old 99-hardening.conf if it exists (renamed to 99-zz- to sort after 99-sysctl.conf)
    if [[ -f "/etc/sysctl.d/99-hardening.conf" ]]; then
        log_info "Removing old 99-hardening.conf (renamed to 99-zz-hardening.conf)"
        rm -f "/etc/sysctl.d/99-hardening.conf"
    fi

    local desired_sysctl
    desired_sysctl=$(cat <<'SYSEOF'
# VPS hardening — managed by vps-harden.sh
# SYN flood protection
net.ipv4.tcp_syncookies = 1

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log martian packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore broadcast ICMP
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
SYSEOF
)

    if [[ -f "$sysctl_conf" ]] && diff -q <(echo "$desired_sysctl") "$sysctl_conf" &>/dev/null; then
        log_info "Kernel hardening sysctl already correct"
    else
        echo "$desired_sysctl" | write_file "$sysctl_conf" 644
        if [[ "$DRY_RUN" != "true" ]]; then
            run_cmd sysctl --system
        fi
    fi
}

# ── Module: netbird ──────────────────────────────────────────────────────────
mod_netbird() {
    log_header "Module: netbird"

    if [[ -z "$NETBIRD_KEY" ]]; then
        log_info "No --netbird-key provided, skipping Netbird setup"
        return 0
    fi

    # Install if missing
    if ! command -v netbird &>/dev/null; then
        log_info "Installing Netbird"
        if [[ "$DRY_RUN" == "true" ]]; then
            log_dry "curl + install Netbird"
        else
            curl -fsSL https://pkgs.netbird.io/install.sh | bash >> "$LOG_FILE" 2>&1
        fi
    else
        log_info "Netbird already installed"
    fi

    # Check connection status
    local nb_status
    nb_status=$(netbird status 2>/dev/null | head -1 || echo "unknown")

    if echo "$nb_status" | grep -qi "connected"; then
        log_info "Netbird already connected"
    else
        log_info "Connecting Netbird with setup key"
        run_cmd netbird up --setup-key "$NETBIRD_KEY"

        if [[ "$DRY_RUN" != "true" ]]; then
            # Wait for tunnel
            local attempts=0
            while [[ $attempts -lt 30 ]]; do
                if ip link show wt0 &>/dev/null; then
                    log_info "Netbird tunnel (wt0) is up"
                    break
                fi
                sleep 1
                ((attempts++))
            done
            if [[ $attempts -ge 30 ]]; then
                log_warn "Netbird tunnel did not come up within 30s"
            fi
        fi
    fi

    # Ensure service enabled
    run_cmd systemctl enable netbird 2>/dev/null || true
}

# ── Module: firewall_tighten ─────────────────────────────────────────────────
mod_firewall_tighten() {
    log_header "Module: firewall_tighten"

    # Allow all traffic on Netbird tunnel interface
    if ip link show wt0 &>/dev/null; then
        if ufw status | grep -q "Anywhere on wt0"; then
            log_info "UFW already allows traffic on wt0"
        else
            log_info "Allowing all traffic on wt0 (Netbird tunnel)"
            run_cmd ufw allow in on wt0
        fi
    else
        log_warn "wt0 interface not found — skipping tunnel firewall rules"
        log_warn "Run again after Netbird is connected to tighten firewall"
        return 0
    fi

    # Allow SSH from safety IP if specified
    if [[ -n "$SSH_SAFETY_IP" ]]; then
        if ufw status | grep -q "$SSH_SAFETY_IP"; then
            log_info "SSH safety rule for $SSH_SAFETY_IP already exists"
        else
            log_info "Allowing SSH from safety IP $SSH_SAFETY_IP"
            run_cmd ufw allow from "$SSH_SAFETY_IP" to any port 22 proto tcp
        fi
    fi

    # Remove broad 22/tcp rule (Anywhere) if tunnel + safety IP are in place
    local has_tunnel has_safety
    has_tunnel=$(ufw status | grep -c "wt0" || true)
    has_safety=1
    [[ -n "$SSH_SAFETY_IP" ]] && has_safety=$(ufw status | grep -c "$SSH_SAFETY_IP" || true)

    if [[ $has_tunnel -gt 0 && $has_safety -gt 0 ]]; then
        # Check for broad 22/tcp ALLOW Anywhere rules
        local broad_rules
        broad_rules=$(ufw status numbered | grep "22/tcp" | grep "Anywhere" | grep -v "v6" | grep -v "$SSH_SAFETY_IP" || true)
        if [[ -n "$broad_rules" ]]; then
            log_info "Removing broad 22/tcp Anywhere rule (tunnel + safety IP in place)"
            if [[ "$DRY_RUN" == "true" ]]; then
                log_dry "ufw delete allow 22/tcp"
            else
                ufw delete allow 22/tcp >> "$LOG_FILE" 2>&1 || true
            fi
        else
            log_info "No broad 22/tcp rule to remove"
        fi
    else
        log_warn "Not removing broad SSH rule — tunnel or safety IP not confirmed"
    fi
}

# ── Module: sops ─────────────────────────────────────────────────────────────
mod_sops() {
    log_header "Module: sops"

    local user_home="/home/${USERNAME}"

    # Install age if missing
    if ! command -v age &>/dev/null; then
        log_info "Installing age"
        run_cmd apt-get install -y -qq age
    else
        log_info "age already installed"
    fi

    # Install sops if missing
    if ! command -v sops &>/dev/null; then
        log_info "Installing SOPS"
        if [[ "$DRY_RUN" == "true" ]]; then
            log_dry "Download and install SOPS binary"
        else
            local arch
            arch=$(detect_arch)
            local sops_version
            # Try to fetch latest version from GitHub API
            sops_version=$(curl -fsSL "https://api.github.com/repos/getsops/sops/releases/latest" 2>/dev/null \
                | grep '"tag_name"' | sed 's/.*"v\(.*\)".*/\1/' || true)
            if [[ -z "$sops_version" ]]; then
                sops_version="$SOPS_FALLBACK_VERSION"
                log_warn "Could not fetch latest SOPS version, using fallback v${sops_version}"
            else
                log_info "Fetched latest SOPS version: v${sops_version}"
            fi
            local sops_url="https://github.com/getsops/sops/releases/download/v${sops_version}/sops-v${sops_version}.linux.${arch}"
            curl -fsSL "$sops_url" -o /usr/local/bin/sops
            chmod 755 /usr/local/bin/sops
        fi
    else
        log_info "SOPS already installed"
    fi

    # Generate age keypair if missing
    local age_dir="${user_home}/.config/sops/age"
    local age_key="${age_dir}/keys.txt"
    if [[ -f "$age_key" ]]; then
        log_info "age keypair already exists at $age_key"
    else
        if [[ "$DRY_RUN" == "true" ]]; then
            log_dry "Generate age keypair at $age_key"
        else
            mkdir -p "$age_dir"
            age-keygen -o "$age_key" 2>/dev/null
            chmod 600 "$age_key"
            chown -R "${USERNAME}:${USERNAME}" "${user_home}/.config"
            log_info "Generated age keypair at $age_key"
            local pub_key
            pub_key=$(grep "^# public key:" "$age_key" | awk '{print $NF}')
            log_info "age public key: $pub_key"
        fi
    fi

    # Create .sops.yaml scaffold if missing
    local sops_yaml="${user_home}/.sops.yaml"
    if [[ -f "$sops_yaml" ]]; then
        log_info ".sops.yaml already exists"
    else
        local pub_key=""
        if [[ -f "$age_key" ]]; then
            pub_key=$(grep "^# public key:" "$age_key" | awk '{print $NF}')
        fi
        cat <<SOPSEOF | write_file "$sops_yaml" 644 "${USERNAME}:${USERNAME}"
# SOPS config — edit age recipient to match your key
creation_rules:
  - path_regex: '\.enc\.(env|json|yaml)$'
    age: '${pub_key:-INSERT_YOUR_AGE_PUBLIC_KEY}'
SOPSEOF
    fi
}

# ── Module: upgrades ─────────────────────────────────────────────────────────
mod_upgrades() {
    log_header "Module: upgrades"

    # Install unattended-upgrades if missing
    if dpkg -l unattended-upgrades 2>/dev/null | grep -q "^ii"; then
        log_info "unattended-upgrades already installed"
    else
        log_info "Installing unattended-upgrades"
        run_cmd apt-get install -y -qq unattended-upgrades
    fi

    # Enable
    if [[ "$DRY_RUN" != "true" ]]; then
        run_cmd dpkg-reconfigure -plow unattended-upgrades 2>/dev/null || true
    fi

    # Auto-reboot if requested
    local reboot_conf="/etc/apt/apt.conf.d/50unattended-upgrades"
    if [[ "$AUTO_REBOOT" == "true" ]]; then
        if grep -q 'Unattended-Upgrade::Automatic-Reboot "true"' "$reboot_conf" 2>/dev/null; then
            log_info "Auto-reboot already enabled"
        else
            log_info "Enabling auto-reboot for kernel updates"
            if [[ "$DRY_RUN" == "true" ]]; then
                log_dry "Set Automatic-Reboot true in $reboot_conf"
            else
                sed -i 's|//Unattended-Upgrade::Automatic-Reboot "false";|Unattended-Upgrade::Automatic-Reboot "true";|' "$reboot_conf" 2>/dev/null || \
                    echo 'Unattended-Upgrade::Automatic-Reboot "true";' >> "$reboot_conf"
            fi
        fi
    fi
}

# ── Module: monitoring ───────────────────────────────────────────────────────
mod_monitoring() {
    log_header "Module: monitoring"

    # ── Install auditd + logwatch ────────────────────────────────────────
    local pkgs=(auditd audispd-plugins logwatch)
    local to_install=()

    for pkg in "${pkgs[@]}"; do
        if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            log_info "$pkg already installed"
        else
            to_install+=("$pkg")
        fi
    done

    if [[ ${#to_install[@]} -gt 0 ]]; then
        log_info "Installing: ${to_install[*]}"
        run_cmd apt-get update -qq
        run_cmd apt-get install -y -qq "${to_install[@]}"
    fi

    # ── Audit rules ──────────────────────────────────────────────────────
    local audit_rules="/etc/audit/rules.d/vps-harden.rules"
    local desired_rules
    desired_rules=$(cat <<'AUDITEOF'
## vps-harden.sh — audit rules

# SSH config changes
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/ssh/sshd_config.d/ -p wa -k ssh_config

# User/password database
-w /etc/passwd -p wa -k user_db
-w /etc/shadow -p wa -k user_db
-w /etc/group -p wa -k user_db
-w /etc/gshadow -p wa -k user_db

# Sudoers changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# Firewall config
-w /etc/ufw/ -p wa -k firewall_config

# Cron changes
-w /etc/crontab -p wa -k cron_changes
-w /etc/cron.d/ -p wa -k cron_changes
-w /var/spool/cron/ -p wa -k cron_changes

# Privilege escalation
-a always,exit -F arch=b64 -S setuid -S setgid -k priv_esc
AUDITEOF
)

    if [[ -f "$audit_rules" ]] && diff -q <(echo "$desired_rules") "$audit_rules" &>/dev/null; then
        log_info "Audit rules already correct"
    else
        echo "$desired_rules" | write_file "$audit_rules" 640
        if [[ "$DRY_RUN" != "true" ]]; then
            run_cmd systemctl enable auditd
            run_cmd systemctl restart auditd
            # Reload rules (augenrules merges rules.d/ into audit.rules)
            run_cmd augenrules --load
        fi
    fi

    # ── Logwatch config ──────────────────────────────────────────────────
    local logwatch_conf="/etc/logwatch/conf/logwatch.conf"
    local desired_logwatch
    desired_logwatch=$(cat <<'LWEOF'
# vps-harden.sh — logwatch configuration
Output = stdout
Format = text
Detail = Low
Range = yesterday
Service = All
LWEOF
)

    if [[ "$DRY_RUN" != "true" ]]; then
        mkdir -p /etc/logwatch/conf
    fi

    if [[ -f "$logwatch_conf" ]] && diff -q <(echo "$desired_logwatch") "$logwatch_conf" &>/dev/null; then
        log_info "Logwatch config already correct"
    else
        echo "$desired_logwatch" | write_file "$logwatch_conf" 644
    fi

    # ── Install server-report ────────────────────────────────────────────
    local report_src
    report_src="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/server-report"
    local report_dest="/usr/local/bin/server-report"

    if [[ -f "$report_src" ]]; then
        if [[ -f "$report_dest" ]] && diff -q "$report_src" "$report_dest" &>/dev/null; then
            log_info "server-report already installed and up-to-date"
        else
            if [[ "$DRY_RUN" == "true" ]]; then
                log_dry "Install server-report to $report_dest"
            else
                cp "$report_src" "$report_dest"
                chmod 755 "$report_dest"
                chown root:root "$report_dest"
                log_info "Installed server-report to $report_dest"
            fi
        fi
    else
        log_warn "server-report source not found at $report_src — skipping install"
    fi

    # ── Sudoers rule ─────────────────────────────────────────────────────
    local sudoers_file="/etc/sudoers.d/server-report"
    local desired_sudoers="${USERNAME} ALL=(root) NOPASSWD: /usr/local/bin/server-report"

    if [[ -f "$sudoers_file" ]] && grep -qF "$desired_sudoers" "$sudoers_file" 2>/dev/null; then
        log_info "Sudoers rule for server-report already exists"
    else
        if [[ "$DRY_RUN" == "true" ]]; then
            log_dry "Write sudoers rule to $sudoers_file"
        else
            echo "$desired_sudoers" > "$sudoers_file"
            chmod 440 "$sudoers_file"
            chown root:root "$sudoers_file"
            # Validate with visudo
            if visudo -cf "$sudoers_file" &>/dev/null; then
                log_info "Sudoers rule installed and validated"
            else
                log_fail "Sudoers file failed validation — removing"
                rm -f "$sudoers_file"
            fi
        fi
    fi

    # ── OpenClaw skill (optional) ────────────────────────────────────────
    if [[ "$OPENCLAW_SKILL" == "true" ]]; then
        setup_openclaw_skill
    fi
}

# ── OpenClaw skill setup ────────────────────────────────────────────────────
setup_openclaw_skill() {
    log_header "OpenClaw: server-report skill"

    local user_home="/home/${USERNAME}"
    local oc_config="${user_home}/.openclaw/openclaw.json"

    if [[ ! -f "$oc_config" ]]; then
        log_warn "OpenClaw config not found at $oc_config — skipping skill setup"
        return 0
    fi

    # ── Add server-report to safeBins ────────────────────────────────────
    if jq -e '.tools.exec.safeBins | index("server-report")' "$oc_config" &>/dev/null; then
        log_info "server-report already in safeBins"
    else
        if [[ "$DRY_RUN" == "true" ]]; then
            log_dry "Add server-report to safeBins in $oc_config"
        else
            local tmp_config
            tmp_config=$(mktemp)
            if jq '.tools.exec.safeBins += ["server-report"]' "$oc_config" > "$tmp_config" 2>/dev/null; then
                mv "$tmp_config" "$oc_config"
                chown "${USERNAME}:${USERNAME}" "$oc_config"
                chmod 600 "$oc_config"
                log_info "Added server-report to safeBins"
            else
                rm -f "$tmp_config"
                log_warn "Failed to update safeBins — edit $oc_config manually"
            fi
        fi
    fi

    # ── Create skill SKILL.md ────────────────────────────────────────────
    local skill_dir="${user_home}/.openclaw/workspace/skills/server-report"
    local skill_file="${skill_dir}/SKILL.md"

    if [[ -f "$skill_file" ]]; then
        log_info "server-report skill already exists"
    else
        if [[ "$DRY_RUN" == "true" ]]; then
            log_dry "Create skill at $skill_file"
        else
            mkdir -p "$skill_dir"
            cat > "$skill_file" <<'SKILLEOF'
# server-report — VPS Health Monitoring

You have access to the `server-report` tool for checking VPS health.

## Usage

```bash
sudo server-report <command>
```

## Commands

| Command | Use when | Output size |
|---------|----------|-------------|
| `summary` | "How's the server?", general health check | Short — send directly |
| `auth` | "Any attacks?", "Who logged in?", SSH/login questions | Medium — summarize key findings |
| `audit` | "Any config changes?", "Check audit logs" | Medium — summarize by key |
| `full` | "Full report", "Run logwatch" | Long — always summarize, highlight important items only |

## Decision Guide

- **Default / general questions** -> `summary`
- **Security / attack / login questions** -> `auth`
- **Config changes / audit trail** -> `audit`
- **Comprehensive / "everything"** -> `full`

## Output Rules

- `summary` output is compact — send it directly in the chat message as-is
- For `auth`, `audit`, and `full` — read the output, then write a concise summary highlighting:
  - Anything unusual or concerning
  - Key numbers (failed logins, banned IPs, rule violations)
  - Overall status (normal / needs attention / urgent)
- Never send raw `full` output — it's too long for chat

## Examples

User: "how's the server doing?"
-> Run `sudo server-report summary`, send the output directly

User: "anyone trying to break in?"
-> Run `sudo server-report auth`, summarize: "In the last 48h: X failed login attempts from Y unique IPs. Z IPs currently banned by fail2ban. No successful unauthorized logins."

User: "any suspicious changes?"
-> Run `sudo server-report audit`, summarize by key
SKILLEOF
            chown -R "${USERNAME}:${USERNAME}" "$skill_dir"
            log_info "Created skill at $skill_file"
        fi
    fi

    # ── Add to TOOLS.md ──────────────────────────────────────────────────
    local tools_md="${user_home}/.openclaw/workspace/TOOLS.md"

    if [[ -f "$tools_md" ]] && grep -q "server-report" "$tools_md" 2>/dev/null; then
        log_info "server-report already documented in TOOLS.md"
    elif [[ -f "$tools_md" ]]; then
        if [[ "$DRY_RUN" == "true" ]]; then
            log_dry "Append server-report section to $tools_md"
        else
            cat >> "$tools_md" <<'TOOLSEOF'

## Server Monitoring
- **server-report** — VPS health reports via `sudo server-report <command>`
- Subcommands: `summary` (quick health), `auth` (logins/bans), `audit` (audit events), `full` (logwatch)
- Runs via sudo NOPASSWD — no password prompt needed
- See `skills/server-report/SKILL.md` for decision guide on which subcommand to use
TOOLSEOF
            chown "${USERNAME}:${USERNAME}" "$tools_md"
            log_info "Added server-report section to TOOLS.md"
        fi
    else
        log_warn "TOOLS.md not found at $tools_md — skipping"
    fi

    # ── Restart gateway ──────────────────────────────────────────────────
    if [[ "$DRY_RUN" == "true" ]]; then
        log_dry "Restart openclaw-gateway service"
    else
        local uid
        uid=$(id -u "$USERNAME")
        if sudo -u "$USERNAME" XDG_RUNTIME_DIR="/run/user/${uid}" systemctl --user restart openclaw-gateway 2>/dev/null; then
            log_info "Restarted openclaw-gateway"
        else
            log_warn "Could not restart openclaw-gateway — restart it manually: systemctl --user restart openclaw-gateway"
        fi
    fi
}

# ── Module: shell ────────────────────────────────────────────────────────────
mod_shell() {
    log_header "Module: shell"

    local user_home="/home/${USERNAME}"
    local bashrc="${user_home}/.bashrc"

    # umask
    if grep -q "^umask 027" "$bashrc" 2>/dev/null; then
        log_info "umask 027 already set in .bashrc"
    else
        if [[ "$DRY_RUN" == "true" ]]; then
            log_dry "Append umask 027 to $bashrc"
        else
            {
                echo ""
                echo "# Security hardening — managed by vps-harden.sh"
                echo "umask 027"
            } >> "$bashrc"
        fi
        log_info "Added umask 027 to .bashrc"
    fi

    # HISTSIZE + timestamps
    if grep -q "^HISTSIZE=10000" "$bashrc" 2>/dev/null; then
        log_info "HISTSIZE already set"
    else
        if [[ "$DRY_RUN" == "true" ]]; then
            log_dry "Set HISTSIZE=10000 and HISTTIMEFORMAT in $bashrc"
        else
            {
                echo 'HISTSIZE=10000'
                echo 'HISTFILESIZE=20000'
                echo 'HISTTIMEFORMAT="%F %T "'
            } >> "$bashrc"
        fi
        log_info "Set HISTSIZE=10000 with timestamps"
    fi

    # Scan for plaintext secrets in shell profiles
    log_info "Scanning shell profiles for plaintext secrets..."
    local profiles=("$bashrc" "${user_home}/.bash_profile" "${user_home}/.profile" "/root/.bashrc")
    local found_secrets=false
    for f in "${profiles[@]}"; do
        if [[ -f "$f" ]]; then
            if grep -qEi '(api.?key|secret|token|password)\s*=\s*["\x27]?[a-zA-Z0-9_-]{20,}' "$f" 2>/dev/null; then
                log_warn "Possible plaintext secret in $f"
                found_secrets=true
            fi
        fi
    done
    if [[ "$found_secrets" == "false" ]]; then
        log_info "No plaintext secrets detected in shell profiles"
    fi
}

# ── Module: misc ─────────────────────────────────────────────────────────────
mod_misc() {
    log_header "Module: misc"

    # Timezone
    if [[ -n "$TIMEZONE" ]]; then
        local current_tz
        current_tz=$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo "unknown")
        if [[ "$current_tz" == "$TIMEZONE" ]]; then
            log_info "Timezone already set to $TIMEZONE"
        else
            log_info "Setting timezone to $TIMEZONE"
            run_cmd timedatectl set-timezone "$TIMEZONE"
        fi
    fi

    # Hostname
    if [[ -n "$SET_HOSTNAME" ]]; then
        local current_hostname
        current_hostname=$(hostname)
        if [[ "$current_hostname" == "$SET_HOSTNAME" ]]; then
            log_info "Hostname already set to $SET_HOSTNAME"
        else
            log_info "Setting hostname to $SET_HOSTNAME"
            run_cmd hostnamectl set-hostname "$SET_HOSTNAME"
        fi
    fi

    # Lock root password (prevent direct root login with password)
    local root_pw_status
    root_pw_status=$(passwd -S root 2>/dev/null | awk '{print $2}')
    if [[ "$root_pw_status" == "L" ]]; then
        log_info "Root password already locked"
    else
        log_info "Locking root password"
        run_cmd passwd -l root
    fi

    # Restrict su to sudo group
    local su_pam="/etc/pam.d/su"
    if grep -q "^auth.*required.*pam_wheel.so.*group=sudo" "$su_pam" 2>/dev/null; then
        log_info "su already restricted to sudo group"
    else
        if [[ "$DRY_RUN" == "true" ]]; then
            log_dry "Restrict su to sudo group in $su_pam"
        else
            # Add pam_wheel restriction right after the existing commented line
            if grep -q "# auth.*required.*pam_wheel.so" "$su_pam" 2>/dev/null; then
                sed -i '/# auth.*required.*pam_wheel.so/a auth       required   pam_wheel.so group=sudo' "$su_pam"
            else
                echo "auth       required   pam_wheel.so group=sudo" >> "$su_pam"
            fi
            log_info "Restricted su to sudo group"
        fi
    fi
}

# ── Module: verify ───────────────────────────────────────────────────────────
mod_verify() {
    log_header "Module: verify — Security Scorecard"

    # SSH checks
    check_ssh_setting "PermitRootLogin" "no"
    check_ssh_setting "MaxAuthTries" "3"
    check_ssh_setting "X11Forwarding" "no"
    check_ssh_setting "PermitEmptyPasswords" "no"
    check_ssh_setting "MaxSessions" "3"
    check_ssh_setting "LoginGraceTime" "30"

    # AllowUsers check
    local allow_users
    allow_users=$(sshd -T 2>/dev/null | grep "^allowusers " | awk '{$1=""; print $0}' | xargs || true)
    if [[ -n "$allow_users" ]]; then
        sc_add "PASS" "AllowUsers configured: $allow_users"
    else
        sc_add "WARN" "AllowUsers not set (all users can SSH)"
    fi

    # SSH keys
    local auth_keys="/home/${USERNAME}/.ssh/authorized_keys"
    if [[ -f "$auth_keys" ]] && [[ -s "$auth_keys" ]]; then
        local key_count
        key_count=$(grep -c "^ssh-" "$auth_keys" || true)
        sc_add "PASS" "SSH authorized_keys has $key_count key(s)"
    else
        sc_add "FAIL" "No SSH keys in authorized_keys"
    fi

    # Banner
    if [[ -f "/etc/ssh/banner.txt" ]]; then
        sc_add "PASS" "SSH banner configured"
    else
        sc_add "WARN" "No SSH banner"
    fi

    # Firewall
    if command -v ufw &>/dev/null && ufw status | grep -q "^Status: active"; then
        sc_add "PASS" "UFW active, default deny"
    else
        sc_add "FAIL" "UFW not active"
    fi

    # Check SSH not open to Anywhere (0.0.0.0/0)
    if ufw status 2>/dev/null | grep "22/tcp" | grep -q "Anywhere" | grep -v "on wt0"; then
        sc_add "WARN" "SSH (22/tcp) open to Anywhere"
    else
        sc_add "PASS" "SSH restricted (not open to 0.0.0.0)"
    fi

    # fail2ban
    if command -v fail2ban-client &>/dev/null; then
        if fail2ban-client status sshd &>/dev/null; then
            sc_add "PASS" "fail2ban sshd jail active"
        else
            sc_add "WARN" "fail2ban installed but sshd jail not active"
        fi
    else
        sc_add "FAIL" "fail2ban not installed"
    fi

    # Kernel hardening
    local syncookies
    syncookies=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "0")
    if [[ "$syncookies" == "1" ]]; then
        sc_add "PASS" "SYN cookies enabled"
    else
        sc_add "WARN" "SYN cookies disabled"
    fi

    local redirects
    redirects=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null || echo "1")
    if [[ "$redirects" == "0" ]]; then
        sc_add "PASS" "ICMP redirects disabled"
    else
        sc_add "WARN" "ICMP redirects enabled"
    fi

    local source_route
    source_route=$(sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null || echo "1")
    if [[ "$source_route" == "0" ]]; then
        sc_add "PASS" "Source routing disabled"
    else
        sc_add "WARN" "Source routing enabled"
    fi

    local martians
    martians=$(sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null || echo "0")
    if [[ "$martians" == "1" ]]; then
        sc_add "PASS" "Martian logging enabled"
    else
        sc_add "WARN" "Martian logging disabled"
    fi

    # Auditd
    if command -v auditctl &>/dev/null; then
        if systemctl is-active auditd &>/dev/null; then
            sc_add "PASS" "auditd active"
            local audit_rule_count
            audit_rule_count=$(auditctl -l 2>/dev/null | grep -cv "^No rules" || echo 0)
            if [[ "$audit_rule_count" -gt 0 ]]; then
                sc_add "PASS" "Audit rules loaded ($audit_rule_count rules)"
            else
                sc_add "WARN" "auditd active but no rules loaded"
            fi
        else
            sc_add "WARN" "auditd installed but not active"
        fi
    else
        sc_add "WARN" "auditd not installed"
    fi

    # Logwatch
    if command -v logwatch &>/dev/null; then
        sc_add "PASS" "logwatch installed"
    else
        sc_add "WARN" "logwatch not installed"
    fi

    # server-report
    if [[ -x /usr/local/bin/server-report ]]; then
        sc_add "PASS" "server-report installed"
    else
        sc_add "WARN" "server-report not installed"
    fi

    # Netbird
    if command -v netbird &>/dev/null; then
        if ip link show wt0 &>/dev/null; then
            sc_add "PASS" "Netbird connected, wt0 up"
        else
            sc_add "WARN" "Netbird installed but wt0 not up"
        fi
    else
        sc_add "WARN" "Netbird not installed"
    fi

    # SOPS + age
    if command -v sops &>/dev/null && command -v age &>/dev/null; then
        sc_add "PASS" "SOPS + age installed"
    else
        sc_add "WARN" "SOPS and/or age not installed"
    fi

    # Unattended upgrades
    if dpkg -l unattended-upgrades 2>/dev/null | grep -q "^ii"; then
        sc_add "PASS" "Unattended upgrades enabled"
    else
        sc_add "WARN" "Unattended upgrades not configured"
    fi

    # Root password locked
    local root_pw
    root_pw=$(passwd -S root 2>/dev/null | awk '{print $2}')
    if [[ "$root_pw" == "L" ]]; then
        sc_add "PASS" "Root password locked"
    else
        sc_add "WARN" "Root password not locked"
    fi

    # Plaintext secrets
    local user_bashrc="/home/${USERNAME}/.bashrc"
    if [[ -f "$user_bashrc" ]] && grep -qEi '(api.?key|secret|token|password)\s*=\s*["\x27]?[a-zA-Z0-9_-]{20,}' "$user_bashrc" 2>/dev/null; then
        sc_add "FAIL" "Plaintext secrets in .bashrc"
    else
        sc_add "PASS" "No plaintext secrets in .bashrc"
    fi

    # File permissions
    if [[ -f "$auth_keys" ]]; then
        local ak_perms
        ak_perms=$(stat -c %a "$auth_keys" 2>/dev/null || echo "unknown")
        if [[ "$ak_perms" == "600" ]]; then
            sc_add "PASS" "authorized_keys permissions 600"
        else
            sc_add "WARN" "authorized_keys permissions are $ak_perms (should be 600)"
        fi
    fi

    # ── Print scorecard ──────────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}====================================================================${NC}"
    echo -e "${BOLD}               VPS SECURITY SCORECARD${NC}"
    echo -e "${BOLD}====================================================================${NC}"

    for i in "${!SC_LABELS[@]}"; do
        local result="${SC_RESULTS[$i]}"
        local label="${SC_LABELS[$i]}"
        local color
        case "$result" in
            PASS) color="$GREEN" ;;
            WARN) color="$YELLOW" ;;
            FAIL) color="$RED" ;;
        esac
        printf "  ${color}[%s]${NC} %s\n" "$result" "$label"
    done

    echo -e "${BOLD}--------------------------------------------------------------------${NC}"
    printf "  SCORE: ${GREEN}%d PASSED${NC} | ${YELLOW}%d WARNING${NC} | ${RED}%d FAILED${NC}\n" \
        "$SC_PASS" "$SC_WARN" "$SC_FAIL"
    echo -e "${BOLD}--------------------------------------------------------------------${NC}"
    echo ""

    log_raw "SCORECARD: $SC_PASS PASS | $SC_WARN WARN | $SC_FAIL FAIL"

    if [[ $SC_FAIL -gt 0 ]]; then
        log_warn "There are $SC_FAIL FAILED checks — review and fix them"
    fi
}

check_ssh_setting() {
    local setting="$1" expected="$2"
    local actual
    actual=$(sshd -T 2>/dev/null | grep -i "^${setting} " | awk '{print $2}' || echo "unknown")
    local expected_lower actual_lower
    expected_lower=$(echo "$expected" | tr '[:upper:]' '[:lower:]')
    actual_lower=$(echo "$actual" | tr '[:upper:]' '[:lower:]')

    if [[ "$actual_lower" == "$expected_lower" ]]; then
        sc_add "PASS" "${setting} = ${actual}"
    else
        sc_add "FAIL" "${setting} = ${actual} (expected ${expected})"
    fi
}

# ── Interactive Setup Wizard ──────────────────────────────────────────────────
interactive_setup() {
    # Require a TTY for interactive mode
    if [[ ! -t 0 ]]; then
        die "Interactive mode requires a terminal (stdin is not a TTY)"
    fi

    setup_colors

    echo -e "${BOLD}${CYAN}"
    echo "  ╦  ╦╔═╗╔═╗  ╦ ╦╔═╗╦═╗╔╦╗╔═╗╔╗╔"
    echo "  ╚╗╔╝╠═╝╚═╗  ╠═╣╠═╣╠╦╝ ║║║╣ ║║║"
    echo "   ╚╝ ╩  ╚═╝  ╩ ╩╩ ╩╩╚══╩╝╚═╝╝╚╝  Setup Wizard"
    echo -e "${NC}"

    local wiz_key_source=""

    # ── Step 1: Username ─────────────────────────────────────────────────
    echo -e "${BOLD}1. Username${NC}"
    echo "   The non-root user to create (or harden if it exists)."
    echo "   This user gets sudo access and SSH login."
    local default_user="${USERNAME:-}"
    if [[ -z "$default_user" ]] && [[ -n "${SUDO_USER:-}" ]] && [[ "$SUDO_USER" != "root" ]]; then
        default_user="$SUDO_USER"
    fi
    if [[ -z "$default_user" ]]; then
        default_user="deploy"
    fi
    printf "   Username [%s]: " "$default_user"
    read -r input
    USERNAME="${input:-$default_user}"
    echo ""

    # ── Step 2: SSH Public Key ───────────────────────────────────────────
    echo -e "${BOLD}2. SSH Public Key${NC}"
    echo "   Your public key for passwordless SSH login."
    echo "   Without this, you'll be locked out when password auth is disabled."

    if [[ -z "$SSH_KEY_CONTENT" ]]; then
        # Try to auto-detect from authorized_keys
        local detected_key=""
        local key_file=""
        for candidate in "/root/.ssh/authorized_keys" "/home/${USERNAME}/.ssh/authorized_keys"; do
            if [[ -f "$candidate" ]]; then
                detected_key=$(grep -m1 "^ssh-" "$candidate" 2>/dev/null || true)
                if [[ -n "$detected_key" ]]; then
                    key_file="$candidate"
                    break
                fi
            fi
        done

        if [[ -n "$detected_key" ]]; then
            local key_type key_comment
            key_type=$(echo "$detected_key" | awk '{print $1}')
            key_comment=$(echo "$detected_key" | awk '{print $3}')
            echo ""
            echo "   Detected key from ${key_file}:"
            echo -e "   ${CYAN}${key_type} ...${key_comment:+$key_comment}${NC}"
            printf "   Use this key? [Y/n]: "
            read -r input
            if [[ -z "$input" || "$input" =~ ^[Yy] ]]; then
                SSH_KEY="$key_file"
                SSH_KEY_CONTENT=$(grep "^ssh-" "$key_file")
                wiz_key_source="auto-detected from $key_file"
            else
                detected_key=""
            fi
        fi

        if [[ -z "$detected_key" ]] && [[ -z "$SSH_KEY_CONTENT" ]]; then
            echo ""
            echo "   No SSH key found on this server."
            echo ""
            echo "   How would you like to provide your public key?"
            echo "     1) GitHub — fetch your key from GitHub (easiest)"
            echo "     2) ssh-copy-id — copy it from your local machine"
            echo "     3) Paste — paste the key string directly"
            echo ""
            printf "   Choice [1]: "
            read -r choice
            choice="${choice:-1}"

            case "$choice" in
                1)
                    # GitHub fetch
                    printf "   GitHub username: "
                    read -r gh_user
                    if [[ -z "$gh_user" ]]; then
                        die "GitHub username cannot be empty"
                    fi
                    echo "   Fetching keys from github.com/${gh_user}..."
                    local gh_keys
                    gh_keys=$(curl -fsSL "https://github.com/${gh_user}.keys" 2>/dev/null || true)
                    if [[ -z "$gh_keys" ]]; then
                        die "No SSH keys found for GitHub user '${gh_user}'. Check the username and try again."
                    fi
                    local gh_key_count
                    gh_key_count=$(echo "$gh_keys" | grep -c "^ssh-" || true)
                    echo "   Found ${gh_key_count} key(s):"
                    echo "$gh_keys" | while IFS= read -r k; do
                        local kt kfp
                        kt=$(echo "$k" | awk '{print $1}')
                        kfp=$(echo "$k" | awk '{print substr($2,length($2)-7)}')
                        echo -e "     ${CYAN}${kt} ...${kfp}${NC}"
                    done
                    printf "   Use these keys? [Y/n]: "
                    read -r input
                    if [[ -z "$input" || "$input" =~ ^[Yy] ]]; then
                        SSH_KEY_CONTENT="$gh_keys"
                        wiz_key_source="fetched from github.com/${gh_user}"
                    else
                        die "Aborted. Re-run the wizard to try another method."
                    fi
                    ;;
                2)
                    # ssh-copy-id
                    echo ""
                    echo "   On your LOCAL machine, open a new terminal and run:"
                    echo -e "     ${BOLD}ssh-copy-id root@$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'YOUR_VPS_IP')${NC}"
                    echo ""
                    printf "   Press Enter here when done..."
                    read -r
                    # Re-check for keys
                    local copied_key=""
                    for candidate in "/root/.ssh/authorized_keys" "/home/${USERNAME}/.ssh/authorized_keys"; do
                        if [[ -f "$candidate" ]]; then
                            copied_key=$(grep -m1 "^ssh-" "$candidate" 2>/dev/null || true)
                            if [[ -n "$copied_key" ]]; then
                                key_file="$candidate"
                                break
                            fi
                        fi
                    done
                    if [[ -z "$copied_key" ]]; then
                        die "Still no SSH key found. Make sure ssh-copy-id succeeded and try again."
                    fi
                    SSH_KEY="$key_file"
                    SSH_KEY_CONTENT=$(grep "^ssh-" "$key_file")
                    wiz_key_source="copied via ssh-copy-id"
                    local kt2 kc2
                    kt2=$(echo "$copied_key" | awk '{print $1}')
                    kc2=$(echo "$copied_key" | awk '{print $3}')
                    echo -e "   Found: ${CYAN}${kt2} ...${kc2:+$kc2}${NC}"
                    ;;
                3)
                    # Manual paste
                    echo ""
                    echo "   On your local machine, run:"
                    echo -e "     ${BOLD}cat ~/.ssh/id_ed25519.pub${NC}"
                    echo "   Then paste the output here."
                    echo ""
                    printf "   SSH public key: "
                    read -r pasted_key
                    if [[ ! "$pasted_key" =~ ^ssh- ]]; then
                        die "That doesn't look like an SSH public key (must start with ssh-). Try again."
                    fi
                    SSH_KEY_CONTENT="$pasted_key"
                    wiz_key_source="pasted manually"
                    ;;
                *)
                    die "Invalid choice: $choice"
                    ;;
            esac
        fi
    fi
    echo ""

    # ── Step 3: Safety IP ────────────────────────────────────────────────
    echo -e "${BOLD}3. SSH Safety IP${NC}"
    echo "   A fallback IP that can always reach SSH port 22, even if the"
    echo "   VPN tunnel goes down. Usually your current public IP."
    local detected_ip
    detected_ip=$(detect_ssh_client_ip)
    local default_ip="${SSH_SAFETY_IP:-$detected_ip}"
    if [[ -n "$default_ip" ]]; then
        echo -e "   Detected your IP: ${CYAN}${default_ip}${NC}"
        printf "   Safety IP [%s] (or 'skip'): " "$default_ip"
    else
        printf "   Safety IP (or 'skip'): "
    fi
    read -r input
    if [[ "$input" == "skip" ]]; then
        SSH_SAFETY_IP=""
    else
        SSH_SAFETY_IP="${input:-$default_ip}"
    fi
    echo ""

    # ── Step 4: Timezone ─────────────────────────────────────────────────
    echo -e "${BOLD}4. Timezone${NC}"
    echo "   System timezone for logs and cron jobs."
    local detected_tz
    detected_tz=$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo "UTC")
    local default_tz="${TIMEZONE:-$detected_tz}"
    printf "   Timezone [%s] (or 'skip'): " "$default_tz"
    read -r input
    if [[ "$input" == "skip" ]]; then
        TIMEZONE=""
    else
        TIMEZONE="${input:-$default_tz}"
    fi
    echo ""

    # ── Step 5: Netbird Key ──────────────────────────────────────────────
    echo -e "${BOLD}5. Netbird VPN Setup Key (optional)${NC}"
    echo "   Connects this server to your Netbird mesh network."
    echo "   Get a setup key from app.netbird.io → Setup Keys."
    local default_nb="${NETBIRD_KEY:-}"
    if [[ -n "$default_nb" ]]; then
        printf "   Netbird setup key [%s...]: " "${default_nb:0:8}"
    else
        printf "   Netbird setup key (Enter to skip): "
    fi
    read -r input
    NETBIRD_KEY="${input:-$default_nb}"
    echo ""

    # ── Step 6: Dry Run ──────────────────────────────────────────────────
    echo -e "${BOLD}6. Dry Run?${NC}"
    echo "   A dry run shows what would change without making changes."
    echo "   Recommended for the first run."
    printf "   Start with dry run? [Y/n]: "
    read -r input
    if [[ -z "$input" || "$input" =~ ^[Yy] ]]; then
        DRY_RUN="true"
    else
        DRY_RUN="false"
    fi
    echo ""

    # ── Summary ──────────────────────────────────────────────────────────
    local key_display
    if [[ -n "$SSH_KEY_CONTENT" ]]; then
        local first_key
        first_key=$(echo "$SSH_KEY_CONTENT" | head -1)
        local kt3 kc3
        kt3=$(echo "$first_key" | awk '{print $1}')
        kc3=$(echo "$first_key" | awk '{print $3}')
        key_display="${kt3} ...${kc3:+$kc3}"
        if [[ -n "$wiz_key_source" ]]; then
            key_display="${key_display} (${wiz_key_source})"
        fi
    elif [[ -n "$SSH_KEY" ]]; then
        key_display="$SSH_KEY"
    fi

    echo -e "${BOLD}── Summary ──────────────────────────────────────────${NC}"
    printf "   Username:     %s\n" "$USERNAME"
    printf "   SSH key:      %s\n" "$key_display"
    printf "   Safety IP:    %s\n" "${SSH_SAFETY_IP:-<skipped>}"
    printf "   Timezone:     %s\n" "${TIMEZONE:-<skipped>}"
    printf "   Netbird:      %s\n" "${NETBIRD_KEY:+${NETBIRD_KEY:0:8}...}"
    [[ -z "$NETBIRD_KEY" ]] && printf "   Netbird:      %s\n" "<skipped>"
    printf "   Dry run:      %s\n" "$DRY_RUN"
    echo ""

    # Build equivalent CLI command
    local cli_cmd="sudo ./vps-harden.sh --username ${USERNAME}"
    if [[ -n "$SSH_KEY" ]]; then
        cli_cmd+=" --ssh-key ${SSH_KEY}"
    elif [[ -n "$SSH_KEY_CONTENT" ]]; then
        # Use first key inline (truncated for display)
        cli_cmd+=" --ssh-key \"$(echo "$SSH_KEY_CONTENT" | head -1)\""
    fi
    [[ -n "$SSH_SAFETY_IP" ]] && cli_cmd+=" --ssh-safety-ip ${SSH_SAFETY_IP}"
    [[ -n "$TIMEZONE" ]] && cli_cmd+=" --timezone ${TIMEZONE}"
    [[ -n "$NETBIRD_KEY" ]] && cli_cmd+=" --netbird-key ${NETBIRD_KEY}"
    [[ "$DRY_RUN" == "true" ]] && cli_cmd+=" --dry-run"

    echo "   For future runs:"
    echo -e "   ${CYAN}${cli_cmd}${NC}"
    echo ""

    printf "   Proceed? [Y/n]: "
    read -r input
    if [[ -n "$input" && ! "$input" =~ ^[Yy] ]]; then
        echo "   Aborted."
        exit 0
    fi
    echo ""

    # If we got SSH_KEY_CONTENT but no SSH_KEY, set a sentinel so validate_args
    # knows we already resolved the key
    if [[ -n "$SSH_KEY_CONTENT" && -z "$SSH_KEY" ]]; then
        SSH_KEY="<wizard>"
    fi
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"
    setup_colors
    [[ -n "$CONFIG_FILE" ]] && parse_config_file "$CONFIG_FILE"

    # Launch interactive wizard if --interactive, or if no required params and no config file
    if [[ "$INTERACTIVE" == "true" ]] || \
       { [[ -z "$USERNAME" ]] && [[ -z "$SSH_KEY" ]] && [[ -z "$CONFIG_FILE" ]]; }; then
        interactive_setup
    fi

    validate_args
    check_distro
    log_init

    echo -e "${BOLD}${CYAN}"
    echo "  ╦  ╦╔═╗╔═╗  ╦ ╦╔═╗╦═╗╔╦╗╔═╗╔╗╔"
    echo "  ╚╗╔╝╠═╝╚═╗  ╠═╣╠═╣╠╦╝ ║║║╣ ║║║"
    echo "   ╚╝ ╩  ╚═╝  ╩ ╩╩ ╩╩╚══╩╝╚═╝╝╚╝  v${SCRIPT_VERSION}"
    echo -e "${NC}"

    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "${YELLOW}*** DRY RUN MODE — no changes will be made ***${NC}"
        echo ""
    fi

    log_info "Target user: $USERNAME"
    log_info "Dry run: $DRY_RUN"
    [[ -n "$SKIP_MODULES" ]] && log_info "Skipping modules: $SKIP_MODULES"
    [[ -n "$ONLY_MODULES" ]] && log_info "Only modules: $ONLY_MODULES"

    # Run modules in order
    for mod in $ALL_MODULES; do
        if should_run "$mod"; then
            ( mod_"$mod" ) || {
                case "$mod" in
                    user|ssh)
                        die "Critical module '$mod' failed — aborting"
                        ;;
                    *)
                        log_warn "Module '$mod' failed — continuing"
                        ;;
                esac
            }
        else
            log_info "Skipping module: $mod"
        fi
    done

    echo ""
    log_info "Done. Log saved to $LOG_FILE"
    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "${YELLOW}This was a dry run. Run without --dry-run to apply changes.${NC}"
    fi
}

main "$@"
