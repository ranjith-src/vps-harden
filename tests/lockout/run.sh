#!/usr/bin/env bash
# tests/lockout/run.sh — Shows that the last release locks you out of root, and this one doesn't.
#
# Each scenario boots a new container that behaves like a fresh VPS (real systemd, sshd and
# sudo), runs vps-harden in it, then tries to get root the way its owner would: over SSH with
# their key, typing at real sudo and su prompts. Needs Docker and nothing else.
# The later scenarios hold the script to what it reports and prints: the scorecard's SSH row,
# homes and groups it has to look up, and commands meant to be pasted.
#
# Usage: tests/lockout/run.sh [-l] [SCENARIO ...]     -l lists the scenarios
#   BASE=debian:12     base image (default ubuntu:24.04)
#   OLD_REF=v1.4.0     git ref of the script that locks out
#
# It removes its containers and leaves the vps-harden-lockout image for next time.
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
BASE="${BASE:-ubuntu:24.04}"
OLD_REF="${OLD_REF:-v1.4.0}"
IMAGE="vps-harden-lockout:$(echo "$BASE" | tr ':/' '--')"
TMP_ROOT="${TMPDIR:-/tmp}"
WORK=$(mktemp -d "${TMP_ROOT%/}/vps-harden-lockout.XXXXXX")
NAME_PREFIX="vps-harden-lockout-$$"

# Throwaway values: they exist only inside containers that are deleted after each scenario.
ROOT_PW="provider-root-pw"
USER_PW="s3cret pass:w\$rd"

BOX="" OUT="" RC=0 SCENARIO="" BOX_COUNT=0 PASSED=0 FAILED=0 FAILURES=""
SSH_COMMON=(-o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
SSH_OPTS=(-o BatchMode=yes "${SSH_COMMON[@]}" -i /root/id_user)
SSH_TTY_OPTS=(-tt "${SSH_COMMON[@]}" -i /root/id_user)

# ── Plumbing ─────────────────────────────────────────────────────────────────
remove_box() {
    if [[ -n "$BOX" ]]; then
        docker rm -f "$BOX" >/dev/null 2>&1
        BOX=""
    fi
}

finish() {
    remove_box
    if [[ $FAILED -eq 0 ]]; then
        rm -rf "$WORK"
    else
        echo "Run transcripts kept in $WORK"
    fi
}
trap finish EXIT
trap 'exit 130' INT TERM

pass() { echo "    ok    $1"; PASSED=$((PASSED + 1)); }
fail() {
    echo "    FAIL  $1"
    FAILED=$((FAILED + 1))
    FAILURES="${FAILURES}  ${SCENARIO}: $1"$'\n'
}
check()  { local what="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi; }
refute() { local what="$1"; shift; if "$@" >/dev/null 2>&1; then fail "$what"; else pass "$what"; fi; }

in_box() { docker exec "$BOX" "$@"; }

# Boots a fresh box with the given script installed the way install.sh does it.
# Root has a password and an SSH key, as a VPS provider hands it over.
boot_box() {
    local script="$1"
    remove_box
    BOX_COUNT=$((BOX_COUNT + 1))
    BOX="${NAME_PREFIX}-${BOX_COUNT}"
    docker run -d --name "$BOX" --hostname vps \
        --cap-add SYS_ADMIN --cap-add NET_ADMIN --cap-add AUDIT_CONTROL \
        --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
        --cgroupns=private --tmpfs /run --tmpfs /run/lock \
        "$IMAGE" >/dev/null || { echo "Could not start a container"; exit 1; }
    local tries=0
    until in_box systemctl is-active --quiet ssh.service ssh.socket 2>/dev/null; do
        tries=$((tries + 1))
        [[ $tries -lt 60 ]] || { echo "ssh did not come up in the container"; exit 1; }
        sleep 1
    done
    docker cp "$script" "$BOX:/usr/local/bin/vps-harden" >/dev/null
    docker cp "$REPO/server-report" "$BOX:/usr/local/bin/server-report" >/dev/null
    in_box sh -c "
        chmod 755 /usr/local/bin/vps-harden /usr/local/bin/server-report
        ssh-keygen -q -t ed25519 -N '' -f /root/id_user -C me@laptop
        install -d -m 700 /root/.ssh
        cat /root/id_user.pub >> /root/.ssh/authorized_keys
        chmod 600 /root/.ssh/authorized_keys
        echo 'root:$ROOT_PW' | chpasswd
        timeout 60 systemctl is-system-running --wait >/dev/null 2>&1 || true
    "
}

new_box() { boot_box "$REPO/vps-harden.sh"; }

old_box() {
    git -C "$REPO" show "${OLD_REF}:vps-harden.sh" > "$WORK/old-vps-harden.sh" \
        || { echo "Cannot read ${OLD_REF}:vps-harden.sh (a shallow clone has no tags: git fetch --tags)"; exit 1; }
    boot_box "$WORK/old-vps-harden.sh"
}

# Runs vps-harden with stdin not a terminal, as automation does.
harden() {
    OUT="$WORK/${SCENARIO}.$BOX_COUNT.out"
    in_box vps-harden --no-color "$@" > "$OUT" 2>&1 < /dev/null
    RC=$?
}

# tty_harden PROMPT REPLY ... -- ARG ...: runs vps-harden on a terminal, typing at its prompts.
tty_harden() {
    OUT="$WORK/${SCENARIO}.$BOX_COUNT.out"
    local args=()
    while [[ $# -gt 0 && "$1" != "--" ]]; do args+=("$1"); shift; done
    shift
    in_box answer ${args[@]+"${args[@]}"} -- vps-harden --no-color "$@" > "$OUT" 2>&1 < /dev/null
    RC=$?
}

said()      { grep -qF -- "$1" "$OUT"; }
exited_ok() { [[ $RC -eq 0 ]]; }
stopped()   { [[ $RC -ne 0 && $RC -lt 100 ]]; }

fingerprint() {
    in_box sh -c 'find /etc /home /root /usr/local/bin /var/spool/cron -xdev -printf "%M %u:%g %p -> %l\n" | sort
        find /etc /home /root /usr/local/bin -xdev -type f -print0 | sort -z | xargs -0 sha256sum
        ufw status' 2>/dev/null
}
snapshot()   { fingerprint > "$WORK/before"; }
unchanged()  { fingerprint > "$WORK/after"; diff "$WORK/before" "$WORK/after" > "$WORK/${SCENARIO}.$BOX_COUNT.diff"; }

# ── Ways to root, tried the way the owner would ──────────────────────────────
# True if the command prints a line that is exactly 0, which is what `id -u` prints for root.
# Its exit status does not count: answer exits non-zero if sudo stops asking early.
gets_root() {
    local output
    output=$("$@" 2>/dev/null)
    echo "$output" | tr -d '\r' | grep -qx 0
}
root_over_ssh() { gets_root in_box ssh "${SSH_OPTS[@]}" root@127.0.0.1 id -u; }
sudo_without_password() { gets_root in_box ssh "${SSH_OPTS[@]}" "${1}@127.0.0.1" sudo -n id -u; }
# Types the password at sudo's prompt in an SSH session. sudo asks up to three times.
# The wording differs between sudo and sudo-rs, so match only on the word.
SUDO_PROMPT='[Pp]assword[^\r\n]*: *$'
sudo_with_password() {
    gets_root in_box answer "$SUDO_PROMPT" "$2" "$SUDO_PROMPT" "$2" "$SUDO_PROMPT" "$2" -- \
        ssh "${SSH_TTY_OPTS[@]}" "${1}@127.0.0.1" sudo id -u
}
sudo_first_try() {
    gets_root in_box answer "$SUDO_PROMPT" "$2" -- ssh "${SSH_TTY_OPTS[@]}" "${1}@127.0.0.1" sudo id -u
}
su_with_root_password() {
    gets_root in_box answer 'Password:' "$ROOT_PW" -- ssh "${SSH_TTY_OPTS[@]}" "${1}@127.0.0.1" su - -c "'id -u'"
}
sets_own_password() {
    local output
    output=$(in_box answer 'Current password:' '' -- ssh "${SSH_TTY_OPTS[@]}" "${1}@127.0.0.1" passwd 2>/dev/null)
    echo "$output" | grep -q 'New password'
}
password_login_works() {
    local output
    output=$(in_box answer 'password:' "$2" -- ssh -tt "${SSH_COMMON[@]}" -o PubkeyAuthentication=no \
        -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 "${1}@127.0.0.1" id -u 2>/dev/null)
    echo "$output" | tr -d '\r' | grep -qx '[0-9][0-9]*'
}
key_login_works() { in_box ssh "${SSH_OPTS[@]}" "${1}@127.0.0.1" true 2>/dev/null; }
status_of()       { in_box passwd -S "$1" 2>/dev/null | awk '{print $2}'; }
is_locked()       { [[ $(status_of "$1") == "L" ]]; }
has_password()    { [[ $(status_of "$1") == "P" ]]; }
no_hardening()    { ! in_box test -e /etc/ssh/sshd_config.d/00-hardening.conf; }
user_absent()     { ! in_box id "$1"; }
sudo_gone()       { ! in_box sh -c 'command -v sudo'; }
remove_sudo()     { in_box sh -c 'SUDO_FORCE_REMOVE=yes apt-get remove -y -qq sudo sudo-rs >/dev/null 2>&1 || SUDO_FORCE_REMOVE=yes apt-get remove -y -qq sudo >/dev/null 2>&1'; }
sudo_runs_as()    { in_box runuser -u "$1" -- sudo -n true; }
pam_denies_sudo() { in_box sed -i '1i auth requisite pam_deny.so' /etc/pam.d/sudo; }
sudo_rule_safe()  { [[ $(in_box stat -c '%a %U:%G' "$1") == "440 root:root" ]]; }

prove_locked_out() {
    local user="$1"
    check  "$user can log in by key, so this is not an SSH lockout" key_login_works "$user"
    refute "root over SSH is refused" root_over_ssh
    refute "$user: sudo without a password is refused" sudo_without_password "$user"
    refute "$user: sudo refuses an empty password" sudo_with_password "$user" ""
    refute "$user: sudo refuses the root password" sudo_with_password "$user" "$ROOT_PW"
    refute "$user: su refuses the root password that worked before the run" su_with_root_password "$user"
    refute "$user: cannot set their own password" sets_own_password "$user"
    check  "$user has no usable password" is_locked "$user"
    check  "root password is locked, so the provider console is closed too" is_locked root
}

prove_can_get_root_nopasswd() {
    local user="$1"
    check  "$user can log in by key" key_login_works "$user"
    check  "$user: sudo gets root without a password" sudo_without_password "$user"
    refute "root over SSH is refused" root_over_ssh
    check  "root password is locked" is_locked root
}

prove_can_get_root_password() {
    local user="$1" password="$2"
    check  "$user can log in by key" key_login_works "$user"
    check  "$user: typing the password at sudo gets root" sudo_first_try "$user" "$password"
    refute "$user: sudo refuses a wrong password" sudo_with_password "$user" "wrong-password"
    refute "$user: sudo without a password is refused" sudo_without_password "$user"
    refute "$user: the password does not open SSH" password_login_works "$user" "$password"
    refute "root over SSH is refused" root_over_ssh
    check  "root password is locked" is_locked root
}

KEY=/root/id_user.pub
WIZARD_TAIL=('Safety IP.*skip' 'skip' 'Timezone \[' 'skip' 'Netbird setup key' '')

# ── Scenarios: the last release ──────────────────────────────────────────────
scenario_old_cli_locks_out() {
    old_box
    check "before the run: root over SSH works" root_over_ssh
    harden --username deploy --ssh-key "$KEY" --timezone UTC
    check "the run reports success" exited_ok
    check "the scorecard says 0 FAILED" said "0 FAILED"
    prove_locked_out deploy
    check "sudo -l still looks healthy, which is why it cannot be the test" \
        in_box ssh "${SSH_OPTS[@]}" deploy@127.0.0.1 sudo -n -l
}

scenario_old_wizard_locks_out() {
    old_box
    tty_harden 'Username \[' deploy 'Use this key' y "${WIZARD_TAIL[@]}" 'Start with dry run' n 'Proceed\?' y --
    check "the run reports success" exited_ok
    prove_locked_out deploy
}

# ── Scenarios: stops before anything can lock you out ────────────────────────
prove_stopped_untouched() {
    check "it stopped" stopped
    check "it says nothing was changed" said "Nothing has been changed"
    check "nothing on the box changed" unchanged
    check "root over SSH still works" root_over_ssh
    check "root still has its password" has_password root
}

scenario_cli_without_choice_stops() {
    new_box; snapshot
    harden --username deploy --ssh-key "$KEY" --timezone UTC
    prove_stopped_untouched
    check "it offers --sudo-access password" said "--sudo-access password"
    check "it offers --sudo-access nopasswd" said "--sudo-access nopasswd"
    check "no user was created" user_absent deploy
}

scenario_config_file_without_choice_stops() {
    new_box
    in_box sh -c "printf 'username=deploy\nssh_key=$KEY\n' > /root/harden.env"
    snapshot
    harden --config /root/harden.env
    prove_stopped_untouched
}

scenario_run_through_sudo_stops() {
    new_box
    # The first user a cloud image comes with. What counts is the target user's sudo, not theirs.
    in_box sh -c "useradd -m firstuser; echo 'firstuser ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-cloud-init-users; chmod 440 /etc/sudoers.d/90-cloud-init-users"
    check "the first user has working sudo" sudo_runs_as firstuser
    snapshot
    OUT="$WORK/${SCENARIO}.$BOX_COUNT.out"
    in_box runuser -u firstuser -- sudo -n vps-harden --no-color --username deploy --ssh-key "$KEY" > "$OUT" 2>&1 < /dev/null
    RC=$?
    prove_stopped_untouched
}

scenario_password_without_terminal_stops() {
    new_box; snapshot
    harden --username deploy --ssh-key "$KEY" --sudo-access password
    prove_stopped_untouched
    check "it says a terminal is needed" said "reads the password from a terminal"
}

# Root login gets disabled and root's password locked, so root cannot be the way back.
scenario_username_root_stops() {
    new_box
    in_box useradd -o -u 0 -M -s /bin/bash toor
    snapshot
    harden --username root --ssh-key "$KEY" --sudo-access nopasswd
    check "root is refused" stopped
    check "it says why" said "must not be root"
    harden --username toor --ssh-key "$KEY" --sudo-access nopasswd
    check "so is another account with UID 0" stopped
    check "nothing on the box changed" unchanged
    check "root over SSH still works" root_over_ssh
    check "root still has its password" has_password root
}

# sudo works through runuser for this user, but nobody can log in to reach it.
scenario_no_login_shell_stops() {
    new_box
    in_box sh -c "useradd -m -s /usr/sbin/nologin deploy; echo 'deploy ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/deploy; chmod 440 /etc/sudoers.d/deploy"
    snapshot
    harden --username deploy --ssh-key "$KEY"
    prove_stopped_untouched
    check "it says why" said "no login shell"
    check "it says what to do" said "chsh -s /bin/bash deploy"
    # Logging in to prove root still works leaves files behind, so start counting again.
    snapshot
    harden --username deploy --ssh-key "$KEY" --sudo-access nopasswd
    prove_stopped_untouched
    snapshot
    harden --username deploy --ssh-key "$KEY" --dry-run
    check "a dry run finishes" exited_ok
    check "it warns a real run would stop" said "a real run would stop here"
    check "the scorecard shows what is needed" said "needs a login shell"
    check "nothing on the box changed" unchanged
}

scenario_bad_flag_value_stops() {
    new_box; snapshot
    harden --username deploy --ssh-key "$KEY" --sudo-access sometimes
    check "it stopped" stopped
    check "it names the valid values" said "must be password or nopasswd"
    check "nothing on the box changed" unchanged
}

scenario_only_user_warns_and_leaves_root_open() {
    new_box
    harden --username deploy --ssh-key "$KEY" --only user
    check "it finishes" exited_ok
    check "it warns" said "cannot sudo yet"
    check "root over SSH still works" root_over_ssh
    check "root still has its password" has_password root
}

scenario_only_ssh_stops() {
    new_box
    harden --username deploy --ssh-key "$KEY" --only user
    snapshot
    harden --username deploy --ssh-key "$KEY" --only ssh
    prove_stopped_untouched
    check "no SSH hardening was written" no_hardening
}

scenario_only_misc_stops() {
    new_box
    harden --username deploy --ssh-key "$KEY" --only user
    snapshot
    harden --username deploy --ssh-key "$KEY" --only misc
    prove_stopped_untouched
}

scenario_skip_user_stops() {
    new_box; snapshot
    harden --username deploy --ssh-key "$KEY" --skip user
    prove_stopped_untouched
    check "no user was created" user_absent deploy
}

scenario_flag_without_user_module_stops() {
    new_box; snapshot
    harden --username deploy --ssh-key "$KEY" --only ssh,misc --sudo-access nopasswd
    prove_stopped_untouched
    check "it says the user module applies the flag" said "applied by the user module"
}

scenario_sudo_missing_without_prereqs_stops() {
    new_box
    remove_sudo
    check "sudo is really gone" sudo_gone
    snapshot
    harden --username deploy --ssh-key "$KEY" --skip prereqs --sudo-access nopasswd
    prove_stopped_untouched
    check "it says to install sudo" said "apt-get install sudo"
}

# The preflight cannot see this one coming: sudoers has no rule for the sudo group.
scenario_gate_catches_what_preflight_cannot() {
    new_box
    in_box sh -c "useradd -m -G sudo deploy && echo 'deploy:$USER_PW' | chpasswd && sed -i '/^%sudo/d' /etc/sudoers"
    harden --username deploy --ssh-key "$KEY" --only user,ssh,misc,verify
    check "it stopped" stopped
    check "it says the ssh module did not run" said "The ssh module did not run"
    check "it explains sudoers" said "no rule for it"
    check "no SSH hardening was written" no_hardening
    check "root over SSH still works" root_over_ssh
    check "root still has its password" has_password root
}

# ── Scenarios: finishes with a working way to root ───────────────────────────
scenario_cli_nopasswd_works() {
    new_box
    harden --username deploy --ssh-key "$KEY" --timezone UTC --sudo-access nopasswd
    check "the run reports success" exited_ok
    check "the scorecard says so" said "[PASS] deploy can sudo (passwordless rule)"
    check "the scorecard says 0 FAILED" said "0 FAILED"
    check "the rule file is 440 root:root" sudo_rule_safe /etc/sudoers.d/vps-harden-deploy
    check "visudo accepts the whole configuration" in_box visudo -c
    refute "no temporary file was left behind" in_box sh -c 'ls -A /etc/sudoers.d | grep -q "^\.vps-harden"'
    check "the next steps say to test sudo" said "sudo whoami"
    prove_can_get_root_nopasswd deploy
}

scenario_cli_password_works() {
    new_box
    tty_harden 'New password' "$USER_PW" 'Confirm password' "$USER_PW" -- \
        --username deploy --ssh-key "$KEY" --timezone UTC --sudo-access password
    check "the run reports success" exited_ok
    check "the scorecard says so" said "[PASS] deploy can sudo (with password)"
    check "the scorecard says 0 FAILED" said "0 FAILED"
    check "it proved the password through sudo" said "sudo accepts the new password"
    refute "the password is not in the output" said "$USER_PW"
    refute "the password is not in any log" in_box grep -rqF "$USER_PW" /var/log
    prove_can_get_root_password deploy "$USER_PW"
}

scenario_password_prompt_retries() {
    new_box
    tty_harden 'New password' 'short' 'Confirm password' 'short' \
        'New password' 'long-enough-1' 'Confirm password' 'long-enough-2' \
        'New password' "$USER_PW" 'Confirm password' "$USER_PW" -- \
        --username deploy --ssh-key "$KEY" --sudo-access password --only user,verify
    check "it finishes" exited_ok
    check "it rejected the short one" said "Too short"
    check "it rejected the mismatch" said "do not match"
    check "the third try counts" has_password deploy
}

scenario_ctrl_c_at_password_prompt_leaves_nothing_behind() {
    new_box; snapshot
    OUT="$WORK/${SCENARIO}.$BOX_COUNT.out"
    # The format of stty -a differs between systems, so pick out the one setting.
    in_box answer 'New password' '<ctrl-c>' -- bash -c \
        "vps-harden --no-color --username deploy --ssh-key $KEY --sudo-access password; echo status=\$?; stty -a | tr -s ' ;' '\n' | grep -E '^-?echo\$' | sed 's/^/tty: /'" \
        > "$OUT" 2>&1 < /dev/null
    check  "it says it was aborted" said "Aborted"
    check  "the exit status says so too" said "status=130"
    check  "the terminal shows what you type again" said "tty: echo"
    refute "echo is not left off" said "tty: -echo"
    check  "nothing on the box changed" unchanged
}

scenario_password_prompt_gives_up() {
    new_box; snapshot
    tty_harden 'New password' 'a' 'Confirm password' 'a' 'New password' 'b' 'Confirm password' 'b' \
        'New password' 'c' 'Confirm password' 'c' -- \
        --username deploy --ssh-key "$KEY" --sudo-access password
    prove_stopped_untouched
}

scenario_wizard_password_works() {
    new_box
    tty_harden 'Username \[' deploy 'Use this key' y 'Choice \[1\]' 1 "${WIZARD_TAIL[@]}" \
        'Start with dry run' n 'Proceed\?' y 'New password' "$USER_PW" 'Confirm password' "$USER_PW" --
    check "the run reports success" exited_ok
    check "the wizard shows the choice" said "Sudo access:  password"
    check "the scorecard says so" said "[PASS] deploy can sudo (with password)"
    prove_can_get_root_password deploy "$USER_PW"
}

scenario_wizard_default_is_password() {
    new_box; snapshot
    tty_harden 'Username \[' deploy 'Use this key' y 'Choice \[1\]' '' "${WIZARD_TAIL[@]}" \
        'Start with dry run' '' 'Proceed\?' y --
    check "the dry run finishes" exited_ok
    check "the wizard shows the choice" said "Sudo access:  password"
    check "the printed command carries the choice" said "--sudo-access password"
    refute "a dry run asks for no password" said "New password"
    check "nothing on the box changed" unchanged
}

scenario_wizard_nopasswd_works() {
    new_box
    tty_harden 'Username \[' deploy 'Use this key' y 'Choice \[1\]' 2 "${WIZARD_TAIL[@]}" \
        'Start with dry run' n 'Proceed\?' y --
    check "the run reports success" exited_ok
    check "the scorecard says so" said "[PASS] deploy can sudo (passwordless rule)"
    prove_can_get_root_nopasswd deploy
}

scenario_wizard_asks_nothing_when_sudo_works() {
    new_box
    in_box sh -c "useradd -m -G sudo deploy && echo 'deploy ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/deploy && chmod 440 /etc/sudoers.d/deploy"
    tty_harden 'Username \[' deploy 'Use this key' y "${WIZARD_TAIL[@]}" 'Start with dry run' n 'Proceed\?' y --
    check "the run reports success" exited_ok
    check "the wizard says nothing is needed" said "already has what sudo needs"
    prove_can_get_root_nopasswd deploy
}

# The usual workaround until now: a rule added by hand before running the tool.
scenario_existing_nopasswd_rule_needs_no_flag() {
    new_box
    in_box sh -c "useradd -m -s /bin/bash deploy && echo 'deploy ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/deploy && chmod 440 /etc/sudoers.d/deploy"
    harden --username deploy --ssh-key "$KEY" --only user,ssh,misc,verify
    check "the run reports success" exited_ok
    refute "it adds no rule of its own" in_box test -e /etc/sudoers.d/vps-harden-deploy
    prove_can_get_root_nopasswd deploy
}

scenario_existing_password_needs_no_flag() {
    new_box
    in_box sh -c "useradd -m -s /bin/bash -G sudo deploy && echo 'deploy:$USER_PW' | chpasswd"
    harden --username deploy --ssh-key "$KEY" --only user,ssh,misc,verify
    check "the run reports success" exited_ok
    prove_can_get_root_password deploy "$USER_PW"
}

scenario_existing_password_gets_sudo_group() {
    new_box
    in_box sh -c "useradd -m -s /bin/bash deploy && echo 'deploy:$USER_PW' | chpasswd"
    harden --username deploy --ssh-key "$KEY" --only user,ssh,misc,verify
    check "the run reports success" exited_ok
    prove_can_get_root_password deploy "$USER_PW"
}

# Some sudo versions wave an empty password through without asking, others refuse it. Either
# is fine, as long as the run only closes root if sudo really does work.
scenario_empty_password_never_locks_out() {
    new_box
    in_box sh -c "useradd -m -s /bin/bash -G sudo deploy && passwd -d deploy >/dev/null"
    snapshot
    harden --username deploy --ssh-key "$KEY"
    if exited_ok; then
        prove_can_get_root_nopasswd deploy
    else
        prove_stopped_untouched
    fi
}

scenario_narrow_rule_does_not_count() {
    new_box
    in_box sh -c "useradd -m -s /bin/bash -G sudo deploy && echo 'deploy ALL=(root) NOPASSWD: /usr/bin/true, /usr/local/bin/server-report' > /etc/sudoers.d/narrow && chmod 440 /etc/sudoers.d/narrow"
    snapshot
    harden --username deploy --ssh-key "$KEY"
    prove_stopped_untouched
}

scenario_rerun_is_idempotent() {
    new_box
    harden --username deploy --ssh-key "$KEY" --sudo-access nopasswd --only user,ssh,misc,verify
    check "first run finishes" exited_ok
    snapshot
    harden --username deploy --ssh-key "$KEY" --sudo-access nopasswd --only user,ssh,misc,verify
    check "second run finishes" exited_ok
    check "it notices the rule is there" said "already in /etc/sudoers.d/vps-harden-deploy"
    check "second run changes nothing" unchanged
    harden --username deploy --ssh-key "$KEY" --only user,ssh,misc,verify
    check "a later run needs no flag" exited_ok
}

scenario_password_rerun_does_not_ask_again() {
    new_box
    tty_harden 'New password' "$USER_PW" 'Confirm password' "$USER_PW" -- \
        --username deploy --ssh-key "$KEY" --sudo-access password --only user,ssh,misc,verify
    check "first run finishes" exited_ok
    harden --username deploy --ssh-key "$KEY" --sudo-access password --only user,ssh,misc,verify
    check "second run needs no terminal" exited_ok
    check "it keeps the password" said "already has a password, keeping it"
    prove_can_get_root_password deploy "$USER_PW"
}

scenario_switch_from_nopasswd_to_password() {
    new_box
    harden --username deploy --ssh-key "$KEY" --sudo-access nopasswd --only user,ssh,misc,verify
    check "first run finishes" exited_ok
    tty_harden 'New password' "$USER_PW" 'Confirm password' "$USER_PW" -- \
        --username deploy --ssh-key "$KEY" --sudo-access password --only user,ssh,misc,verify
    check "second run finishes" exited_ok
    refute "its own rule is gone" in_box test -e /etc/sudoers.d/vps-harden-deploy
    prove_can_get_root_password deploy "$USER_PW"
}

# A password set earlier cannot be tested. The rule may be how they got here, so it has to stay.
scenario_switch_with_untested_password_keeps_the_rule() {
    new_box
    harden --username deploy --ssh-key "$KEY" --sudo-access nopasswd --only user,ssh,misc,verify
    check "first run finishes" exited_ok
    in_box sh -c "echo 'deploy:$USER_PW' | chpasswd"
    harden --username deploy --ssh-key "$KEY" --sudo-access password --only user,ssh,misc,verify
    check "second run finishes" exited_ok
    check "it says why the rule stays" said "remove it yourself once you have seen sudo accept the password"
    check "the rule is still there" in_box test -e /etc/sudoers.d/vps-harden-deploy
    check "sudo without a password still works" sudo_without_password deploy
}

# PAM refuses every password for sudo here, so the new one cannot work. It also proves the test
# of the password is real: with the passwordless rule in place, sudo would not look at it.
scenario_password_sudo_rejects_stops() {
    new_box
    pam_denies_sudo
    tty_harden 'New password' "$USER_PW" 'Confirm password' "$USER_PW" -- \
        --username deploy --ssh-key "$KEY" --sudo-access password
    check "it stopped" stopped
    check "it says sudo rejected the password" said "sudo rejected the new password"
    refute "the rejected password is not left on the account" has_password deploy
    # The same command again has to ask and test again, not trust what the last run left behind.
    tty_harden 'New password' "$USER_PW" 'Confirm password' "$USER_PW" -- \
        --username deploy --ssh-key "$KEY" --sudo-access password
    check "a second try stops as well" stopped
    check "no SSH hardening was written" no_hardening
    check "root over SSH still works" root_over_ssh
    check "root still has its password" has_password root
}

# The misc module would lock the one password sudo asks for. A password set earlier cannot be
# tested, so this has to be spotted in sudoers.
scenario_sudo_asking_for_root_password_stops() {
    new_box
    in_box sh -c "useradd -m -s /bin/bash -G sudo deploy; echo 'deploy:$USER_PW' | chpasswd; echo 'Defaults rootpw' > /etc/sudoers.d/zz-rootpw; chmod 440 /etc/sudoers.d/zz-rootpw"
    snapshot
    harden --username deploy --ssh-key "$KEY"
    prove_stopped_untouched
    check "it says why" said "ask for root's password"
    harden --username deploy --ssh-key "$KEY" --sudo-access nopasswd --only user,ssh,misc,verify
    check "a passwordless rule gets past it" exited_ok
    prove_can_get_root_nopasswd deploy
}

scenario_the_opposite_setting_is_not_mistaken_for_it() {
    new_box
    in_box sh -c "useradd -m -s /bin/bash -G sudo deploy; echo 'deploy:$USER_PW' | chpasswd; echo 'Defaults !rootpw' > /etc/sudoers.d/zz-rootpw; chmod 440 /etc/sudoers.d/zz-rootpw"
    harden --username deploy --ssh-key "$KEY" --only user,ssh,misc,verify
    check "the run reports success" exited_ok
    prove_can_get_root_password deploy "$USER_PW"
}

# Modules run on the left of ||, so errexit is off inside them and only explicit checks stop them.
scenario_failed_key_ownership_still_aborts() {
    new_box
    # chown deploy:deploy fails because their primary group has another name.
    in_box useradd -m -s /bin/bash -g users deploy
    harden --username deploy --ssh-key "$KEY" --sudo-access nopasswd
    check "it stopped" stopped
    check "the user module is reported as failed" said "Critical module 'user' failed"
    check "no SSH hardening was written" no_hardening
    check "root over SSH still works" root_over_ssh
    check "root still has its password" has_password root
}

scenario_password_sudo_rejects_restores_the_rule() {
    new_box
    harden --username deploy --ssh-key "$KEY" --sudo-access nopasswd --only user,verify
    check "first run finishes" exited_ok
    pam_denies_sudo
    tty_harden 'New password' "$USER_PW" 'Confirm password' "$USER_PW" -- \
        --username deploy --ssh-key "$KEY" --sudo-access password --only user,verify
    check "it stopped" stopped
    check "it says sudo rejected the password" said "sudo rejected the new password"
    check "the rule is back" in_box test -e /etc/sudoers.d/vps-harden-deploy
    refute "no disabled copy is left" in_box test -e /etc/sudoers.d/vps-harden-deploy.off
    check "sudo without a password still works" sudo_without_password deploy
}

scenario_switch_keeps_someone_elses_rule() {
    new_box
    in_box sh -c "useradd -m -s /bin/bash deploy && echo 'deploy ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/mine && chmod 440 /etc/sudoers.d/mine"
    tty_harden 'New password' "$USER_PW" 'Confirm password' "$USER_PW" -- \
        --username deploy --ssh-key "$KEY" --sudo-access password --only user,verify
    check "it finishes" exited_ok
    check "it leaves that rule alone" in_box test -e /etc/sudoers.d/mine
    check "it warns about it" said "Another sudoers rule"
}

scenario_dotted_username_works() {
    new_box
    harden --username john.doe --ssh-key "$KEY" --sudo-access nopasswd --only user,ssh,misc,verify
    check "the run reports success" exited_ok
    check "the rule file has no dot, which sudo would skip" in_box test -e /etc/sudoers.d/vps-harden-john_doe
    prove_can_get_root_nopasswd john.doe
}

scenario_sudo_missing_gets_installed() {
    new_box
    remove_sudo
    check "sudo is really gone" sudo_gone
    harden --username deploy --ssh-key "$KEY" --sudo-access nopasswd --only prereqs,user,ssh,misc,verify
    check "the run reports success" exited_ok
    prove_can_get_root_nopasswd deploy
}

# A box the last release already closed, with a root shell still open: the run that fixes it.
scenario_recovery_from_a_root_shell() {
    old_box
    harden --username deploy --ssh-key "$KEY" --timezone UTC
    refute "the old run left no passwordless sudo" sudo_without_password deploy
    docker cp "$REPO/vps-harden.sh" "$BOX:/usr/local/bin/vps-harden" >/dev/null
    harden --username deploy --ssh-key "$KEY" --only verify
    check "verify reports the problem" said "[FAIL] deploy cannot sudo (no password and no passwordless sudo rule)"
    harden --username deploy --ssh-key "$KEY" --only misc
    check "it refuses to go further" stopped
    harden --username deploy --ssh-key "$KEY" --only user,verify --sudo-access nopasswd
    check "the flag fixes it" exited_ok
    prove_can_get_root_nopasswd deploy
}

# docs/getting-started.md sends anyone the last release locked out to rescue mode. A bind
# mount of the disk stands in for the rescue system.
scenario_rescue_mode_steps_work() {
    old_box
    harden --username deploy --ssh-key "$KEY" --timezone UTC
    prove_locked_out deploy
    in_box mount --bind / /mnt
    in_box answer 'New password:' "$USER_PW" 'Retype new password:' "$USER_PW" -- chroot /mnt passwd deploy >/dev/null 2>&1
    in_box umount /mnt
    check "typing the new password at sudo gets root" sudo_first_try deploy "$USER_PW"
}

# ── Scenarios: runs that do not close root are left alone ────────────────────
scenario_only_verify_never_stops() {
    new_box; snapshot
    harden --username deploy --ssh-key "$KEY" --only verify
    check "it finishes" exited_ok
    check "the scorecard shows the problem" said "[FAIL] deploy cannot sudo (new user"
    check "nothing on the box changed" unchanged
}

scenario_only_firewall_never_stops() {
    new_box
    harden --username deploy --ssh-key "$KEY" --only firewall
    check "it finishes" exited_ok
    refute "it has nothing to say about sudo" said "sudo"
}

scenario_skip_ssh_and_misc_keeps_root_open() {
    new_box
    harden --username deploy --ssh-key "$KEY" --skip ssh,misc
    check "it finishes" exited_ok
    check "it warns" said "cannot sudo yet"
    check "the scorecard shows the problem" said "[FAIL] deploy cannot sudo"
    check "root over SSH still works" root_over_ssh
    check "root still has its password" has_password root
}

# ── Scenarios: dry runs still change nothing ─────────────────────────────────
scenario_old_dry_run_changes_nothing() {
    old_box; snapshot
    harden --username deploy --ssh-key "$KEY" --dry-run
    check "it finishes" exited_ok
    check "nothing on the box changed" unchanged
}

scenario_dry_run_warns_and_changes_nothing() {
    new_box; snapshot
    harden --username deploy --ssh-key "$KEY" --dry-run
    check "it finishes" exited_ok
    check "it warns a real run would stop" said "a real run would stop here"
    check "the scorecard shows what to add" said "needs --sudo-access"
    check "it says what the printed command needs" said "or that command will stop"
    check "nothing on the box changed" unchanged
}

# The check really runs sudo as the user. A dry run has to leave no trace of that.
scenario_dry_run_with_working_sudo_changes_nothing() {
    new_box
    in_box sh -c "useradd -m -s /bin/bash -G sudo deploy && echo 'deploy ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/deploy && chmod 440 /etc/sudoers.d/deploy"
    snapshot
    harden --username deploy --ssh-key "$KEY" --dry-run
    check "it finishes" exited_ok
    check "the scorecard shows sudo works" said "[PASS] deploy can sudo (passwordless rule)"
    check "nothing on the box changed" unchanged
}

scenario_dry_run_nopasswd_changes_nothing() {
    new_box; snapshot
    harden --username deploy --ssh-key "$KEY" --dry-run --sudo-access nopasswd
    check "it finishes" exited_ok
    check "it shows the rule it would write" said "Would: Write passwordless sudo rule"
    check "the scorecard says it will be fixed" said "sudo rule) ← will fix"
    check "the printed command carries the choice" said "--sudo-access nopasswd"
    check "nothing on the box changed" unchanged
}

scenario_dry_run_password_asks_for_nothing() {
    new_box; snapshot
    tty_harden -- --username deploy --ssh-key "$KEY" --dry-run --sudo-access password
    check "it finishes" exited_ok
    refute "it asks for no password" said "New password"
    check "it shows what a real run would do" said "Would: Ask for a password"
    check "nothing on the box changed" unchanged
}

scenario_dry_run_password_without_terminal_warns() {
    new_box; snapshot
    harden --username deploy --ssh-key "$KEY" --dry-run --sudo-access password
    check "it finishes" exited_ok
    check "it warns a real run would stop" said "a real run from here would stop"
    check "nothing on the box changed" unchanged
}

# ── Scenarios: the SSH lockout protection is still there ─────────────────────
scenario_ssh_rollback_still_works() {
    new_box
    in_box sh -c "useradd -m -s /bin/bash deploy && echo 'deploy ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/deploy && chmod 440 /etc/sudoers.d/deploy"
    harden --username deploy --ssh-key "$KEY" --skip user
    check "it stopped" stopped
    check "the rollback ran" said "SSH config rolled back to prevent lockout"
    check "no SSH hardening is left" no_hardening
    check "root over SSH still works" root_over_ssh
}

# ── Scenarios: the scorecard tells the truth about SSH ───────────────────────
SSH_OPEN="[WARN] SSH (22/tcp) open to Anywhere"
SSH_RESTRICTED="[PASS] SSH restricted (not open to 0.0.0.0)"

# ssh_row open|restricted RULE ...: reads the scorecard with only these rules in an active firewall.
ssh_row() {
    local expected="$1" rule
    shift
    in_box sh -c 'ufw --force reset; ufw default deny incoming; ufw --force enable' >/dev/null 2>&1
    for rule in "$@"; do
        in_box sh -c "ufw $rule" >/dev/null 2>&1 || fail "ufw refused: $rule"
    done
    harden --username deploy --ssh-key "$KEY" --only verify
    if [[ "$expected" == "open" ]]; then
        check "with [$*]: the scorecard warns" said "$SSH_OPEN"
    else
        check "with [$*]: the scorecard passes" said "$SSH_RESTRICTED"
    fi
}

scenario_scorecard_warns_when_ssh_is_open() {
    new_box
    harden --username deploy --ssh-key "$KEY" --only verify
    check "with the firewall off, it warns" said "$SSH_OPEN"
    refute "with the firewall off, it does not pass" said "$SSH_RESTRICTED"

    harden --username deploy --ssh-key "$KEY" --only firewall,verify
    check "the firewall module leaves 22/tcp open" in_box sh -c 'ufw status | grep -E "^22/tcp +ALLOW +Anywhere"'
    check "that is what it warns about" said "$SSH_OPEN"
    refute "it does not also pass" said "$SSH_RESTRICTED"
    harden --username deploy --ssh-key "$KEY" --dry-run
    check "a dry run says what closes it" said "needs --netbird-key and --ssh-safety-ip"

    ssh_row open 'allow 22/tcp'
    ssh_row open 'allow ssh'
    ssh_row open 'allow 22'
    ssh_row open 'allow OpenSSH'
    ssh_row open 'limit 22/tcp'
    ssh_row open 'allow 22,80,443/tcp'
    ssh_row open 'allow 20:30/tcp'
    ssh_row open 'allow in on eth0 to any port 22 proto tcp'
    ssh_row open 'allow to 203.0.113.5 port 22 proto tcp'
    ssh_row open 'allow to 203.0.113.5'
    ssh_row open 'allow from any'
    ssh_row open 'allow from ::/0 to any port 22 proto tcp'
    ssh_row open "allow 22/tcp comment 'public'"
    ssh_row open 'default allow incoming'
}

# None of these lets a stranger reach SSH, though several say 22/tcp and Anywhere in one row.
scenario_scorecard_passes_when_ssh_is_restricted() {
    new_box
    ssh_row restricted
    ssh_row restricted 'allow in on wt0'
    ssh_row restricted 'allow in on wt0 to any port 22 proto tcp'
    ssh_row restricted 'allow from 203.0.113.10 to any port 22 proto tcp'
    ssh_row restricted 'allow from 2001:db8::1 to any port 22 proto tcp'
    ssh_row restricted 'allow from 203.0.113.10'
    ssh_row restricted 'deny 22/tcp'
    ssh_row restricted 'reject 22/tcp'
    ssh_row restricted 'allow out 22/tcp'
    ssh_row restricted 'route allow 22/tcp'
    ssh_row restricted 'allow out on wt0'
    ssh_row restricted 'allow 22/udp'
    ssh_row restricted 'allow 222/tcp' 'allow 2222/tcp' 'allow 80,443/tcp' 'allow 2200:2300/tcp'
    ssh_row restricted "allow 80/tcp comment '22/tcp ALLOW IN Anywhere'"
    ssh_row restricted "allow from 203.0.113.10 to any port 22 proto tcp comment 'ALLOW IN Anywhere'"
}

# A veth link stands in for Netbird's wt0, so the script's own modules do the tightening.
scenario_scorecard_follows_firewall_tighten() {
    new_box
    in_box ip link add wt0 type veth peer name wt0-peer
    harden --username deploy --ssh-key "$KEY" --only firewall,firewall_tighten,verify
    check "the tunnel rule is in" in_box sh -c 'ufw status | grep "Anywhere on wt0"'
    # firewall_tighten only removes the broad rule when it is given a safety IP.
    check "the broad rule is still there" in_box sh -c 'ufw status | grep -E "^22/tcp +ALLOW +Anywhere"'
    check "so it warns" said "$SSH_OPEN"
    harden --username deploy --ssh-key "$KEY" --ssh-safety-ip 203.0.113.10 --only firewall,firewall_tighten,verify
    refute "the broad rule is gone" in_box sh -c 'ufw status | grep -E "^22/tcp.*ALLOW +Anywhere"'
    check "the safety IP is in" in_box sh -c 'ufw status | grep -E "^22/tcp +ALLOW +203.0.113.10"'
    check "so it passes" said "$SSH_RESTRICTED"
}

# ── Scenarios: the commands it prints can be pasted ──────────────────────────
# A key with a comment a shell would trip over. sshd does not read comments, so it still logs in.
awkward_key() {
    printf '%s %s\n' "$(in_box cut -d' ' -f1,2 "$KEY")" "it's \$HOME \"my\" \`laptop\` a\\tb"
}

# Prints the command on the line after the one that matches.
printed_after() { sed -n "/$1/{n;s/\r//;s/^ *//;p;q;}" "$OUT"; }

# Runs a printed command as pasting it into a shell on the box would.
paste_command() {
    local command="$1"
    OUT="$WORK/${SCENARIO}.$BOX_COUNT.pasted.out"
    in_box bash -c "$command" > "$OUT" 2>&1 < /dev/null
    RC=$?
}

scenario_printed_command_keeps_inline_key_together() {
    new_box
    local plain key
    plain=$(in_box cat "$KEY")
    harden --username deploy --ssh-key "$plain" --sudo-access nopasswd --dry-run
    check "the dry run finishes" exited_ok
    paste_command "$(printed_after 'To apply changes, run') --dry-run"
    check "the printed command runs" exited_ok

    harden --username deploy --ssh-key "$KEY" --sudo-access nopasswd --dry-run
    check "a path stays as it is" said "--ssh-key $KEY --sudo-access"

    key=$(awkward_key)
    harden --username deploy --ssh-key "$key" --sudo-access nopasswd --dry-run
    check "the dry run finishes with an awkward comment" exited_ok
    paste_command "$(printed_after 'To apply changes, run')"
    check "the printed command runs for real" exited_ok
    check "the key arrives whole" in_box grep -qxF "$key" /home/deploy/.ssh/authorized_keys
    prove_can_get_root_nopasswd deploy
}

scenario_wizard_command_keeps_pasted_key_together() {
    new_box
    local key
    key=$(awkward_key)
    tty_harden 'Username \[' deploy 'Use this key' n 'Choice \[1\]' 3 'SSH public key:' "$key" 'Choice \[1\]' 2 \
        "${WIZARD_TAIL[@]}" 'Start with dry run' y 'Proceed\?' y --
    check "the dry run finishes" exited_ok
    paste_command "$(printed_after 'To apply changes, run')"
    check "the printed command runs for real" exited_ok
    check "the key arrives whole" in_box grep -qxF "$key" /home/deploy/.ssh/authorized_keys
    prove_can_get_root_nopasswd deploy
}

# ── Runner ───────────────────────────────────────────────────────────────────
ALL_SCENARIOS=$(grep -E '^scenario_[a-z_]+\(\)' "${BASH_SOURCE[0]}" | sed 's/^scenario_//; s/().*//')

if [[ "${1:-}" == "-l" ]]; then
    echo "$ALL_SCENARIOS"
    exit 0
fi

command -v docker >/dev/null || { echo "This test needs Docker."; exit 1; }
SELECTED="${*:-$ALL_SCENARIOS}"

echo "Building the test image from $BASE..."
docker build -q -t "$IMAGE" --build-arg "BASE=$BASE" "$HERE" >/dev/null || { echo "Could not build the test image"; exit 1; }
SUDO_VERSION=$(docker run --rm --entrypoint sudo "$IMAGE" --version | head -1)
echo "Testing against: $SUDO_VERSION"

for name in $SELECTED; do
    SCENARIO="$name"
    echo ""
    echo "── $name"
    "scenario_$name"
    remove_box
done

echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  $BASE ($SUDO_VERSION): $PASSED checks passed, $FAILED failed"
[[ $FAILED -eq 0 ]] || printf 'Failed:\n%s' "$FAILURES"
[[ $FAILED -eq 0 ]]
