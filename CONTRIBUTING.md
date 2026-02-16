# Contributing to vps-harden

Thanks for your interest in contributing! This project is intentionally simple — one Bash script, no dependencies — and contributions should keep it that way.

## Getting started

1. Fork the repo and clone your fork
2. Create a feature branch: `git checkout -b my-feature`
3. Make your changes
4. Run the checks: `shellcheck vps-harden.sh server-report && bash -n vps-harden.sh`
5. Submit a pull request

## Guidelines

### Code style

- **ShellCheck must pass.** Run `shellcheck vps-harden.sh server-report` before submitting.
- Use `bash -n` to verify syntax.
- Follow the existing patterns — look at how other modules are structured before adding new ones.
- Keep functions focused. One module = one security concern.
- Use `log_info`, `log_warn`, `log_ok`, and `die` for output — don't write directly to stdout.
- Support `--dry-run` in every module by checking `$DRY_RUN` and using `run_cmd` / `write_file`.

### Modules

Each module follows this pattern:

```bash
mod_example() {
    log_info "Description of what this module does"

    # Check current state before changing anything (idempotent)
    if [[ -f /etc/example.conf ]]; then
        log_ok "Already configured"
        return 0
    fi

    # Use run_cmd for commands, write_file for file creation
    run_cmd "Install example" apt-get install -y -qq example
    write_file "/etc/example.conf" "644" <<'CONF'
# config content here
CONF

    log_ok "Example configured"
}
```

Key rules:
- **Idempotent** — check state before acting. Safe to re-run.
- **Dry-run aware** — use `run_cmd` and `write_file`, never raw commands.
- **Non-interactive** — no prompts. Set `DEBIAN_FRONTEND=noninteractive` for apt.
- **Fail gracefully** — only `user` and `ssh` modules should abort on failure.

### Adding a new module

1. Add your function `mod_yourmodule()` in the appropriate position in the script
2. Add `yourmodule` to the `ALL_MODULES` array
3. Add it to `usage()` module list
4. Add verification checks to `mod_verify()`
5. Update the module table in `README.md`
6. Update `docs/getting-started.md` if the module needs explanation

### Verification checks

Every module should have corresponding checks in `mod_verify()`:

```bash
# In mod_verify()
if systemctl is-active --quiet example; then
    score_pass "example service active"
else
    score_fail "example service not running"
fi
```

### Commits

- Keep commits focused — one logical change per commit
- Write clear commit messages explaining *why*, not just *what*

## What we're looking for

Check the [open issues](https://github.com/ranjith-src/vps-harden/issues) for things to work on. Issues labeled [`good first issue`](https://github.com/ranjith-src/vps-harden/labels/good%20first%20issue) are a great starting point.

Some areas where contributions are welcome:
- New hardening modules (DNS, password policy, swap, AppArmor)
- Improved detection/verification in `mod_verify()`
- Broader OS/distro compatibility
- Documentation improvements
- Bug fixes

## Reporting issues

Use the [bug report template](https://github.com/ranjith-src/vps-harden/issues/new?template=bug_report.yml) for bugs and the [feature request template](https://github.com/ranjith-src/vps-harden/issues/new?template=feature_request.yml) for ideas.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
