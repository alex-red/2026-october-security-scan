# Changelog

## 1.1.0 — 2026-10-22

- New "Signs of exploitation" section with a one-line verdict: webshells and PHP in upload folders,
  `auto_prepend_file` backdoors, WordPress mu-plugin/drop-in/plugin changes and (with `--deep`) new admins,
  exploit traces in web/PHP/kernel/container logs, shells under web workers, reverse shells, miners,
  host persistence (preload, root accounts, cron, systemd, SSH keys, sudoers, temp-dir binaries) and
  `docker diff` drift. Runs on the host and inside every container.
- `--since DATE` sets the lookback (default 2026-10-01). JSON gains `kind`, `since` and `verdict`.
- Containers are labelled by Swarm service name and image; remediation shows host or container steps
  as appropriate, with CapRover / Swarm / Compose redeploy instructions.
- Host folders mounted into a container's web root are no longer reported twice.
- curl fix data for Ubuntu 26.04 / 26.10.
- Fixed: `awk: warning: escape sequence '\.'` on systems with gawk/mawk.

## 1.0.1 — 2026-10-22

- PwnEscape on a host that runs no VMs is now reported as INFO, and INFO rows no longer affect the exit code,
  so servers without KVM don't exit 1 while their vendor has no fixed kernel yet.
- "Containers without shell" raised to MED so un-inspectable containers still count as needing review.
- Fixed: flattening IOC lists could glob-expand `*` in process command lines or paths.

## 1.0.0 — 2026-10-22

- First release. Checks PHP2Shell, NGINX (Oct 14 releases), Plex2Shell, PwnEscape, Nextcloud built-in CODE,
  UpdraftCentral keys, curl, Ghostscript and SiteGuard on Ubuntu, Debian and Proxmox VE, including running containers.
- Fix data as of 2026-10-22.
