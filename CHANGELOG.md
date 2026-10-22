# Changelog

## 1.0.1 — 2026-10-22

- PwnEscape on a host that runs no VMs is now reported as INFO, and INFO rows no longer affect the exit code,
  so servers without KVM don't exit 1 while their vendor has no fixed kernel yet.
- "Containers without shell" raised to MED so un-inspectable containers still count as needing review.
- Fixed: flattening IOC lists could glob-expand `*` in process command lines or paths.

## 1.0.0 — 2026-10-22

- First release. Checks PHP2Shell, NGINX (Oct 14 releases), Plex2Shell, PwnEscape, Nextcloud built-in CODE,
  UpdraftCentral keys, curl, Ghostscript and SiteGuard on Ubuntu, Debian and Proxmox VE, including running containers.
- Fix data as of 2026-10-22.
