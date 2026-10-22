# Changelog

## 1.1.2 — 2026-10-22

Fixes from a run on an Unraid host with 43 containers:
- Container labels no longer show the mount list when a container isn't a Swarm service.
- Container drift ignores what the image's own startup does: changes made within 5 minutes of a container's
  creation or latest start (judged by inode ctime, which package installs can't backdate), volume mount points,
  `/sbin/docker-init` and Python bytecode caches. Cron files are judged by what they run, and `/etc/passwd`
  only matters if it gains an extra UID 0 account. Six false "Container persistence" IOCs are gone.
- Large `docker diff` output no longer fails with "Argument list too long".
- Exposure distinguishes all interfaces, a public IP, and LAN/VPN-only addresses; Plex's "assume compromise"
  note only appears when it listens on all interfaces or a public IP.
- Unraid is detected; host PHP/nginx/kernel findings point to updating Unraid OS.
- The nginx config dump no longer writes warnings into nginx's error log.
- Works when piped (`curl … | sudo bash`); previously aborted on an unset `BASH_SOURCE`.
- "SSH keys changed" lists each key's comment, type and fingerprint so you can recognise your own.

## 1.1.1 — 2026-10-22

- Injection probes are classified by response: "failed" (all 4xx/3xx, or only the homepage) or "reached app"
  (2xx elsewhere, or 5xx — needs a closer look), with a status-code breakdown and IP count. IPs that sent probes
  and also made successful POSTs to PHP files are flagged.
- Log statistics use access-log lines only, so a request also logged in the error log is no longer counted twice.
- Status codes are read right after the request line, so logs with extra columns (e.g. CapRover) parse correctly.
- Remediation commands use `command grep` so they work when `grep` is aliased (e.g. to ripgrep).

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
