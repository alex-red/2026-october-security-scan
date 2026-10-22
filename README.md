# oct2026-scan

A single read-only Bash script that checks an Ubuntu, Debian or Proxmox VE server against the cluster of serious Linux server vulnerabilities disclosed in October 2026. It prints a short summary and the remediation steps that apply to what it found.

It **never installs, restarts or modifies anything**. The only network request it makes is to Plex's local `127.0.0.1:32400/identity` endpoint.

```bash
curl -fsSLO https://raw.githubusercontent.com/alex-red/2026-october-security-scan/main/oct2026-scan.sh
less oct2026-scan.sh          # read what you run
sudo bash oct2026-scan.sh
```

It runs without root, but then it can't read nginx config, other users' files or containers, and it skips the stale-process checks.

## What it checks

| Issue | CVE(s) | Fixed in | Exploited? |
|---|---|---|---|
| **PHP2Shell**: unauthenticated RCE in PHP core | CVE-2026-109618, CVE-2026-109619 | PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, or distro backport (e.g. Ubuntu 24.04 `8.3.6-0ubuntu0.24.04.13`) | Exploitation attempts reported |
| **NGINX** memory corruption | CVE-2026-15176, -93479, -97205 (plus -95101 HTTP/3, -97629 TLS tickets) | nginx 1.30.6 / 1.31.7 | No confirmed wide exploitation |
| **Plex2Shell**: SSRF → token leak → file write → RCE | CVE-2026-96652, -96654, -96655, -96656 | Plex Media Server 1.43.3.10861 | Yes, on the CISA KEV list (2026-10-20) |
| **PwnEscape**: KVM guest-to-host escape | CVE-2026-99999 | `proxmox-kernel-7.0.14-24-pve`, Debian `6.12.113-1` / `6.1.190-1`, upstream 6.18.57 | Lab PoC; public PoC code |
| **Nextcloud built-in CODE** command injection | CVE-2026-110447 | `richdocumentscode` 26.4.303 | Yes, webshells observed |
| **UpdraftCentral** stolen connection keys | (no CVE) | UpdraftPlus 1.26.13 / 2.26.13 | Yes, backdoor plugins |
| curl/libcurl HTTP/2 upload use-after-free | CVE-2026-92392 | curl 8.23.0 (affects 8.12.0–8.22.0) | — |
| Ghostscript | CVE-2026-101258, CVE-2026-103226 | Distro updates (USN-8949-1, DSA-6550-1) | — |
| SiteGuard Server Edition | CVE-2026-106931 | 8.00 Update 5 / 7.00 Update 6 | Yes |

It also checks for **signs that the server was already exploited**; see [Signs of exploitation](#signs-of-exploitation).

Other checks:

- **Container check.** It runs a small read-only probe inside each running Docker or Podman container, reporting PHP, NGINX, Plex, Nextcloud and UpdraftPlus versions *inside* the container. The host's packages don't tell you what a container runs.
- **Patched but not restarted.** It finds PHP and nginx processes still running an old (deleted) binary.
- **Fixed kernel installed but not booted.** It spots a fixed kernel package that the host hasn't rebooted into yet.
- **Exposure.** It lists which relevant ports listen on non-loopback addresses.

## Signs of exploitation

Patching stops new attacks but doesn't undo old ones. The second half of the report looks for what these attack paths leave behind. Each check runs on the host and inside every running container, and the section starts with a one-line verdict: **no signs found**, **REVIEW**, or **LIKELY COMPROMISED**.

| Where | What it looks for |
|---|---|
| Web roots | PHP files inside upload folders (`wp-content/uploads`, Drupal `files`, Laravel `storage`) · webshell code (`eval(base64_decode(…))`, `system($_POST…)`, known shell kits) in recently changed PHP files, or in **all** PHP files with `--deep` · `auto_prepend_file` in `.user.ini`/`.htaccess` (Wordfence and similar allow-listed) |
| WordPress | mu-plugins, drop-ins (`db.php`, `object-cache.php`) and plugin folders changed in the window; plugin changes on sites with UpdraftPlus are flagged higher · with `--deep`: admin/editor accounts created in the window, read from the site database |
| Logs | Successful requests to PHP files in `uploads/` · PHP memory-limit fatals (PHP2Shell's trigger condition) · segfaults of PHP/nginx/Apache/Plex workers, from web, PHP-FPM, kernel and container logs · injection probes, sorted by response: all rejected (4xx/3xx, or just the homepage) is reported as **failed**; a 2xx elsewhere or a 5xx is **reached app**, flagged for a closer look · IPs that sent probes and then made successful POSTs to PHP files |
| Processes | Shells or download tools running under php-fpm/Apache/nginx · shells or netcat holding network connections (reverse shells) · long-running CPU hogs (miners) · binaries running from `/tmp`, `/var/tmp`, `/dev/shm` · published miner/proxy names and attacker IPs |
| Persistence | `/etc/ld.so.preload` · extra UID 0 accounts · web users with login shells · download-and-run cron jobs or crontabs for `www-data` · systemd units running from temp dirs, or changed in the window · SSH `authorized_keys` and sudoers changed in the window · ELF and SUID files in temp dirs |
| Containers | `docker diff`: preload hooks, SSH keys, cron jobs (judged by what they run), extra root accounts, or new binaries in a container's own filesystem. Changes made by the image's startup (within 5 minutes of creation or the latest start, by inode ctime), volume mount points and bytecode caches are ignored |

The window starts at **2026-10-01** by default (`--since YYYY-MM-DD` to change it). Nextcloud CODE checks look back to 2026-09-10, when exploitation of that bug began.

**What it can't tell you:** a clean result is not proof of a clean server. Attackers delete logs and files, logs rotate, and container logs disappear when a container is recreated. Weak signals (memory fatals, plugin updates, changed systemd units) are marked `CHECK` because they're often your own activity. Strong ones (PHP in uploads, webshell code, reverse shells, preload hooks) are `IOC`.

`--deep` reads each containerized WordPress site's database to list new admins. It does this by running the site's `wp-config.php` with WordPress's `SHORTINIT` (no plugins or themes) as `www-data` inside the container. That's the only check that executes site code; it is off by default.

## Options

```
--json        machine-readable output
--no-docker   don't inspect containers
--deep        wider filesystem search, rotated logs, webshell scan of all PHP files,
              new WordPress admins (reads the site database)
--since DATE  start of the lookback for signs of exploitation (default 2026-10-01)
-q, --quiet   hide OK / N/A rows
--no-color    plain output (NO_COLOR is honoured too)
```

On the host, `--deep` uses wp-cli as the site's file owner with `--skip-plugins --skip-themes`, so possibly backdoored plugin code isn't loaded.

**Exit codes:** `0` nothing found · `1` something needs review · `2` vulnerable or indicator of compromise · `3` error. Use them from cron, Ansible and similar tools.

Rows with severity `INFO` never change the exit code. The main case is the PwnEscape kernel flaw on a host that runs no VMs: it needs a malicious VM guest, so there it's reported for information only. Otherwise every Ubuntu server would exit `1` until Ubuntu ships a fixed kernel.

## Reading the output

```
oct2026-scan 1.0.0 · pve01 · Debian GNU/Linux 12 (bookworm) · Proxmox VE 8.4.1 · kernel 6.8.12-1-pve · root ✓
──────────────────────────────────────────────────────────────────────
CRIT  VULNERABLE  Kernel PwnEscape               6.8.12-1-pve: Proxmox ships no fix for this kernel series …; KVM host, 4 VM(s) running [1]
CRIT  VULNERABLE  Plex Media Server 1.43.2.10500 container plex (plexinc/pms-docker): < 1.43.3.10861; … assume compromise [2]
HIGH  CHECK       NGINX 1.22.1                   host package: 1.22.1-9+deb12u2 — distro build; no vendor fix data as of 2026-10-22 [3]
      OK          PHP 8.2.35                     host php8.2 (fpm): 8.2.35-1~deb12u1 ≥ 8.2.35-1~deb12u1 (DLA-4848-1)
──────────────────────────────────────────────────────────────────────
Remediation
[1] PwnEscape KVM guest-to-host escape (CVE-2026-99999)
    …
```

| Status | Meaning |
|---|---|
| `IOC` | Sign of compromise found. Investigate before (or while) patching. |
| `VULNERABLE` | Installed version is below the fixed version. |
| `CHECK` | The scanner can't decide, e.g. a distro build it has no fix data for, a vendor that hasn't shipped a fix yet, or a suspicious-but-maybe-legit file. |
| `OK` / `N/A` / `SKIPPED` | Patched / not present / not inspected. |

### How versions are judged

Ubuntu and Debian **backport** fixes, so their package versions look older than upstream. For example, Ubuntu 24.04's fixed PHP is `8.3.6-…`, not `8.3.36`. The scanner therefore:

1. compares distro packages against the vendor's fixed package version (table at the top of the script), using dpkg version ordering;
2. compares upstream builds (Sury PPA, nginx.org repo, official Docker images, source builds) against the upstream fixed version;
3. reports `CHECK` when it has a distro build but no vendor data, instead of guessing.

## Limitations

- **The fix data is a snapshot from 2026-10-22.** Vendors keep shipping fixes. Ubuntu had no PwnEscape kernel and Debian 12 had no Ghostscript fix at that date, so those show as `CHECK` until the table is updated. Pull the latest script before running.
- **A clean result is not proof of a clean host.** Updating stops new exploitation; it does not remove a backdoor installed earlier. For anything that was internet-facing and vulnerable (PHP, Plex, Nextcloud CODE, UpdraftCentral-connected WordPress), do a proper compromise review.
- **Exposure is approximate.** "Listens on all interfaces" doesn't mean "reachable from the internet". Port forwarding, firewalls and Plex Relay change that.
- **Containers without a shell** (distroless images) can't be probed and are listed for manual checking.
- **Sites are checked once.** A host folder bind-mounted into a container's web root is checked through the container, not again on the host.
- **RPM distros** (RHEL, Alma, Rocky) aren't targeted. On those, most checks fall back to `CHECK` or `N/A`.

## Notes from source verification (2026-10-22)

Each fixed version above was checked against vendor or primary sources. These details differ from some early write-ups:

- **CVE-2026-93479** in nginx is a buffer overflow in *script evaluation* (string expressions with variables). The *map + regex* overflow is a different, older bug, CVE-2026-42533, fixed in 1.30.4 / 1.31.3. nginx.org rates all five October issues *medium*; F5 scores them CVSS 9.2.
- **Plex** shipped 1.43.3.10861 in early August 2026. Coverage disputes whether the first SSRF step needs a token: Plex says the token only has to *exist*, not be valid.
- **Proxmox** staff state only the 7.0.14 kernel series is supported; EOL kernel series (including the 6.8 series of Proxmox VE 8) get no PwnEscape fix.
- **UpdraftPlus:** use 1.26.13 / 2.26.13, not 1.26.12. Keys created on 2026-10-18 between 12:07 and 21:00 UTC can survive the update and need manual deletion.
- **Nextcloud CODE 26.4.303** actually shipped on 2026-09-11 as a silent fix. Exploitation was seen from 2026-09-10, before the advisory.
- The **upstream kernel 6.6.159** threshold comes from secondary reporting only; 6.18.57 and 6.12.113 are corroborated (PoC author, Debian DSA).

## Sources

- PHP: [Ubuntu PHP2Shell post](https://ubuntu.com/blog/php2shell-vulnerability-fixes-available) · [Ubuntu CVE-2026-109618](https://ubuntu.com/security/CVE-2026-109618) · [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-109618) · [AWS bulletin](https://aws.amazon.com/security/security-bulletins/2026-143-aws/)
- NGINX: [nginx security advisories](https://nginx.org/en/security_advisories.html) · [H-ISAC / F5 bulletin](https://www.aha.org/h-isac-white-reports/2026-10-19-h-isac-vulnerability-bulletin-tlp-white-f5-releases-out-band-security-updates-nginx-flaws)
- Plex: [The Hacker News: CISA KEV](https://thehackernews.com/2026/10/cisa-orders-federal-agencies-to-patch.html) · [The Hacker News: exploitation](https://thehackernews.com/2026/10/hackers-exploit-plex2shell-flaws-to.html) · [Security Affairs](https://securityaffairs.com/?p=201324)
- PwnEscape: [Proxmox forum](https://forum.proxmox.com/threads/cve-2026-99999-or-the-vercel-kvm-zero-day.187089/) · [VirtFusion status table](https://docs.virtfusion.com/security/pwnescape/) · [PoC repo](https://github.com/PeronGH/CVE-2026-99999)
- Nextcloud: [WZ-IT analysis](https://wz-it.com/en/blog/nextcloud-built-in-code-server-cve-2026-110447-rce-webshell/) · [OpenCVE](https://app.opencve.io/cve/CVE-2026-110447)
- UpdraftCentral: [TeamUpdraft incident post](https://teamupdraft.com/blog/security-incident-october-2026/) · [Nethemba analysis](https://nethemba.com/updraftcentral-backdoor-analysis/)
- curl: [JFrog write-up](https://research.jfrog.com/post/curl-http2-upload-rce-cve-2026-92392/) · [Debian tracker](https://security-tracker.debian.org/tracker/source-package/curl)
- Ghostscript: [USN-8949-1](https://ubuntu.com/security/notices/USN-8949-1) · [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-103226)
- SiteGuard: [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-exploit-siteguard-waf-flaw-to-run-commands-as-system-root/)

## Contributing

Fix data lives in `FIXED_DATA` near the top of `oct2026-scan.sh`. A new row needs a vendor advisory reference (USN, DSA/DLA, PSA…) in its last column. Run the tests before opening a PR:

```bash
bash tests/run.sh
shellcheck -x oct2026-scan.sh tests/run.sh
```

## License

MIT. See [LICENSE](LICENSE). Provided as-is, with no warranty: this is a triage aid, not a substitute for your vendors' advisories or a forensic investigation.
