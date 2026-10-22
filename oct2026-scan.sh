#!/usr/bin/env bash
# oct2026-scan — read-only exposure check for the October 2026 Linux server
# vulnerability cluster: PHP2Shell, NGINX, Plex2Shell, PwnEscape, Nextcloud
# Collabora built-in CODE, UpdraftCentral keys, curl, Ghostscript, SiteGuard.
#
# It never installs, restarts or modifies anything. The only network request it
# makes is to Plex's local identity endpoint on 127.0.0.1:32400.
#
# Usage: sudo bash oct2026-scan.sh [--json] [--no-docker] [--deep] [--quiet] [--no-color]
# https://github.com/alex-red/2026-october-security-scan
# License: MIT — Copyright (c) 2026 Alex Red

set -u
set -o pipefail

SCAN_VERSION="1.1.0"
DATA_DATE="2026-10-22"

# ---------------------------------------------------------------------------
# Fixed-version data. One row per (component, distro, codename, source package).
# Columns: component distro codename source-package fixed-version reference
# Versions are Debian/Ubuntu package versions, compared with dpkg semantics.
# Keep each row sourced from a vendor advisory; see README for links.
# ---------------------------------------------------------------------------
FIXED_DATA='
php         ubuntu stonking php8.5       8.5.9-0ubuntu2.1                 USN-8948-1
php         ubuntu resolute php8.5       8.5.4-0ubuntu1.5                 USN-8948-1
php         ubuntu noble    php8.3       8.3.6-0ubuntu0.24.04.13          USN-8948-1
php         ubuntu jammy    php8.1       8.1.2-1ubuntu2.28                USN-8948-1
php         ubuntu focal    php7.4       7.4.3-4ubuntu2.29+esm5           USN-8948-2(Ubuntu-Pro)
php         ubuntu bionic   php7.2       7.2.24-0ubuntu0.18.04.17+esm14   USN-8948-2(Ubuntu-Pro)
php         ubuntu xenial   php7.0       7.0.33-0ubuntu0.16.04.16+esm22   USN-8948-2(Pro-Legacy)
php         ubuntu trusty   php5         5.5.9+dfsg-1ubuntu4.29+esm18     USN-8948-2(Pro-Legacy)
php         debian trixie   php8.4       8.4.27-1~deb13u1                 DSA-6574-1
php         debian bookworm php8.2       8.2.35-1~deb12u1                 DLA-4848-1
php         debian bullseye php7.4       7.4.33-1+deb11u14                Freexian-ELTS
kernel      debian trixie   linux        6.12.113-1                       DSA-6568-1
kernel      debian bookworm linux        6.1.190-1                        DLA-4841-1
ghostscript ubuntu stonking ghostscript  10.07.1~dfsg-1ubuntu2.1          USN-8949-1
ghostscript ubuntu resolute ghostscript  10.06.0~dfsg-3ubuntu1.2          USN-8949-1
ghostscript ubuntu noble    ghostscript  10.02.1~dfsg1-0ubuntu7.10        USN-8949-1
ghostscript ubuntu jammy    ghostscript  9.55.0~dfsg1-0ubuntu5.15         USN-8949-1
ghostscript ubuntu focal    ghostscript  9.50~dfsg-5ubuntu4.15+esm3       USN-8949-1(Ubuntu-Pro)
ghostscript debian trixie   ghostscript  10.05.1~dfsg-1+deb13u3           DSA-6550-1
curl        ubuntu stonking curl         8.20.0-2ubuntu11.1               ubuntu.com/security/CVE-2026-92392
curl        ubuntu resolute curl         8.18.0-1ubuntu2.8                ubuntu.com/security/CVE-2026-92392
'

# Upstream thresholds
PHP_UPSTREAM_FIXED="8.5:8.5.12 8.4:8.4.27 8.3:8.3.36 8.2:8.2.35"
PLEX_FIXED="1.43.3.10861"
NEXTCLOUD_CODE_FIXED="26.4.303"
UPDRAFT_FREE_FIXED="1.26.13"
UPDRAFT_PREMIUM_FIXED="2.26.13"
PVE_KERNEL_FIXED="7.0.14-24"
KERNEL_STABLE_FIXED="6.18:6.18.57 6.12:6.12.113 6.6:6.6.159"
CURL_AFFECTED_FROM="8.12.0"
CURL_FIXED="8.23.0"
# Attack window starts used for "changed since" audits
UPDRAFT_INCIDENT_START="2026-10-17"
PHP2SHELL_DISCLOSED="2026-10-21"
# Published indicators: Plex2Shell (miner/proxy payloads) and Nextcloud CODE attacks
IOC_IPS="217.60.194.116 91.92.40.202 176.65.139.228 45.194.92.222 139.28.18.122 89.38.98.50"
IOC_PROC_RE='xmrig|--donate-level|--rig-id|myawesomeproxy|mylovelyminer|proxystream|(^|[/ ])x12345( |$)'

# --- Signs of exploitation ---------------------------------------------------
# Default lookback for "changed since" checks (--since overrides). Earliest
# activity in this cluster: Nextcloud CODE 2026-09-10 (checked separately),
# Plex2Shell PoC 10-16, UpdraftCentral 10-17, PHP2Shell attempts 10-17/10-21.
IOC_SINCE_DEFAULT="2026-10-01"
# Webshell code patterns (POSIX ERE; also used by busybox grep inside containers)
WEBSHELL_RE='eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode|\$_(POST|GET|REQUEST|COOKIE|SERVER))|(assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE)|\$_(POST|GET|REQUEST|COOKIE)[[:space:]]*\[[^]]*\][[:space:]]*\(|create_function[[:space:]]*\([^)]*\$_(POST|GET|REQUEST|COOKIE)|FilesMan|b374k|r57shell|c99shell|IndoXploit|ALFA_DATA|WSOsetcookie'
# Download-and-execute / reverse-shell patterns in cron jobs and unit files
DL_EXEC_RE='(curl|wget)[^|;]*\|[[:space:]]*(ba|da)?sh|base64[[:space:]]+(-d|--decode)|/dev/tcp/|(nc|ncat|netcat)[[:space:]].*-e[[:space:]]|python[0-9.]*[[:space:]]+-c|(ba)?sh[[:space:]]+-i'
# Web workers, and children that should never run under them
WEB_PARENT_RE='php-fpm|php-cgi|apache2|httpd|lsphp|frankenphp|nginx: worker'
SUSP_CHILD_RE='^(sh|bash|dash|ash|zsh|ksh|perl|python[0-9.]*|ruby|nc|ncat|netcat|socat|curl|wget|busybox|base64|id|whoami|uname|telnet|xmrig)$'
# Mail delivery legitimately runs "sh -c sendmail" under PHP
WEB_CHILD_OK_RE='sendmail|msmtp|ssmtp|exim|postdrop'
# Processes holding network connections that should only be interactive tools
NET_SHELL_RE='^(sh|bash|dash|ash|zsh|ksh|nc|ncat|netcat|socat|telnet)$'
# Long-running high-CPU processes that are normal on servers
CPU_OK_RE='^(kvm|qemu-system|ffmpeg|Plex Transcoder|HandBrakeCLI|mysqld|mariadbd|postgres|java|node|dockerd|containerd|kworker|ksoftirqd|z_|zfs|txg_sync|rsync|borg|restic|gzip|xz|zstd|pigz|clamscan|apt|dpkg|unattended-upgr|php-fpm|apache2|nginx)'
# auto_prepend_file values used by legitimate security plugins
PREPEND_OK_RE='wordfence-waf\.php|ninjafirewall|malcare|sucuri|bbq-firewall'
# Remediation keys that describe evidence of exploitation (vs. a missing patch)
COMPROMISE_REMS=" ioc webshell wp_ioc persistence attempts crash drift cpu plex_ioc nextcloud_ioc "

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
OPT_JSON=0
OPT_DOCKER=1
OPT_DEEP=0
OPT_QUIET=0
OPT_COLOR=auto
SINCE=$IOC_SINCE_DEFAULT
DAYS=30

usage() {
	cat <<EOF
oct2026-scan $SCAN_VERSION — read-only check for the October 2026 Linux server vulnerabilities
(data as of $DATA_DATE)

Usage: sudo bash oct2026-scan.sh [options]

  --json        machine-readable output
  --no-docker   do not inspect running containers (docker exec / podman exec)
  --deep        wider filesystem search, rotated logs, webshell scan of ALL PHP files (not only
                recently changed ones), and new WordPress admin accounts (reads the site database)
  --since DATE  lookback for signs of exploitation, YYYY-MM-DD (default $IOC_SINCE_DEFAULT)
  -q, --quiet   hide OK / N/A rows
  --no-color    disable colors (NO_COLOR is honoured too)
  -h, --help    this help
  -V, --version print version

Exit codes: 0 nothing found, 1 needs review (CHECK), 2 vulnerable or indicator of compromise, 3 error
(INFO rows, such as the kernel flaw on a host that runs no VMs, don't affect the exit code)
Latest version: https://github.com/alex-red/2026-october-security-scan
EOF
}

parse_args() {
	while [ $# -gt 0 ]; do
		case $1 in
		--json) OPT_JSON=1 ;;
		--no-docker) OPT_DOCKER=0 ;;
		--deep) OPT_DEEP=1 ;;
		--since)
			case ${2:-} in
			[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]) SINCE=$2; shift ;;
			*) echo "--since needs a date like 2026-10-01" >&2; exit 3 ;;
			esac
			;;
		-q | --quiet) OPT_QUIET=1 ;;
		--no-color) OPT_COLOR=never ;;
		-h | --help) usage; exit 0 ;;
		-V | --version) echo "oct2026-scan $SCAN_VERSION (data $DATA_DATE)"; exit 0 ;;
		*) echo "unknown option: $1" >&2; usage >&2; exit 3 ;;
		esac
		shift
	done
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

# oneline TEXT: join lines/whitespace runs into one space-separated line (no glob expansion)
oneline() { printf '%s\n' "$1" | tr -s ' \t\n' '   ' | sed 's/^ //; s/ $//'; }

# Debian version comparison (dpkg algorithm) in awk; used when dpkg is absent.
# Prints -1, 0 or 1.
vcmp_awk() {
	awk -v a="$1" -v b="$2" '
	function ord(c) { if (c == "") return 0; if (c ~ /[0-9]/) return 0; if (c == "~") return -1
		if (c ~ /[A-Za-z]/) return O[c]; return O[c] + 256 }
	function part(a, b,   ac, bc, na, nb) {
		while (a != "" || b != "") {
			while ((a != "" && substr(a,1,1) !~ /[0-9]/) || (b != "" && substr(b,1,1) !~ /[0-9]/)) {
				ac = ord(substr(a,1,1)); bc = ord(substr(b,1,1))
				if (ac != bc) return ac < bc ? -1 : 1
				a = substr(a,2); b = substr(b,2)
			}
			match(a, /^[0-9]*/); na = substr(a,1,RLENGTH) + 0; a = substr(a,RLENGTH+1)
			match(b, /^[0-9]*/); nb = substr(b,1,RLENGTH) + 0; b = substr(b,RLENGTH+1)
			if (na != nb) return na < nb ? -1 : 1
		}
		return 0
	}
	function split3(v, r,   i) {
		r["e"] = 0; i = index(v, ":"); if (i) { r["e"] = substr(v,1,i-1) + 0; v = substr(v,i+1) }
		r["r"] = ""; if (match(v, /-[^-]*$/)) { r["r"] = substr(v,RSTART+1); v = substr(v,1,RSTART-1) }
		r["u"] = v
	}
	BEGIN {
		for (i = 1; i < 256; i++) O[sprintf("%c", i)] = i
		split3(a, A); split3(b, B)
		if (A["e"] != B["e"]) { print (A["e"] < B["e"] ? -1 : 1); exit }
		c = part(A["u"], B["u"]); if (c == 0) c = part(A["r"], B["r"])
		print c
	}'
}

# vlt A B: true when version A sorts before B
vlt() {
	if [ "${OCT_SCAN_VCMP:-}" != awk ] && have dpkg; then
		dpkg --compare-versions "$1" lt "$2"
	else
		[ "$(vcmp_awk "$1" "$2")" = "-1" ]
	fi
}
vge() { ! vlt "$1" "$2"; }

# upstream VERSION: strip epoch, Debian revision and ~/+ suffixes → 8.3.6
upstream() {
	local v=${1#*:}
	v=${v%%-*}; v=${v%%~*}; v=${v%%+*}
	printf '%s' "$v"
}

# Distro-built package (fixes are backported, so upstream comparisons don't apply)
is_distro_build() {
	case $1 in
	*sury*) return 1 ;;
	*ubuntu* | *deb[0-9]* | *+esm*) return 0 ;;
	esac
	return 1
}

fixed_lookup() { # component distro codename srcpkg → "version reference"
	printf '%s\n' "$FIXED_DATA" | awk -v c="$1" -v d="$2" -v r="$3" -v s="$4" \
		'$1 == c && $2 == d && $3 == r && $4 == s { print $5, $6; exit }'
}

kv_lookup() { # "k:v k:v" key → v
	local pair
	for pair in $1; do
		[ "${pair%%:*}" = "$2" ] && { printf '%s' "${pair#*:}"; return 0; }
	done
	return 1
}

php_upstream_fixed() { kv_lookup "$PHP_UPSTREAM_FIXED" "$(printf '%s' "$1" | cut -d. -f1-2)"; }

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
F_SEV=()
F_STAT=()
F_COMP=()
F_DETAIL=()
F_REM=()
F_KIND=()
# Section new findings go to: vuln (missing patches) or ioc (signs of exploitation)
CUR_KIND=vuln

# add SEVERITY STATUS COMPONENT DETAIL [REMEDIATION-KEY]
# SEVERITY: CRIT HIGH MED LOW INFO
# STATUS:   IOC VULNERABLE CHECK OK N/A SKIPPED
add() {
	local kind=$CUR_KIND
	[ "$2" = IOC ] && kind=ioc
	case $COMPROMISE_REMS in *" ${5:-none} "*) kind=ioc ;; esac
	F_SEV[${#F_SEV[@]}]=$1
	F_STAT[${#F_STAT[@]}]=$2
	F_COMP[${#F_COMP[@]}]=$3
	F_DETAIL[${#F_DETAIL[@]}]=$4
	F_REM[${#F_REM[@]}]=${5:-}
	F_KIND[${#F_KIND[@]}]=$kind
}

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
IS_ROOT=0
OS_ID=unknown
OS_CODENAME=""
OS_PRETTY=""
IS_PVE=0
KREL=""
KVER=""
HOST=""
DPKG_DB=""
LISTEN=""
PS_OUT=""
CTR=""
PLEX_SEEN=0
SWARM=0
CAPROVER=0
# Host paths bind-mounted into inspected containers' web roots (checked there, not twice)
COVERED=""
# WordPress roots (host paths) that have UpdraftPlus installed
UPDRAFT_SITES=""

# is_covered PATH: PATH lies inside a directory already inspected through a container
is_covered() {
	local c
	for c in $COVERED; do
		case $1 in "$c" | "$c"/*) return 0 ;; esac
	done
	return 1
}

detect_env() {
	[ "$(id -u)" = 0 ] && IS_ROOT=1
	OS_PRETTY=$(uname -s)
	# shellcheck disable=SC1091 # /etc/os-release is read on the scanned host
	if [ -r /etc/os-release ]; then
		local id like cn ucn pretty
		id=$(. /etc/os-release; printf '%s' "${ID:-unknown}")
		like=$(. /etc/os-release; printf '%s' "${ID_LIKE:-}")
		cn=$(. /etc/os-release; printf '%s' "${VERSION_CODENAME:-}")
		ucn=$(. /etc/os-release; printf '%s' "${UBUNTU_CODENAME:-}")
		pretty=$(. /etc/os-release; printf '%s' "${PRETTY_NAME:-$id}")
		OS_ID=$id OS_CODENAME=$cn OS_PRETTY=$pretty
		# Ubuntu derivatives (Mint, Pop!_OS…) use Ubuntu's packages
		case " $like " in *" ubuntu "*) [ -n "$ucn" ] && { OS_ID=ubuntu; OS_CODENAME=$ucn; } ;; esac
	fi
	if have pveversion || [ -d /etc/pve ]; then
		IS_PVE=1
		local pv
		pv=$(pveversion 2>/dev/null | sed -n 's|^pve-manager/\([0-9.]*\).*|\1|p')
		OS_PRETTY="$OS_PRETTY · Proxmox VE ${pv:-?}"
	fi
	KREL=$(uname -r)
	KVER=$(uname -v)
	HOST=$(hostname 2>/dev/null || uname -n)
	if have dpkg-query; then
		DPKG_DB=$(dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${source:Package}\t${Version}\n' 2>/dev/null |
			awk -F'\t' '$1 ~ /^ii/ { print $2 "\t" $3 "\t" $4 }')
	fi
	if have ss; then
		LISTEN=$(ss -lntu 2>/dev/null | awk 'NR > 1 { print $5 }')
	fi
	PS_OUT=$(ps -eo pid=,ppid=,user=,args= 2>/dev/null)
}

# src_versions REGEX → "srcpkg<TAB>version" for installed packages whose source matches
src_versions() {
	printf '%s\n' "$DPKG_DB" | awk -F'\t' -v re="$1" '$2 ~ re { print $2 "\t" $3 }' | sort -u
}
pkg_version() { printf '%s\n' "$DPKG_DB" | awk -F'\t' -v p="$1" '$1 == p { print $3; exit }'; }
src_binaries() { printf '%s\n' "$DPKG_DB" | awk -F'\t' -v s="$1" '$2 == s { print $1 }'; }

# public_port PORT: a listener on PORT that is not bound to loopback
public_port() {
	printf '%s\n' "$LISTEN" | awk -v p="$1" '
		{ n = split($1, a, ":"); port = a[n]; addr = substr($1, 1, length($1) - length(port) - 1)
		  if (port == p && addr !~ /^(127\.|\[::1\]|::1|\[::ffff:127\.)/) f = 1 }
		END { exit !f }'
}

# apt_pending INSTALLED-VERSION BINARY-PKG → candidate version if apt knows a newer one
apt_pending() {
	have apt-cache || return 1
	local cand
	cand=$(apt-cache policy "$2" 2>/dev/null | awk '/Candidate:/ { print $2; exit }')
	[ -n "$cand" ] && [ "$cand" != "(none)" ] && vlt "$1" "$cand" && printf '%s' "$cand"
}

# stale_procs PGREP-PATTERN MAPS-REGEX → number of matching processes still mapping a
# replaced (deleted) binary or library, i.e. upgraded but not restarted. Needs root.
stale_procs() {
	[ "$IS_ROOT" = 1 ] || { echo 0; return; }
	local n=0 pid
	for pid in $(pgrep -f "$1" 2>/dev/null); do
		grep -E "$2" "/proc/$pid/maps" 2>/dev/null | grep -q '(deleted)' && n=$((n + 1))
	done
	echo "$n"
}

newer_than() { # DIR DATE → files/dirs directly in DIR modified since DATE
	find "$1" -mindepth 1 -maxdepth 1 -newermt "$2" 2>/dev/null
}

# Roots searched for web apps on the host
web_roots() {
	local r
	local roots="/var/www /srv /opt /home /usr/share/nginx /usr/share/webapps /var/lib/nextcloud /snap/nextcloud/current"
	# --deep: whole top-level trees (each stays on its own filesystem, see -xdev)
	[ "$OPT_DEEP" = 1 ] && roots="/var /srv /opt /home /root /usr/share /usr/local /mnt /data /www /snap/nextcloud/current"
	for r in $roots; do
		[ -d "$r" ] && echo "$r"
	done
}

find_in_roots() { # -path PATTERN, depth
	local depth=$2 roots
	roots=$(web_roots)
	[ -n "$roots" ] || return 0
	[ "$OPT_DEEP" = 1 ] && depth=10
	# shellcheck disable=SC2086
	find $roots -xdev -maxdepth "$depth" \( -path /var/lib/docker -o -path /var/lib/containers -o -path /var/cache \
		-o -path /var/log \) -prune -o -path "$1" -print 2>/dev/null
}

# ---------------------------------------------------------------------------
# Evaluators (shared by host and container checks)
# ---------------------------------------------------------------------------

# eval_php LABEL SRCPKG VERSION DISTRO CODENAME pkg|raw
eval_php() {
	local label=$1 src=$2 ver=$3 os=$4 cn=$5 kind=$6 up fx="" ref="" row
	up=$(upstream "$ver")
	[ -n "$up" ] || { add CRIT CHECK "PHP" "$label: version could not be read" php; return; }
	if [ "$kind" = pkg ] && is_distro_build "$ver"; then
		row=$(fixed_lookup php "$os" "$cn" "$src")
		fx=${row%% *} ref=${row#* }
	fi
	if [ -n "$fx" ]; then
		if vlt "$ver" "$fx"; then
			case $ref in
			*Pro*) add CRIT VULNERABLE "PHP $up" "$label: $ver < $fx ($ref — needs Ubuntu Pro / ELTS)" php_eol ;;
			*) add CRIT VULNERABLE "PHP $up" "$label: $ver < $fx ($ref)" php ;;
			esac
		else
			add CRIT OK "PHP $up" "$label: $ver ≥ $fx ($ref)"
		fi
		return
	fi
	if [ "$kind" = pkg ] && is_distro_build "$ver"; then
		add CRIT CHECK "PHP $up" "$label: $ver — no fix data for $os ${cn:-?}; check your vendor's advisory" php
		return
	fi
	fx=$(php_upstream_fixed "$up")
	if [ -z "$fx" ]; then
		add CRIT VULNERABLE "PHP $up" "$label: branch is end-of-life upstream, no PHP2Shell fix" php_eol
	elif vlt "$up" "$fx"; then
		add CRIT VULNERABLE "PHP $up" "$label: $up < $fx" php
	else
		add CRIT OK "PHP $up" "$label: $up ≥ $fx"
	fi
}

# eval_nginx LABEL VERSION [EXTRA-DETAIL]
eval_nginx() {
	local label=$1 ver=$2 extra=${3:-} up
	up=$(upstream "$ver")
	[ -n "$up" ] || { add HIGH CHECK "NGINX" "$label: version could not be read" nginx; return; }
	if vge "$up" 1.31.7 || { vge "$up" 1.30.6 && vlt "$up" 1.31.0; }; then
		add HIGH OK "NGINX $up" "$label: ≥ 1.30.6/1.31.7$extra"
	elif is_distro_build "$ver"; then
		add HIGH CHECK "NGINX $up" "$label: $ver — distro build; no vendor fix data as of $DATA_DATE$extra" nginx
	else
		add HIGH VULNERABLE "NGINX $up" "$label: $up < 1.30.6 / 1.31.7$extra" nginx
	fi
}

# eval_plex LABEL VERSION
eval_plex() {
	local label=$1 up exp=""
	up=$(upstream "$2")
	PLEX_SEEN=1
	if vlt "$up" "$PLEX_FIXED"; then
		public_port 32400 && exp="; port 32400 listens on all interfaces — assume compromise"
		add CRIT VULNERABLE "Plex Media Server $up" "$label: < $PLEX_FIXED$exp" plex
	else
		add CRIT OK "Plex Media Server $up" "$label: ≥ $PLEX_FIXED"
	fi
}

# plex_codecs_eval LABEL CODECS-DIR SO-PATHS(newline separated)
# Plex's own codecs live in versioned sub-directories and are named lib*_decoder.so /
# lib*_encoder.so. Shared objects at the top level of Codecs/ are the Plex2Shell
# persistence pattern; other unusual names are worth a look.
plex_codecs_eval() {
	local label=$1 dir=$2 p rel name top="" odd=""
	while IFS= read -r p; do
		[ -n "$p" ] || continue
		rel=${p#"$dir"/}
		case $rel in
		*/*)
			name=${rel##*/}
			case $name in lib*_decoder.so | lib*_encoder.so) ;; *) odd="$odd $rel" ;; esac
			;;
		*) top="$top $rel" ;;
		esac
	done <<EOF
$3
EOF
	[ -n "$top" ] && add CRIT IOC "Plex Codecs directory" "$label: shared objects directly in Codecs/:$top" plex_ioc
	[ -n "$odd" ] && add HIGH CHECK "Plex Codecs directory" "$label: unusual codec files:$odd" plex_ioc
	return 0
}

# eval_nextcloud_code LABEL VERSION
eval_nextcloud_code() {
	if [ -z "$2" ]; then
		add HIGH CHECK "Nextcloud built-in CODE" "$1: version unreadable" nextcloud
	elif vlt "$2" "$NEXTCLOUD_CODE_FIXED"; then
		add HIGH VULNERABLE "Nextcloud built-in CODE $2" "$1: < $NEXTCLOUD_CODE_FIXED (disabling the app is not enough)" nextcloud
	else
		add HIGH OK "Nextcloud built-in CODE $2" "$1: ≥ $NEXTCLOUD_CODE_FIXED"
	fi
}

# eval_updraft LABEL VERSION
eval_updraft() {
	local fx=$UPDRAFT_FREE_FIXED edition=free
	case $2 in 2.*) fx=$UPDRAFT_PREMIUM_FIXED edition=Premium ;; esac
	if [ -z "$2" ]; then
		add HIGH CHECK "UpdraftPlus" "$1: version unreadable" updraft
	elif vlt "$2" "$fx"; then
		add HIGH VULNERABLE "UpdraftPlus $2" "$1: $edition < $fx — stolen UpdraftCentral keys still accepted" updraft
	else
		add HIGH OK "UpdraftPlus $2" "$1: ≥ $fx (old keys revoked; backdoors added earlier are not removed)"
	fi
}

# eval_kernel IS_PVE DISTRO CODENAME UNAME_R UNAME_V KVM_HOST(0/1) CONTEXT
eval_kernel() {
	local pve=$1 os=$2 cn=$3 rel=$4 uv=$5 kvm=$6 ctx=$7 sev=INFO base fx="" row ref
	[ "$kvm" = 1 ] && sev=CRIT
	if [ "$pve" = 1 ] && [ "${rel%-pve}" != "$rel" ]; then
		base=${rel%-pve}
		case $base in
		7.0.*)
			if vlt "$base" "$PVE_KERNEL_FIXED"; then
				add $sev VULNERABLE "Kernel PwnEscape" "$rel < $PVE_KERNEL_FIXED-pve; $ctx" kernel
			else
				add $sev OK "Kernel PwnEscape" "$rel ≥ $PVE_KERNEL_FIXED-pve; $ctx"
			fi
			;;
		*) add $sev VULNERABLE "Kernel PwnEscape" "$rel: Proxmox ships no fix for this kernel series (fixed: proxmox-kernel-$PVE_KERNEL_FIXED-pve); $ctx" kernel ;;
		esac
		return
	fi
	if [ "$os" = debian ]; then
		base=$(printf '%s' "$uv" | sed -n 's/.*Debian \([0-9][^ ]*\).*/\1/p')
		row=$(fixed_lookup kernel debian "$cn" linux)
		fx=${row%% *} ref=${row#* }
		case $base in *bpo*) fx="" ;; esac # backports kernel: different series, no table entry
		if [ -n "$base" ]; then
			if [ -z "$fx" ]; then
				add $sev CHECK "Kernel PwnEscape" "$rel (Debian $base): no fix data for this kernel; check security-tracker.debian.org; $ctx" kernel
			elif vlt "$base" "$fx"; then
				add $sev VULNERABLE "Kernel PwnEscape" "$rel (Debian $base) < $fx ($ref); $ctx" kernel
			else
				add $sev OK "Kernel PwnEscape" "$rel (Debian $base) ≥ $fx ($ref); $ctx"
			fi
			return
		fi
	fi
	if [ "$os" = ubuntu ]; then
		add $sev CHECK "Kernel PwnEscape" "$rel: no fixed Ubuntu kernel published as of $DATA_DATE; $ctx" kernel
		return
	fi
	base=$(printf '%s' "$rel" | sed -n 's/^\([0-9]*\.[0-9]*\.[0-9]*\).*/\1/p')
	fx=$(kv_lookup "$KERNEL_STABLE_FIXED" "$(printf '%s' "$base" | cut -d. -f1-2)") || fx=""
	if [ -n "$fx" ] && ! is_distro_build "$uv"; then
		if vlt "$base" "$fx"; then
			add $sev VULNERABLE "Kernel PwnEscape" "$rel < upstream stable $fx; $ctx" kernel
		else
			add $sev OK "Kernel PwnEscape" "$rel ≥ upstream stable $fx; $ctx"
		fi
	else
		add $sev CHECK "Kernel PwnEscape" "$rel: no fix data for this kernel; check your vendor; $ctx" kernel
	fi
}

# ---------------------------------------------------------------------------
# Host checks
# ---------------------------------------------------------------------------
check_php() {
	local src ver sapis found=0 b real v seen=" " up mitig stale extra
	while IFS="$(printf '\t')" read -r src ver; do
		[ -n "$src" ] || continue
		found=1
		sapis=$(src_binaries "$src" | sed -n 's/.*-\(fpm\|cgi\)$/\1/p; s/^libapache2-mod-php.*/mod_php/p' | sort -u | tr '\n' ',' | sed 's/,$//')
		eval_php "host ${src}${sapis:+ ($sapis)}" "$src" "$ver" "$OS_ID" "$OS_CODENAME" pkg
		up=$(upstream "$ver")
		mitig=$(php_upload_progress "$(printf '%s' "$up" | cut -d. -f1-2)")
		extra=""
		[ "${F_STAT[$((${#F_STAT[@]} - 1))]}" = VULNERABLE ] && [ "$mitig" = off ] &&
			extra="session.upload_progress disabled (partial mitigation only)"
		[ -n "$extra" ] && F_DETAIL[${#F_DETAIL[@]} - 1]="${F_DETAIL[$((${#F_DETAIL[@]} - 1))]}; $extra"
	done <<EOF
$(src_versions '^php[0-9]+([.][0-9]+)?$')
EOF
	# PHP not installed from Debian/Ubuntu packages (source builds, /opt stacks)
	for b in $(type -ap php 2>/dev/null) /usr/local/bin/php /usr/local/sbin/php-fpm /opt/*/bin/php /opt/*/sbin/php-fpm; do
		[ -x "$b" ] || continue
		real=$(readlink -f "$b" 2>/dev/null || printf '%s' "$b")
		case $seen in *" $real "*) continue ;; esac
		seen="$seen$real "
		have dpkg && dpkg -S "$real" >/dev/null 2>&1 && continue
		v=$("$b" -v 2>/dev/null | sed -n 's/^PHP \([0-9][0-9.]*\).*/\1/p' | head -n1)
		[ -n "$v" ] || continue
		found=1
		eval_php "host $b (not from a package)" "" "$v" "" "" raw
	done
	if [ "$found" = 1 ]; then
		stale=$(stale_procs 'php-fpm|apache2|httpd|lsphp|frankenphp' 'php|libphp')
		[ "$stale" -gt 0 ] && add CRIT CHECK "PHP workers" "$stale process(es) still run a replaced PHP binary — restart them" php_restart
	else
		add CRIT N/A "PHP" "not installed on host"
	fi
}

# php_upload_progress BRANCH → on|off (effective setting across /etc/php/BRANCH SAPIs; default on)
php_upload_progress() {
	local val
	val=$(cat /etc/php/"$1"/*/php.ini /etc/php/"$1"/*/conf.d/*.ini 2>/dev/null |
		sed -n 's/^[[:space:]]*session\.upload_progress\.enabled[[:space:]]*=[[:space:]]*\([A-Za-z0-9"]*\).*/\1/p' | tail -n1 | tr -d '"' | tr '[:upper:]' '[:lower:]')
	case $val in off | 0 | false | no) echo off ;; *) echo on ;; esac
}

check_nginx() {
	local ver bin v risky="" conf extra="" stale
	ver=$(pkg_version nginx)
	[ -n "$ver" ] || ver=$(src_versions '^nginx$' | cut -f2 | head -n1)
	bin=$(command -v nginx 2>/dev/null || { [ -x /usr/sbin/nginx ] && echo /usr/sbin/nginx; })
	if [ -z "$ver" ] && [ -n "$bin" ]; then
		v=$("$bin" -v 2>&1 | sed -n 's|.*nginx/\([0-9][0-9.]*\).*|\1|p')
		ver=$v
	fi
	if [ -z "$ver" ]; then
		add HIGH N/A "NGINX" "not installed on host"
		return
	fi
	if [ -n "$bin" ] && [ "$IS_ROOT" = 1 ]; then
		conf=$(timeout 10 "$bin" -T 2>/dev/null | sed 's/#.*//')
		if [ -n "$conf" ]; then
			# shellcheck disable=SC2016 # literal nginx variable name
			printf '%s\n' "$conf" | grep -qE '^[[:space:]]*alias[[:space:]]' &&
				printf '%s\n' "$conf" | grep -qE '^[[:space:]]*rewrite[[:space:]]|\$request_filename' && risky="$risky alias+rewrite"
			printf '%s\n' "$conf" | grep -qE '^[[:space:]]*aio[[:space:]]+(on|threads)' &&
				printf '%s\n' "$conf" | grep -qE '^[[:space:]]*ssi[[:space:]]+on' && risky="$risky aio+ssi"
			printf '%s\n' "$conf" | grep -qE '^[[:space:]]*listen[^;]*quic' && risky="$risky http3"
			printf '%s\n' "$conf" | grep -qE '^[[:space:]]*map[[:space:]]' &&
				printf '%s\n' "$conf" | grep -qE '^[[:space:]]*~' && risky="$risky map-regex"
		fi
	fi
	[ -n "$risky" ] && extra="; config uses:$risky"
	public_port 443 || public_port 80 && extra="$extra; listens publicly on 80/443"
	eval_nginx "host package" "$ver" "$extra"
	stale=$(stale_procs 'nginx: (master|worker)' 'nginx')
	[ "$stale" -gt 0 ] && add HIGH CHECK "NGINX workers" "$stale process(es) still run a replaced nginx binary — restart nginx" nginx_restart
	return 0
}

check_plex_host() {
	local ver data codecs list id
	ver=$(pkg_version plexmediaserver)
	[ -n "$ver" ] && eval_plex "host package" "$ver"
	data="/var/lib/plexmediaserver/Library/Application Support/Plex Media Server"
	codecs="$data/Codecs"
	if [ -d "$codecs" ]; then
		list=$(find "$codecs" -name '*.so' 2>/dev/null)
		plex_codecs_eval "host" "$codecs" "$list"
	fi
	if [ "$PLEX_SEEN" = 0 ]; then
		# Not packaged on the host and not found in a container: ask the local server directly
		if have curl; then
			id=$(curl -fsS -m 3 http://127.0.0.1:32400/identity 2>/dev/null)
		elif have wget; then
			id=$(wget -qO- -T 3 http://127.0.0.1:32400/identity 2>/dev/null)
		else
			id=""
		fi
		ver=$(printf '%s' "$id" | sed -n 's/.*version="\([^"]*\)".*/\1/p' | head -n1)
		if [ -n "$ver" ]; then
			eval_plex "127.0.0.1:32400" "$ver"
		else
			add CRIT N/A "Plex Media Server" "not found"
		fi
	fi
}

# Children of Plex Media Server whose name doesn't start with "Plex" (transcoder, scanner,
# tuner, plug-ins and EasyAudioEncoder are expected).
check_plex_children() {
	local pids odd
	pids=$(printf '%s\n' "$PS_OUT" | awk '/Plex Media Server/ && !/awk/ { print $1 }')
	[ -n "$pids" ] || return 0
	odd=$(printf '%s\n' "$PS_OUT" | awk -v pids=" $(oneline "$pids") " '
		index(pids, " " $2 " ") {
			cmd = ""; for (i = 4; i <= NF; i++) cmd = cmd (i > 4 ? " " : "") $i
			if (cmd !~ /Plex|EasyAudioEncoder/) print $1 ":" substr(cmd, 1, 60)
		}')
	[ -n "$odd" ] && add CRIT IOC "Plex child processes" "unexpected processes spawned by Plex: $(oneline "$odd")" plex_ioc
	return 0
}

check_kernel() {
	local vms kvm=0 ctx reboot="" pkgs best=""
	vms=$(printf '%s\n' "$PS_OUT" | grep -cE 'qemu-system|/usr/bin/kvm ' 2>/dev/null)
	vms=${vms:-0}
	if [ -e /dev/kvm ] && { [ "$vms" -gt 0 ] || [ "$IS_PVE" = 1 ] || have virsh; }; then
		kvm=1
		ctx="KVM host, $vms VM(s) running"
	else
		ctx="not a KVM host (exploit needs a malicious VM guest)"
	fi
	eval_kernel "$IS_PVE" "$OS_ID" "$OS_CODENAME" "$KREL" "$KVER" "$kvm" "$ctx"
	# Fixed kernel installed but not booted yet?
	if [ "${F_STAT[$((${#F_STAT[@]} - 1))]}" != OK ]; then
		if [ "$IS_PVE" = 1 ]; then
			pkgs=$(printf '%s\n' "$DPKG_DB" | cut -f1 | sed -n 's/^proxmox-kernel-\(7\.0\.[0-9]*-[0-9]*\)-pve\(-signed\)\{0,1\}$/\1/p')
			for best in $pkgs; do vge "$best" "$PVE_KERNEL_FIXED" && reboot="proxmox-kernel-$best-pve" && break; done
		elif [ "$OS_ID" = debian ]; then
			local row fx
			row=$(fixed_lookup kernel debian "$OS_CODENAME" linux)
			fx=${row%% *}
			if [ -n "$fx" ]; then
				pkgs=$(printf '%s\n' "$DPKG_DB" | awk -F'\t' '$1 ~ /^linux-image-[0-9]/ { print $3 }')
				for best in $pkgs; do vge "$best" "$fx" && reboot="linux-image $best" && break; done
			fi
		fi
		[ -n "$reboot" ] && F_DETAIL[${#F_DETAIL[@]} - 1]="${F_DETAIL[$((${#F_DETAIL[@]} - 1))]}; fixed $reboot is installed — reboot into it"
	fi
	[ -e /var/run/reboot-required ] && add INFO CHECK "Reboot" "/var/run/reboot-required exists — pending updates need a reboot" kernel_reboot
	return 0
}

check_nextcloud_host() {
	local f dir ver shx newer hits logs
	local found=0
	while IFS= read -r f; do
		[ -n "$f" ] || continue
		dir=${f%/appinfo/info.xml}
		is_covered "$dir" && continue
		found=1
		ver=$(sed -n 's:.*<version>\([^<]*\)</version>.*:\1:p' "$f" | head -n1)
		eval_nextcloud_code "host $dir" "$ver"
		shx=$(find "$dir" -name 'shx*.php' 2>/dev/null | head -n5)
		[ -n "$shx" ] && add CRIT IOC "Nextcloud CODE webshell" "$(oneline "$shx")" nextcloud_ioc
		newer=$(find "$dir" -name '*.php' -newer "$f" 2>/dev/null | head -n5)
		[ -n "$newer" ] && add HIGH CHECK "Nextcloud CODE files" "PHP files modified after the app was installed: $(oneline "$newer")" nextcloud_ioc
	done <<EOF
$(find_in_roots '*/richdocumentscode/appinfo/info.xml' 7)
EOF
	[ "$found" = 1 ] || { add HIGH N/A "Nextcloud built-in CODE" "richdocumentscode app not found on host"; return 0; }
	# Exploit attempts in web server logs
	logs=$(ls /var/log/apache2/*access*log /var/log/nginx/*access*log /var/log/httpd/*access*log 2>/dev/null)
	[ "$OPT_DEEP" = 1 ] && logs="$logs $(ls /var/log/apache2/*access*log.* /var/log/nginx/*access*log.* 2>/dev/null)"
	if [ -n "$(oneline "$logs")" ]; then
		# shellcheck disable=SC2086
		hits=$(zgrep -ihE 'richdocumentscode/proxy\.php[^ "]*(%2e%2e|\$\(|\$\{IFS|%24%28|%24%7b)' $logs 2>/dev/null | wc -l | tr -d ' ')
		[ "${hits:-0}" -gt 0 ] && add CRIT IOC "Nextcloud CODE exploit attempts" "$hits proxy.php injection request(s) in web server logs" nextcloud_ioc
	fi
	return 0
}

check_wordpress_host() {
	local f site ver up sites=0 owner admins
	while IFS= read -r f; do
		[ -n "$f" ] || continue
		site=${f%/wp-includes/version.php}
		is_covered "$site" && continue
		sites=$((sites + 1))
		up="$site/wp-content/plugins/updraftplus/updraftplus.php"
		[ -f "$up" ] || continue
		UPDRAFT_SITES="$UPDRAFT_SITES $site"
		ver=$(sed -n 's/^[ *]*Version:[ ]*\([0-9][0-9.]*\).*/\1/p' "$up" | head -n1)
		eval_updraft "$site" "$ver"
		if [ "$OPT_DEEP" = 1 ] && [ "$IS_ROOT" = 1 ] && have wp; then
			# Run wp-cli as the site owner without loading plugins/themes (they may be backdoored)
			owner=$(stat -c %U "$site/wp-config.php" 2>/dev/null || stat -c %U "$site" 2>/dev/null)
			admins=$(for role in administrator editor; do
				timeout 30 runuser -u "${owner:-www-data}" -- wp --path="$site" --skip-plugins --skip-themes \
					user list --role="$role" --fields=user_login,user_registered --format=csv 2>/dev/null
			done | awk -F, -v d="$SINCE" '$1 != "user_login" && $2 >= d { print $1 " (" $2 ")" }')
			[ -n "$admins" ] && add CRIT IOC "WordPress new admins" "$site: admin/editor accounts created since $SINCE: $(oneline "$admins")" wp_ioc
		fi
	done <<EOF
$(find_in_roots '*/wp-includes/version.php' 6)
EOF
	[ "$sites" = 0 ] && [ -z "$COVERED" ] && add HIGH N/A "WordPress / UpdraftPlus" "no WordPress sites found on host"
	return 0
}

# check_simple_pkg COMPONENT SRCPKG SEVERITY REMKEY LABEL → table-driven distro check
check_simple_pkg() {
	local comp=$1 src=$2 sev=$3 rem=$4 label=$5 ver row fx ref bin pend
	ver=$(src_versions "^$src\$" | cut -f2 | head -n1)
	[ -n "$ver" ] || { add "$sev" N/A "$label" "not installed"; return; }
	row=$(fixed_lookup "$comp" "$OS_ID" "$OS_CODENAME" "$src")
	fx=${row%% *} ref=${row#* }
	if [ -n "$fx" ]; then
		if vlt "$ver" "$fx"; then
			add "$sev" VULNERABLE "$label" "$ver < $fx ($ref)" "$rem"
		else
			add "$sev" OK "$label" "$ver ≥ $fx ($ref)"
		fi
		return
	fi
	bin=$(src_binaries "$src" | head -n1)
	pend=$(apt_pending "$ver" "$bin")
	add "$sev" CHECK "$label" "$ver — no fix data for $OS_ID ${OS_CODENAME:-?} as of $DATA_DATE${pend:+; apt offers $pend}" "$rem"
}

check_curl() {
	local ver up
	ver=$(src_versions '^curl$' | cut -f2 | head -n1)
	[ -n "$ver" ] || { add MED N/A "curl/libcurl" "not installed"; return; }
	up=$(upstream "$ver")
	if vlt "$up" "$CURL_AFFECTED_FROM" || vge "$up" "$CURL_FIXED"; then
		add MED OK "curl/libcurl $up" "$ver outside affected range $CURL_AFFECTED_FROM–8.22.0"
	elif is_distro_build "$ver"; then
		check_simple_pkg curl curl MED curl "curl/libcurl $up"
	else
		add MED VULNERABLE "curl/libcurl $up" "$up < $CURL_FIXED" curl
	fi
}

check_siteguard() {
	local d found=""
	for d in /opt/jp-secure/siteguardlite /opt/jp-secure/siteguard /opt/jp-secure; do
		[ -d "$d" ] && { found=$d; break; }
	done
	[ -z "$found" ] && found=$(printf '%s\n' "$DPKG_DB" | awk -F'\t' 'tolower($1) ~ /siteguard/ { print $1 " " $3; exit }')
	[ -z "$found" ] && have rpm && found=$(rpm -qa 2>/dev/null | grep -i siteguard | head -n1)
	if [ -n "$found" ]; then
		add HIGH CHECK "SiteGuard Server Edition" "found ($found) — verify ≥ 8.00 Update 5 (7.00 Update 6 on FreeBSD)" siteguard
	else
		add HIGH N/A "SiteGuard Server Edition" "not installed"
	fi
}

# ---------------------------------------------------------------------------
# Containers
# ---------------------------------------------------------------------------
# POSIX sh probe run inside each container (read-only).
PROBE=$(cat <<'EOF'
p=$(command -v php 2>/dev/null) || p=""
[ -z "$p" ] && [ -x /usr/local/bin/php ] && p=/usr/local/bin/php
if [ -z "$p" ]; then for f in /usr/local/sbin/php-fpm /usr/sbin/php-fpm*; do [ -x "$f" ] && { p=$f; break; }; done; fi
[ -n "$p" ] && echo "php=$("$p" -v 2>/dev/null | sed -n 's/^PHP \([0-9][0-9.]*\).*/\1/p' | head -n1)"
n=$(command -v nginx 2>/dev/null) || n=""
[ -z "$n" ] && [ -x /usr/sbin/nginx ] && n=/usr/sbin/nginx
[ -n "$n" ] && echo "nginx=$("$n" -v 2>&1 | sed -n 's|.*nginx/\([0-9][0-9.]*\).*|\1|p')"
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='${db:Status-Abbrev} ${source:Package} ${Version}\n' 2>/dev/null |
    awk '$1 ~ /^ii/ && $2 ~ /^(php[0-9.]+|nginx|plexmediaserver)$/ { print "pkg=" $2 "=" $3 }' | sort -u
fi
[ -r /etc/os-release ] && (. /etc/os-release; echo "os=${ID:-}:${VERSION_CODENAME:-}")
[ -d /usr/lib/plexmediaserver ] && echo "plex=1"
for c in "/config/Library/Application Support/Plex Media Server/Codecs" "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Codecs"; do
  [ -d "$c" ] && { echo "plexcodecs=$c"; find "$c" -name '*.so' 2>/dev/null | sed 's/^/plexso=/'; }
done
for d in /var/www /app /config/www; do
  [ -d "$d" ] || continue
  find "$d" -maxdepth 6 -path '*/richdocumentscode/appinfo/info.xml' 2>/dev/null | while read -r f; do
    a=${f%/appinfo/info.xml}
    echo "rdc=$a|$(sed -n 's:.*<version>\([^<]*\)</version>.*:\1:p' "$f" | head -n1)"
    find "$a" -name 'shx*.php' 2>/dev/null | sed 's/^/rdcshx=/'
  done
  find "$d" -maxdepth 6 -path '*/wp-content/plugins/updraftplus/updraftplus.php' 2>/dev/null | while read -r f; do
    echo "updraft=${f%/wp-content/*}|$(sed -n 's/^[ *]*Version:[ ]*\([0-9][0-9.]*\).*/\1/p' "$f" | head -n1)"
  done
done
EOF
)

# Read-only POSIX sh probe for signs of exploitation; runs on the host and inside containers.
# Args: DAYS DEEP WEBSHELL_RE DL_EXEC_RE SYS ROOTS...   (SYS=1 also checks cron/preload/tmp)
ioc_probe() {
	cat <<'EOF'
days=$1 deep=$2 sig=$3 dl=$4 sys=$5
shift 5
age="-mtime -$days"
[ "$deep" = 1 ] && age=""
for d in "$@"; do
  [ -d "$d" ] || continue
  # PHP inside upload directories (WordPress, Drupal, Laravel); skip "silence is golden" stubs
  find "$d" -maxdepth 10 -type f \( -path '*/wp-content/uploads/*' -o -path '*/sites/default/files/*' -o -path '*/storage/app/public/*' \) \
    \( -name '*.php' -o -name '*.php[0-9]' -o -name '*.phtml' -o -name '*.phar' \) 2>/dev/null | head -n 50 | while read -r f; do
    case $f in */index.php) grep -qE 'eval|\$_|base64|system|exec' "$f" 2>/dev/null || continue ;; esac
    echo "upphp=$f"
  done
  # auto_prepend_file / auto_append_file persistence
  find "$d" -maxdepth 8 -type f \( -name .user.ini -o -name .htaccess -o -name php.ini \) 2>/dev/null | head -n 2000 | while read -r f; do
    v=$(grep -iE '^[[:space:]]*(php_value[[:space:]]+)?auto_(prepend|append)_file' "$f" 2>/dev/null | grep -viE '(=|[[:space:]])[[:space:]]*"?(none)?"?[[:space:]]*$' | head -n1)
    [ -n "$v" ] && echo "prepend=$f|$v"
  done
  # Webshell code in PHP files (recently changed ones; all with --deep)
  # shellcheck disable=SC2086
  find "$d" -maxdepth 12 -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' -o -name '*.inc' \) $age \
    -exec grep -lE "$sig" {} + 2>/dev/null | head -n 10 | sed 's/^/sig=/'
  # shellcheck disable=SC2086
  echo "recent=$d|$(find "$d" -maxdepth 12 -type f -name '*.php' -mtime -"$days" 2>/dev/null | wc -l | tr -d ' ')"
  # WordPress: mu-plugins, drop-ins and plugin folders changed in the window
  find "$d" -maxdepth 8 -type f -path '*/wp-content/mu-plugins/*' -mtime -"$days" 2>/dev/null | head -n 10 | sed 's/^/mu=/'
  find "$d" -maxdepth 8 -type f \( -path '*/wp-content/db.php' -o -path '*/wp-content/object-cache.php' -o -path '*/wp-content/advanced-cache.php' \) \
    -mtime -"$days" 2>/dev/null | sed 's/^/dropin=/'
  find "$d" -maxdepth 8 -mindepth 1 -type d -path '*/wp-content/plugins/*' ! -path '*/wp-content/plugins/*/*' -mtime -"$days" 2>/dev/null | head -n 20 | sed 's/^/plug=/'
done
if [ "$sys" = 1 ]; then
  [ -s /etc/ld.so.preload ] && echo "preload=$(head -c 200 /etc/ld.so.preload | tr '\n' ' ')"
  for f in /etc/crontab /etc/cron.d/* /etc/crontabs/* /var/spool/cron/crontabs/* /var/spool/cron/*; do
    [ -f "$f" ] && grep -qiE "$dl" "$f" 2>/dev/null && echo "cron=$f"
  done
  find /tmp /var/tmp /dev/shm -maxdepth 3 -type f 2>/dev/null | head -n 500 | while read -r f; do
    [ "$(head -c 4 "$f" 2>/dev/null | tr -d '\177')" = ELF ] && echo "tmpelf=$f"
  done
fi
exit 0
EOF
}

check_containers() {
	if [ "$OPT_DOCKER" = 0 ]; then
		add INFO SKIPPED "Containers" "skipped (--no-docker)"
		return
	fi
	local c
	for c in docker podman; do
		have "$c" && "$c" ps -q >/dev/null 2>&1 && { CTR=$c; break; }
	done
	if [ -z "$CTR" ]; then
		if have docker || have podman; then
			add INFO SKIPPED "Containers" "container runtime present but not accessible — run as root" ""
		fi
		return
	fi
	local ids name image svc mounts m src dst out lbl n=0 noshell=""
	ids=$("$CTR" ps -q 2>/dev/null)
	[ -n "$ids" ] || { add INFO OK "Containers" "no running containers"; return; }
	# shellcheck disable=SC2086
	while IFS="$(printf '\t')" read -r name image svc mounts; do
		[ -n "$name" ] || continue
		n=$((n + 1))
		name=${name#/}
		image=${image%%@sha256:*}
		[ "$svc" = "<no value>" ] && svc=""
		[ -n "$svc" ] && SWARM=1
		case "$name $svc" in captain-* | *srv-captain--*) CAPROVER=1 ;; esac
		lbl="container $name"
		[ -n "$svc" ] && lbl="service $svc"
		# Host directories mounted into the container's web roots are checked through the container
		for m in $(printf '%s' "$mounts" | tr ';' ' '); do
			src=${m%%>*} dst=${m#*>}
			case $dst in /var/www | /var/www/* | /app | /app/* | /config/www | /config/www/* | /srv | /srv/*) COVERED="$COVERED $src" ;; esac
		done
		if ! out=$(timeout 60 "$CTR" exec "$name" sh -c "$PROBE
$(ioc_probe)" probe "$DAYS" "$OPT_DEEP" "$WEBSHELL_RE" "$DL_EXEC_RE" 1 /var/www /app /config/www /srv /usr/share/nginx/html 2>/dev/null); then
			[ -n "$out" ] || { noshell="$noshell $name"; continue; }
		fi
		CTR_OUT="${CTR_OUT}${name}	${lbl}	${image}
"
		eval_container "$lbl" "$image" "$out"
		CTR_IOC_OUT="${CTR_IOC_OUT}@@${lbl}
${out}
"
	done <<EOF
$("$CTR" inspect -f '{{.Name}}	{{.Config.Image}}	{{index .Config.Labels "com.docker.swarm.service.name"}}	{{range .Mounts}}{{.Source}}>{{.Destination}};{{end}}' $ids 2>/dev/null)
EOF
	[ -n "$noshell" ] && add MED CHECK "Containers without shell" "could not inspect:$noshell — check their image versions manually" containers
	add INFO OK "Containers" "$n running container(s) inspected via $CTR exec"
}
# Per-container data kept for the exploitation phase
CTR_OUT=""
CTR_IOC_OUT=""

# eval_container LABEL IMAGE PROBE-OUTPUT  (version checks; evidence is evaluated later)
eval_container() {
	local lbl=$1 image=$2 out=$3 line k v os="" cn="" php="" nginx="" plexflag=0 codecs="" sos=""
	local pkgs="" src ver
	while IFS= read -r line; do
		k=${line%%=*} v=${line#*=}
		case $k in
		php) php=$v ;;
		nginx) nginx=$v ;;
		os) os=${v%%:*} cn=${v#*:} ;;
		pkg) pkgs="$pkgs $v" ;;
		plex) plexflag=1 ;;
		plexcodecs) codecs=$v ;;
		plexso) sos="$sos
$v" ;;
		rdc) eval_nextcloud_code "$lbl: ${v%%|*}" "${v#*|}" ;;
		rdcshx) add CRIT IOC "Nextcloud CODE webshell" "$lbl: $v" nextcloud_ioc ;;
		updraft) eval_updraft "$lbl: ${v%%|*}" "${v#*|}" ;;
		esac
	done <<EOF
$out
EOF
	# Packaged PHP/nginx/Plex use the image's distro data; otherwise compare upstream.
	local seen_php=0 seen_nginx=0 p
	for p in $pkgs; do
		src=${p%%=*} ver=${p#*=}
		case $src in
		php*) seen_php=1; eval_php "$lbl ($image)" "$src" "$ver" "$os" "$cn" pkg ;;
		nginx) seen_nginx=1; eval_nginx "$lbl ($image)" "$ver" ;;
		plexmediaserver) eval_plex "$lbl ($image)" "$ver" ;;
		esac
	done
	[ "$seen_php" = 0 ] && [ -n "$php" ] && eval_php "$lbl ($image)" "" "$php" "" "" raw
	[ "$seen_nginx" = 0 ] && [ -n "$nginx" ] && eval_nginx "$lbl ($image)" "$nginx"
	if [ "$plexflag" = 1 ] && ! printf '%s' "$pkgs" | grep -q plexmediaserver; then
		PLEX_SEEN=1
		add CRIT CHECK "Plex Media Server" "$lbl ($image): version unreadable — check Settings → General" plex
	fi
	[ -n "$codecs" ] && plex_codecs_eval "$lbl" "$codecs" "$sos"
	return 0
}

# ---------------------------------------------------------------------------
# Signs of exploitation
# ---------------------------------------------------------------------------

# list_short "a b c d" → "a b c (+1 more)" — keeps rows to one line
list_short() {
	local n=0 out="" x
	for x in $1; do
		n=$((n + 1))
		[ "$n" -le 3 ] && out="$out $x"
	done
	[ "$n" -gt 3 ] && out="$out (+$((n - 3)) more)"
	printf '%s' "${out# }"
}

# eval_ioc_output LABEL PROBE-OUTPUT UPDRAFT-SITES — findings from IOC_PROBE output
eval_ioc_output() {
	local lbl=$1 out=$2 usites=" $3 " line k v f
	local up="" sig="" pre="" mu="" drop="" plug="" plugu="" cron="" preload="" elf="" recent=0 site
	while IFS= read -r line; do
		k=${line%%=*} v=${line#*=}
		case $k in
		upphp) up="$up $v" ;;
		sig) sig="$sig $v" ;;
		prepend)
			f=${v%%|*}
			printf '%s' "${v#*|}" | grep -qiE "$PREPEND_OK_RE" || pre="$pre $f"
			;;
		mu) mu="$mu $v" ;;
		dropin) drop="$drop $v" ;;
		plug)
			site=${v%/wp-content/plugins/*}
			case $v in */updraftplus) continue ;; esac
			case $usites in *" $site "*) plugu="$plugu ${v##*/}" ;; *) plug="$plug ${v##*/}" ;; esac
			;;
		cron) cron="$cron $v" ;;
		preload) preload=$v ;;
		tmpelf) elf="$elf $v" ;;
		recent) recent=$((recent + ${v#*|})) ;;
		esac
	done <<EOF
$out
EOF
	[ -n "$up" ] && add CRIT IOC "PHP in uploads folder" "$lbl: $(list_short "$up")" webshell
	[ -n "$sig" ] && add CRIT IOC "Webshell code" "$lbl: $(list_short "$sig")" webshell
	[ -n "$pre" ] && add HIGH CHECK "auto_prepend_file set" "$lbl: $(list_short "$pre") — PHP runs this file before every request" webshell
	[ -n "$preload" ] && add CRIT IOC "/etc/ld.so.preload" "$lbl: preloads $preload" persistence
	[ -n "$cron" ] && add CRIT IOC "Download-and-run cron job" "$lbl: $(list_short "$cron")" persistence
	[ -n "$elf" ] && add HIGH CHECK "Binaries in temp dirs" "$lbl: $(list_short "$elf")" persistence
	[ -n "$mu" ] && add HIGH CHECK "WordPress mu-plugins changed" "$lbl: since $SINCE: $(list_short "$mu")" wp_ioc
	[ -n "$drop" ] && add MED CHECK "WordPress drop-ins changed" "$lbl: since $SINCE: $(list_short "$drop")" wp_ioc
	[ -n "$plugu" ] && add HIGH CHECK "Plugins changed (UpdraftCentral)" "$lbl: since $SINCE on a site with UpdraftPlus: $(list_short "$plugu")" wp_ioc
	[ -n "$plug" ] && add INFO CHECK "Plugins added/updated" "$lbl: since $SINCE: $(list_short "$plug") — expected if you updated them" wp_ioc
	[ "$recent" -gt 0 ] && [ -z "$up$sig" ] && add INFO OK "PHP files changed" "$lbl: $recent PHP file(s) changed since $SINCE, none match webshell patterns"
	return 0
}

# log_counts < LOG-LINES → "mem crash up200 up inject<TAB>crash-sample<TAB>uploads-sample"
log_counts() {
	awk '
	/Allowed memory size of [0-9]+ bytes exhausted/ { m++ }
	/exit signal Segmentation fault|exited on signal (6|11)|SIGSEGV|segfault at/ { c++; if (cs == "") cs = substr($0, 1, 120) }
	/\/wp-content\/uploads\/[^ "?]*\.(php[0-9]?|phtml|phar)/ {
		if ($0 ~ /\/wp-content\/uploads\/[^ "?]*\.(php[0-9]?|phtml|phar)[^"]*" 200 /) { u2++; if (us == "") us = substr($0, 1, 120) } else u++
	}
	{ l = tolower($0) }
	l ~ /(\$\(|%24%28|\$\{ifs|%24%7bifs|\/bin\/(ba)?sh|(wget|curl)(%20|\+)http|base64_decode|php:\/\/input|allow_url_include|auto_prepend_file)/ { i++ }
	END { printf "%d %d %d %d %d\t%s\t%s\n", m, c, u2, u, i, cs, us }'
}

# eval_log_counts LABEL "COUNTS<TAB>CRASH-SAMPLE<TAB>UPLOAD-SAMPLE"
eval_log_counts() {
	local lbl=$1 nums cs us m c u2 u i
	nums=$(printf '%s' "$2" | cut -f1)
	cs=$(printf '%s' "$2" | cut -f2)
	us=$(printf '%s' "$2" | cut -f3)
	read -r m c u2 u i <<EOF
$nums
EOF
	[ "${u2:-0}" -gt 0 ] && add CRIT IOC "PHP executed from uploads" "$lbl: $u2 successful request(s), e.g. $us" webshell
	[ "${c:-0}" -gt 0 ] && add HIGH CHECK "Web worker crashes" "$lbl: $c segfault/abort(s) since $SINCE, e.g. $cs" crash
	[ "${m:-0}" -gt 0 ] && add MED CHECK "PHP memory-limit fatals" "$lbl: $m since $SINCE (the PHP2Shell trigger condition)" attempts
	[ "${u:-0}" -gt 0 ] && add INFO CHECK "Probes for PHP in uploads" "$lbl: $u failed request(s) since $SINCE" attempts
	[ "${i:-0}" -gt 0 ] && add INFO CHECK "Injection probes" "$lbl: $i request(s) with shell/PHP injection payloads since $SINCE" attempts
	return 0
}

# eval_drift LABEL "docker diff" output — files changed in the container's writable layer
eval_drift() {
	local lbl=$1 res ioc chk
	res=$(printf '%s\n' "$2" | awk '
		{ t = $1; p = $2 }
		p ~ /^\/(proc|sys|dev|run|var\/run|var\/lock|var\/log|var\/cache|tmp|var\/tmp)(\/|$)/ { next }
		t != "D" && p ~ /^\/etc\/ld\.so\.preload$|^\/etc\/cron[^\/]*\/.|^\/etc\/crontabs\/.|^\/var\/spool\/cron\/.|^\/root\/\.ssh\/./ { print "ioc " p; next }
		t != "D" && p ~ /^\/etc\/(passwd|shadow|sudoers)/ { print "chk " p; next }
		t == "A" && p ~ /^\/(usr|bin|sbin|lib|lib64|opt|etc\/init\.d|etc\/systemd|etc\/profile\.d)\/./ { print "chk " p }')
	ioc=$(printf '%s\n' "$res" | sed -n 's/^ioc //p')
	chk=$(printf '%s\n' "$res" | sed -n 's/^chk //p')
	[ -n "$ioc" ] && add CRIT IOC "Container persistence" "$lbl: $(list_short "$(oneline "$ioc")")" drift
	[ -n "$chk" ] && add MED CHECK "Container files changed" "$lbl: outside volumes: $(list_short "$(oneline "$chk")")" drift
	return 0
}

eval_ctr_block() { # LABEL PROBE-OUTPUT
	eval_ioc_output "$1" "$2" "$(printf '%s\n' "$2" | sed -n 's/^updraft=\([^|]*\)|.*/\1/p' | tr '\n' ' ')"
}

# Evidence collected per container: probe results, logs, filesystem drift
check_containers_ioc() {
	[ -n "$CTR" ] || return 0
	local line lbl="" out="" name image logs
	# Probe output blocks are separated by "@@LABEL" lines
	while IFS= read -r line; do
		case $line in
		@@*)
			[ -n "$lbl" ] && eval_ctr_block "$lbl" "$out"
			lbl=${line#@@} out=""
			;;
		*) out="$out$line
" ;;
		esac
	done <<EOF
$CTR_IOC_OUT
EOF
	[ -n "$lbl" ] && eval_ctr_block "$lbl" "$out"
	while IFS="$(printf '\t')" read -r name lbl image; do
		[ -n "$name" ] || continue
		logs=$(timeout 60 "$CTR" logs --since "$SINCE" "$name" 2>&1 | log_counts)
		eval_log_counts "$lbl" "$logs"
		eval_drift "$lbl" "$(timeout 30 "$CTR" diff "$name" 2>/dev/null)"
	done <<EOF
$CTR_OUT
EOF
	return 0
}

# Host web roots (minus anything already covered through a container)
check_host_webroots_ioc() {
	local roots="" r out list="/var/www /srv /opt /home /usr/share/nginx /usr/share/webapps /var/lib/nextcloud /snap/nextcloud/current"
	# --deep adds more web-content locations, but never /var/lib/docker (containers are probed directly) or media mounts
	[ "$OPT_DEEP" = 1 ] && list="$list /root /usr/local /www /var/lib/www"
	for r in $list; do
		[ -d "$r" ] && ! is_covered "$r" && roots="$roots $r"
	done
	[ -n "$roots" ] || return 0
	# shellcheck disable=SC2086
	out=$(sh -c "$(ioc_probe)" probe "$DAYS" "$OPT_DEEP" "$WEBSHELL_RE" "$DL_EXEC_RE" 0 $roots 2>/dev/null |
		while IFS= read -r line; do
			v=${line#*=}
			is_covered "${v%%|*}" || printf '%s\n' "$line"
		done)
	eval_ioc_output "host" "$out" "$UPDRAFT_SITES"
}

# Web server / PHP logs on the host, plus kernel-logged crashes of web workers
check_host_logs() {
	local files counts kcrash=0
	files=$(ls /var/log/apache2/*.log /var/log/nginx/*.log /var/log/httpd/*log /var/log/php*-fpm.log /var/log/php*/*.log 2>/dev/null)
	[ "$OPT_DEEP" = 1 ] && files="$files $(ls /var/log/apache2/*.log.* /var/log/nginx/*.log.* /var/log/httpd/*log.* 2>/dev/null)"
	if [ -n "$(oneline "$files")" ]; then
		# shellcheck disable=SC2086
		counts=$(zcat -f $files 2>/dev/null | log_counts)
		eval_log_counts "host logs" "$counts"
	fi
	if have journalctl; then
		kcrash=$(journalctl -k --since "$SINCE" --no-pager 2>/dev/null | grep -E 'segfault at' | grep -cE 'php|apache2|httpd|nginx|lsphp|Plex')
		[ "${kcrash:-0}" -gt 0 ] && add HIGH CHECK "Web worker crashes" "kernel log: $kcrash segfault(s) of PHP/web/Plex processes since $SINCE" crash
	fi
	return 0
}

# Shells or download tools running as children of web workers (all containers included)
check_web_children() {
	local hits
	hits=$(printf '%s\n' "$PS_OUT" | awk -v wre="$WEB_PARENT_RE" -v cre="$SUSP_CHILD_RE" -v okre="$WEB_CHILD_OK_RE" '
		{ cmd = ""; for (i = 4; i <= NF; i++) cmd = cmd (i > 4 ? " " : "") $i; P[$1] = $2; C[$1] = cmd; U[$1] = $3 }
		END {
			for (p in P) {
				pp = P[p]
				if (!(pp in C) || C[pp] !~ wre) continue
				split(C[p], a, " "); b = a[1]; sub(/.*\//, "", b); sub(/:$/, "", b)
				if (b ~ cre && C[p] !~ okre) print p ":" U[p] ":" substr(C[p], 1, 60)
			}
		}')
	[ -n "$hits" ] && add CRIT IOC "Shell under web server" "$(oneline "$hits" | cut -c1-200)" ioc
	check_plex_children
	return 0
}

# Shells / netcat holding network connections (reverse shells); needs root for process names
check_net_shells() {
	have ss || return 0
	[ "$IS_ROOT" = 1 ] || return 0
	local hits
	hits=$(ss -tnp 2>/dev/null | awk -v re="$NET_SHELL_RE" '
		NR > 1 && $1 == "ESTAB" {
			peer = $5; if (peer ~ /^(127\.|\[::1\]|::1)/) next
			s = $0
			while (match(s, /\("[^"]+"/)) {
				name = substr(s, RSTART + 2, RLENGTH - 3); s = substr(s, RSTART + RLENGTH)
				if (name ~ re) { print name "→" peer; break }
			}
		}' | sort -u)
	[ -n "$hits" ] && add CRIT IOC "Reverse shell" "shell/netcat with network connection: $(oneline "$hits")" ioc
	return 0
}

# Long-running CPU hogs not on the allow-list (miners)
check_cpu() {
	local hits
	hits=$(ps -eo pid=,user=,pcpu=,etimes=,comm= 2>/dev/null | awk -v ok="$CPU_OK_RE" '
		{ comm = $5; for (i = 6; i <= NF; i++) comm = comm " " $i }
		$3 >= 80 && $4 >= 600 && comm !~ ok { printf "%s(pid %s, %s, %d%%)\n", comm, $1, $2, $3 }')
	[ -n "$hits" ] && add MED CHECK "Sustained high CPU" "$(oneline "$hits" | cut -c1-200)" cpu
	return 0
}

# Host persistence: preload, extra root accounts, cron/systemd/ssh changes
check_persistence() {
	local f uid0 webusers cronhits="" units="" unitbad="" keys="" sudo="" elf="" suid="" any=0
	if [ -s /etc/ld.so.preload ]; then
		any=1
		add CRIT IOC "/etc/ld.so.preload" "host preloads: $(head -c 200 /etc/ld.so.preload | tr '\n' ' ')" persistence
	fi
	uid0=$(awk -F: '$3 == 0 && $1 != "root" { print $1 }' /etc/passwd 2>/dev/null)
	[ -n "$uid0" ] && { any=1; add CRIT IOC "Extra root accounts" "UID 0 accounts besides root: $(oneline "$uid0")" persistence; }
	webusers=$(awk -F: '($1 == "www-data" || $1 == "apache" || $1 == "nginx" || $1 == "http") && $7 !~ /(nologin|false)$/ { print $1 ":" $7 }' /etc/passwd 2>/dev/null)
	[ -n "$webusers" ] && { any=1; add HIGH CHECK "Web user has a login shell" "$(oneline "$webusers")" persistence; }
	for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /var/spool/cron/crontabs/* /var/spool/cron/*; do
		[ -f "$f" ] && grep -qiE "$DL_EXEC_RE" "$f" 2>/dev/null && cronhits="$cronhits $f"
	done
	for f in /var/spool/cron/crontabs/www-data /var/spool/cron/crontabs/apache /var/spool/cron/crontabs/nginx /var/spool/cron/www-data; do
		[ -f "$f" ] && cronhits="$cronhits $f"
	done
	[ -n "$cronhits" ] && { any=1; add CRIT IOC "Suspicious cron jobs" "$(list_short "$cronhits")" persistence; }
	for f in /etc/systemd/system/*.service /etc/systemd/system/*/*.service /root/.config/systemd/user/*.service /home/*/.config/systemd/user/*.service; do
		[ -f "$f" ] && [ ! -L "$f" ] || continue
		if grep -qE "^Exec[A-Za-z]*=.*(/tmp/|/dev/shm/|/var/tmp/)" "$f" 2>/dev/null || grep -qiE "$DL_EXEC_RE" "$f" 2>/dev/null; then
			unitbad="$unitbad $f"
		elif [ -n "$(find "$f" -newermt "$SINCE" 2>/dev/null)" ]; then
			units="$units ${f##*/}"
		fi
	done
	[ -n "$unitbad" ] && { any=1; add CRIT IOC "Suspicious systemd units" "$(list_short "$unitbad")" persistence; }
	[ -n "$units" ] && { any=1; add MED CHECK "New/changed systemd units" "since $SINCE: $(list_short "$units")" persistence; }
	for f in /root/.ssh/authorized_keys /root/.ssh/authorized_keys2 /home/*/.ssh/authorized_keys /home/*/.ssh/authorized_keys2; do
		[ -f "$f" ] && [ -n "$(find "$f" -newermt "$SINCE" 2>/dev/null)" ] && keys="$keys $f"
	done
	[ -n "$keys" ] && { any=1; add MED CHECK "SSH keys changed" "since $SINCE: $(list_short "$keys")" persistence; }
	sudo=$(find /etc/sudoers /etc/sudoers.d -newermt "$SINCE" -type f 2>/dev/null)
	[ -n "$sudo" ] && { any=1; add MED CHECK "sudoers changed" "since $SINCE: $(list_short "$(oneline "$sudo")")" persistence; }
	for f in $(find /tmp /var/tmp /dev/shm -xdev -maxdepth 3 -type f 2>/dev/null | head -n 500); do
		[ "$(head -c 4 "$f" 2>/dev/null | tr -d '\177')" = ELF ] && elf="$elf $f"
	done
	[ -n "$elf" ] && { any=1; add HIGH CHECK "Binaries in temp dirs" "host: $(list_short "$elf")" persistence; }
	suid=$(find /tmp /var/tmp /dev/shm /home -xdev -maxdepth 4 -type f -perm -4000 2>/dev/null | head -n 5)
	[ -n "$suid" ] && { any=1; add CRIT IOC "SUID files in temp/home" "$(list_short "$(oneline "$suid")")" persistence; }
	[ "$any" = 0 ] && add INFO OK "Persistence" "no preload hooks, extra root accounts, download-and-run cron jobs, rogue units or temp-dir binaries"
	return 0
}

check_ioc() {
	local procs ip conns hits="" tmpx="" pid exe any=0
	procs=$(printf '%s\n' "$PS_OUT" | grep -E "$IOC_PROC_RE" | awk '{ $2 = ""; print substr($0, 1, 100) }' | head -n5)
	[ -n "$procs" ] && { any=1; add CRIT IOC "Miner / proxy processes" "$(oneline "$procs")" ioc; }
	if have ss; then
		conns=$(ss -tn 2>/dev/null)
		for ip in $IOC_IPS; do
			printf '%s\n' "$conns" | grep -qF " $ip:" && hits="$hits $ip"
		done
		[ -n "$hits" ] && { any=1; add CRIT IOC "Connections to known attacker IPs" "active TCP connections to:$hits" ioc; }
	fi
	if [ "$IS_ROOT" = 1 ]; then
		for pid in /proc/[0-9]*; do
			pid=${pid#/proc/}
			exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
			case $exe in /tmp/* | /var/tmp/* | /dev/shm/* | memfd:*) tmpx="$tmpx $pid:$exe" ;; esac
		done
		[ -n "$tmpx" ] && { any=1; add HIGH IOC "Processes running from temp dirs" "$(oneline "$tmpx" | cut -c1-200)" ioc; }
	fi
	[ "$any" = 0 ] && add INFO OK "Processes & connections" "no known miner/proxy processes, attacker IPs or temp-dir binaries"
	return 0
}

# Admin/editor accounts created in the window, read from each containerized WordPress database.
# --deep only: it runs the site's wp-config.php (SHORTINIT: no plugins or themes) as www-data.
wp_users_php() {
	cat <<'EOF'
<?php
define('SHORTINIT', true);
$_SERVER['HTTP_HOST'] = 'localhost';
error_reporting(0);
require getcwd() . '/wp-load.php';
global $wpdb;
$since = $argv[1];
$sql = $wpdb->prepare("SELECT u.user_login, u.user_registered, m.meta_value FROM {$wpdb->users} u JOIN {$wpdb->usermeta} m ON m.user_id = u.ID AND m.meta_key = %s WHERE u.user_registered >= %s", $wpdb->prefix . 'capabilities', $since);
foreach ((array) $wpdb->get_results($sql) as $r) {
	if (preg_match('/administrator|editor/', $r->meta_value)) echo $r->user_login, ' (', $r->user_registered, ")\n";
}
EOF
}

check_wp_users_containers() {
	[ "$OPT_DEEP" = 1 ] && [ -n "$CTR" ] || return 0
	local name lbl image roots r admins
	while IFS="$(printf '\t')" read -r name lbl image; do
		[ -n "$name" ] || continue
		roots=$(timeout 30 "$CTR" exec "$name" sh -c 'for d in /var/www /app /config/www; do [ -d "$d" ] && find "$d" -maxdepth 4 -name wp-load.php 2>/dev/null; done' 2>/dev/null)
		for r in $roots; do
			admins=$(wp_users_php | timeout 30 "$CTR" exec -i -u www-data -w "${r%/wp-load.php}" "$name" php -- "$SINCE" 2>/dev/null)
			[ -n "$admins" ] && add CRIT IOC "WordPress new admins" "$lbl: created since $SINCE: $(oneline "$admins")" wp_ioc
		done
	done <<EOF
$CTR_OUT
EOF
	return 0
}

check_exposure() {
	local p pub=""
	for p in 80 443 8080 8443 8006 32400 9000; do
		public_port "$p" && pub="$pub $p"
	done
	[ -n "$pub" ] && add INFO OK "Exposure" "listening on non-loopback addresses (ports):$pub"
	return 0
}

# ---------------------------------------------------------------------------
# Remediation text
# ---------------------------------------------------------------------------
rem_title() {
	case $1 in
	php) echo "PHP2Shell (CVE-2026-109618 / CVE-2026-109619)" ;;
	php_eol) echo "PHP2Shell on an end-of-life PHP" ;;
	php_restart) echo "PHP workers not restarted after update" ;;
	nginx) echo "NGINX memory-corruption fixes (CVE-2026-15176 / -93479 / -97205 / -95101 / -97629)" ;;
	nginx_restart) echo "NGINX not restarted after update" ;;
	plex) echo "Plex2Shell (CVE-2026-96652 / -96654 / -96655 / -96656)" ;;
	plex_ioc) echo "Possible Plex compromise" ;;
	kernel) echo "PwnEscape KVM guest-to-host escape (CVE-2026-99999)" ;;
	kernel_reboot) echo "Reboot pending" ;;
	nextcloud) echo "Nextcloud built-in CODE command injection (CVE-2026-110447)" ;;
	nextcloud_ioc) echo "Possible Nextcloud compromise" ;;
	updraft) echo "UpdraftCentral stolen connection keys" ;;
	curl) echo "curl/libcurl HTTP/2 upload use-after-free (CVE-2026-92392)" ;;
	ghostscript) echo "Ghostscript (CVE-2026-101258 / CVE-2026-103226)" ;;
	siteguard) echo "SiteGuard Server Edition command injection (CVE-2026-106931)" ;;
	ioc) echo "Attacker activity on this host" ;;
	webshell) echo "Webshell / backdoor in a web root" ;;
	wp_ioc) echo "WordPress changes to verify" ;;
	persistence) echo "Persistence mechanisms" ;;
	attempts) echo "Exploit attempts in logs" ;;
	crash) echo "Web worker crashes (possible memory-corruption exploitation)" ;;
	drift) echo "Container filesystem changed since start" ;;
	cpu) echo "Possible cryptominer" ;;
	containers) echo "Containers that could not be inspected" ;;
	*) echo "$1" ;;
	esac
}

rem_body() {
	case $1 in
	php)
		case $(rem_scope php) in *host*)
			echo "Host: sudo apt update && sudo apt install --only-upgrade \$(dpkg-query -W -f='\${Package}\\n' 'php*' 'libapache2-mod-php*' | grep -E '^(php|libapache2)')"
			echo "      then restart every PHP process: sudo systemctl restart 'php*-fpm' apache2   (whichever you run)"
			;;
		esac
		case $(rem_scope php) in *container*)
			echo "Containers: rebuild on an image with PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or newer — restarting is not enough."
			ctr_redeploy_hint "php -v"
			;;
		esac
		echo "Stopgap only: session.upload_progress.enabled = Off, limit request body size, restart workers."
		echo "Then check the \"Signs of exploitation\" section; re-run with --deep for a full webshell scan and new WordPress admins."
		echo "Ref: https://ubuntu.com/blog/php2shell-vulnerability-fixes-available · https://security-tracker.debian.org/tracker/CVE-2026-109618"
		;;
	php_eol) cat <<EOF
PHP ≤ 8.1 gets no upstream fix. Options:
  Ubuntu 14.04–20.04: sudo pro attach && sudo pro enable esm-apps (16.04/14.04 also need the Legacy add-on), then apt upgrade
  Debian 11: Freexian ELTS packages
  Otherwise migrate to PHP 8.2+ on a supported OS. A CDN/WAF in front is not a fix.
Ref: https://ubuntu.com/security/CVE-2026-109618
EOF
	;;
	php_restart) echo "sudo systemctl restart 'php*-fpm' apache2   # whichever is in use; needrestart -r l lists all" ;;
	nginx) cat <<'EOF'
sudo apt update && sudo apt install --only-upgrade nginx 'nginx-*' && sudo nginx -t && sudo systemctl restart nginx
nginx.org repo: upgrade to 1.30.6+ (stable) or 1.31.7+ (mainline). Containers: rebuild on nginx 1.30.6+ / 1.31.7+.
Distro builds without a backport yet — reduce exposure until one ships:
  • avoid `alias` combined with `rewrite` or $request_filename (CVE-2026-15176)
  • turn off `aio` or `ssi` where not needed (CVE-2026-97205)
  • drop `quic` listeners if HTTP/3 isn't needed (CVE-2026-95101)
Ref: https://nginx.org/en/security_advisories.html
EOF
	;;
	nginx_restart) echo "sudo nginx -t && sudo systemctl restart nginx" ;;
	plex) cat <<EOF
Update to Plex Media Server $PLEX_FIXED or later and verify the full build in Settings → General:
  sudo apt update && sudo apt install --only-upgrade plexmediaserver
  Containers: pull the image again and recreate (Compose: docker compose pull && docker compose up -d --force-recreate)
Do not port-forward 32400 directly; use Plex Relay/VPN or restrict by firewall.
If an older build was reachable from the internet, treat it as compromised — see "Possible Plex compromise".
Ref: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
EOF
	;;
	plex_ioc) cat <<'EOF'
1. Isolate: stop Plex (or the container) and block outbound traffic from it.
2. Preserve evidence: copy the Codecs/ directory and `ps auxf` / `ss -tnp` output before deleting anything.
3. Look for miners/proxies (xmrig, myawesomeproxy, mylovelyminer) and unusual outbound connections.
4. Rebuild from a clean package/image at the fixed version; delete the Codecs/ directory (Plex re-downloads it).
5. Change your Plex account password and "sign out of all devices" to invalidate tokens; rotate any credentials
   readable by the Plex user or container mounts.
EOF
	;;
	kernel)
		echo "Patch the HOST kernel and reboot — updating guests does not help."
		if [ "$IS_PVE" = 1 ]; then
			echo "apt update && apt full-upgrade → proxmox-kernel-$PVE_KERNEL_FIXED-pve or newer → migrate/stop VMs → reboot."
			echo "Older kernel series (e.g. 6.8 on Proxmox VE 8) get no fix: upgrade to a release with the 7.0 kernel series."
		elif [ "$OS_ID" = debian ]; then
			echo "sudo apt update && sudo apt full-upgrade && sudo reboot   # then confirm with: uname -v"
		elif [ "$OS_ID" = ubuntu ]; then
			echo "No fixed Ubuntu kernel at $DATA_DATE — watch https://ubuntu.com/security/CVE-2026-99999 and install it when listed."
			echo "Meanwhile run only trusted guests on this host."
		else
			echo "Install your vendor's kernel with the upstream fix (commit 6785011f8b16) and reboot."
		fi
		echo "After rebooting, re-run this scan to confirm the running kernel."
		echo "Ref: https://forum.proxmox.com/threads/cve-2026-99999-or-the-vercel-kvm-zero-day.187089/ · https://docs.virtfusion.com/security/pwnescape/"
		;;
	kernel_reboot) echo "Reboot into the newest installed kernel (migrate or shut down VMs first), then re-run this scan." ;;
	nextcloud) cat <<'EOF'
Update the app, or remove it if you don't use the built-in CODE server (disabling is NOT enough):
  sudo -u www-data php occ app:update richdocumentscode
  sudo -u www-data php occ app:remove richdocumentscode
Standalone Collabora Online and Nextcloud All-in-One are not affected.
Ref: https://wz-it.com/en/blog/nextcloud-built-in-code-server-cve-2026-110447-rce-webshell/
EOF
	;;
	nextcloud_ioc) cat <<'EOF'
1. Preserve logs and the apps/richdocumentscode directory, then delete shx*.php webshells.
2. Search access logs since 2026-09-10 for proxy.php requests containing %2e%2e, $( or ${IFS}.
3. Assume credentials in config/config.php (DB, SMTP, object storage) are exposed — rotate them.
4. Check for other web shells and unknown cron jobs under the web server user; rebuild if unsure.
EOF
	;;
	updraft) cat <<EOF
1. Update UpdraftPlus to 1.26.13+ (free) / 2.26.13+ (Premium), then delete old keys:
   Settings → UpdraftPlus → Advanced Tools → UpdraftCentral, or: wp option delete updraft_central_localkeys
   (keys created on 2026-10-18 between 12:07 and 21:00 UTC can survive the update — delete them manually).
2. Audit: wp user list --role=administrator ; wp plugin list --status=must-use,dropin ;
   plugins and mu-plugins changed since $UPDRAFT_INCIDENT_START ; files under wp-content newer than that date.
3. Log in to each site directly, not through UpdraftCentral, until the audit is complete.
Ref: https://teamupdraft.com/blog/security-incident-october-2026/
EOF
	;;
	curl) cat <<'EOF'
sudo apt update && sudo apt install --only-upgrade curl 'libcurl*'   (upstream fix: curl 8.23.0)
Until patched: force HTTP/1.1 (--http1.1) for uploads to servers you don't trust.
EOF
	;;
	ghostscript) cat <<'EOF'
sudo apt update && sudo apt install --only-upgrade ghostscript 'libgs*'
Without a fixed package: stop processing untrusted PDFs/PostScript/fonts (document previews, ImageMagick PDF
delegates) until one ships.
EOF
	;;
	siteguard) cat <<'EOF'
Save SiteGuard diagnostic information FIRST (updating can erase attack traces), then update to
8.00 Update 5 (7.00 Update 6 on FreeBSD) or apply the vendor's statistics-module patch.
EOF
	;;
	ioc) cat <<'EOF'
Treat the host as compromised: isolate it, preserve evidence (ps auxf, ss -tnp, /proc/<pid>/exe copies),
identify the entry point (Plex, PHP app, Nextcloud, WordPress), rotate credentials, and rebuild from clean media.
Patching alone does not remove what an attacker already installed.
EOF
	;;
	webshell) cat <<'EOF'
Treat the site as compromised. Before deleting anything:
  1. Preserve evidence: copy the files with timestamps (cp -a), save `stat <file>` output and the access-log
     lines that requested them (grep the file name in the web server / container logs).
  2. Find the entry point: what else changed around the same mtime?  find <webroot> -newermt '<mtime - 10 min>' ! -newermt '<mtime + 30 min>'
  3. Clean: take the site offline, delete the backdoor, reinstall WordPress core and plugins from clean copies
     (wp core download --force --skip-content; reinstall each plugin), or restore a backup from before the window.
  4. Rotate the database password, WordPress salts (wp config shuffle-salts), every admin password and any API keys
     in wp-config.php / .env. Containers: the backdoor lives on the volume, so recreating the container is not enough.
EOF
	;;
	wp_ioc) cat <<'EOF'
Verify each listed change is yours:
  wp user list --role=administrator --fields=ID,user_login,user_email,user_registered
  wp plugin list --status=must-use,dropin ; wp plugin list
Unknown admin, mu-plugin or drop-in → treat as a backdoor (see the webshell steps): preserve, remove, reset all
passwords and salts, delete UpdraftCentral keys (wp option delete updraft_central_localkeys).
EOF
	;;
	persistence) cat <<'EOF'
Persistence means an attacker had code execution. Preserve first (copy the file, `stat` it, note what it runs),
then remove it, and find how they got in (web roots, Plex, Nextcloud, SSH). Safest: rebuild the host from clean
media and restore data only; rotate SSH keys, passwords and any credentials stored on the machine.
Review: crontab -l -u <user> ; systemctl cat <unit> ; ls -la ~/.ssh ; cat /etc/ld.so.preload
EOF
	;;
	attempts) cat <<'EOF'
Probes are normal internet noise; they matter when they hit a version that was vulnerable at the time.
Memory-limit fatals are PHP2Shell's trigger condition: compare their timestamps with POST requests to PHP endpoints
in the access log, and if PHP was unpatched at that time, look for new PHP files and admins (re-run with --deep).
  docker logs --since <date> <container> 2>&1 | grep -E 'Allowed memory size|uploads/.*\.php'
EOF
	;;
	crash) cat <<'EOF'
Repeated segfaults of PHP / nginx / Plex workers are consistent with memory-corruption exploit attempts
(PHP2Shell, NGINX CVE-2026-15176 / -97205). Patch first, then review files changed around each crash time:
  find <webroot> -newermt '<crash time - 5 min>' ! -newermt '<crash time + 30 min>'
EOF
	;;
	drift) cat <<'EOF'
Files were added or changed inside the container (outside its volumes) after it started — not from the image.
Inspect:  docker diff <container> ; docker exec <container> ls -la <path>
Preserve: docker export <container> > evidence.tar   (recreating the container discards these changes)
Then recreate it from a clean, patched image and check its volumes with the webshell steps.
EOF
	;;
	cpu) cat <<'EOF'
Identify the process before killing it:
  ps -o pid,ppid,user,etime,args -p <pid> ; ls -l /proc/<pid>/exe ; ss -tnp | grep 'pid=<pid>,'
Miners usually connect to pool ports such as 3333, 4444, 5555, 7777 or 14444. If it's a miner, follow "Attacker activity".
EOF
	;;
	containers) echo "Check those images' PHP / NGINX / Plex versions against the fixed versions above, e.g. docker image inspect." ;;
	esac
}

# rem_scope KEY → "host", "container" or "host container": where KEY's open findings are
rem_scope() {
	local i h="" c=""
	for ((i = 0; i < ${#F_REM[@]}; i++)); do
		[ "${F_REM[$i]}" = "$1" ] || continue
		case ${F_STAT[$i]} in OK | N/A | SKIPPED) continue ;; esac
		case ${F_DETAIL[$i]} in "container "* | "service "*) c=container ;; *) h=host ;; esac
	done
	printf '%s %s' "$h" "$c"
}

# ctr_redeploy_hint VERIFY-CMD: how to recreate containers for the detected orchestration
ctr_redeploy_hint() {
	if [ "$CAPROVER" = 1 ]; then
		echo "  CapRover: for each app, redeploy on a fixed image — Deployment → \"Deploy via ImageName\" with a tag"
		echo "  published after the fix, or bump FROM in the app's Dockerfile and redeploy (docker pull the base first)."
	elif [ "$SWARM" = 1 ]; then
		echo "  Swarm: docker service update --force --image <image>:<fixed-tag> <service>"
	else
		echo "  Compose: docker compose pull && docker compose up -d --force-recreate"
	fi
	echo "  Verify inside each container afterwards: docker exec <container> $1"
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
stat_rank() { case $1 in IOC) echo 0 ;; VULNERABLE) echo 1 ;; CHECK) echo 2 ;; OK) echo 3 ;; N/A) echo 4 ;; *) echo 5 ;; esac; }
sev_rank() { case $1 in CRIT) echo 0 ;; HIGH) echo 1 ;; MED) echo 2 ;; LOW) echo 3 ;; *) echo 4 ;; esac; }

sorted_indices() {
	local i
	for ((i = 0; i < ${#F_STAT[@]}; i++)); do
		printf '%s %s %03d\n' "$(stat_rank "${F_STAT[$i]}")" "$(sev_rank "${F_SEV[$i]}")" "$i"
	done | sort | awk '{ print $3 + 0 }'
}

# verdict → "clean", "review" or "compromised" (from the exploitation section, INFO rows excluded)
verdict() {
	local i v=clean
	for ((i = 0; i < ${#F_STAT[@]}; i++)); do
		[ "${F_KIND[$i]}" = ioc ] && [ "${F_SEV[$i]}" != INFO ] || continue
		case ${F_STAT[$i]} in
		IOC) v=compromised ;;
		CHECK) [ "$v" = clean ] && v=review ;;
		esac
	done
	printf '%s' "$v"
}

render_text() {
	local c_red="" c_yel="" c_grn="" c_dim="" c_bold="" c_off="" idx keys=" " key n col sev kind
	if [ "$OPT_COLOR" != never ] && [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
		c_red=$'\033[31m' c_yel=$'\033[33m' c_grn=$'\033[32m' c_dim=$'\033[2m' c_bold=$'\033[1m' c_off=$'\033[0m'
	fi
	local rule="──────────────────────────────────────────────────────────────────────"
	printf '%soct2026-scan %s%s · %s · %s · kernel %s · %s\n' "$c_bold" "$SCAN_VERSION" "$c_off" "$HOST" "$OS_PRETTY" "$KREL" \
		"$([ "$IS_ROOT" = 1 ] && echo "root ✓" || echo "not root: partial scan")"
	printf '%sfix data as of %s — latest: https://github.com/alex-red/2026-october-security-scan%s\n' "$c_dim" "$DATA_DATE" "$c_off"
	local order rems="" refs
	order=$(sorted_indices)
	# Remediation numbers follow display order: vulnerabilities first, then evidence
	for kind in vuln ioc; do
		for idx in $order; do
			[ "${F_KIND[$idx]}" = "$kind" ] || continue
			key=${F_REM[$idx]}
			case ${F_STAT[$idx]} in OK | N/A | SKIPPED) continue ;; esac
			[ -n "$key" ] || continue
			case $keys in *" $key "*) ;; *) keys="$keys$key " rems="$rems $key" ;; esac
		done
	done
	for kind in vuln ioc; do
		if [ "$kind" = vuln ]; then
			printf '\n%sVulnerabilities%s\n%s\n' "$c_bold" "$c_off" "$rule"
		else
			case $(verdict) in
			compromised) v="${c_red}${c_bold}LIKELY COMPROMISED — indicators found${c_off}" ;;
			review) v="${c_yel}${c_bold}REVIEW — findings that could mean exploitation${c_off}" ;;
			*) v="${c_grn}${c_bold}no signs of exploitation found${c_off} ${c_dim}(not proof of a clean host)${c_off}" ;;
			esac
			printf '\n%sSigns of exploitation since %s:%s %s\n%s\n' "$c_bold" "$SINCE" "$c_off" "$v" "$rule"
		fi
		for idx in $order; do
			[ "${F_KIND[$idx]}" = "$kind" ] || continue
			case ${F_STAT[$idx]} in
			IOC | VULNERABLE) col=$c_red ;;
			CHECK) col=$c_yel ;;
			OK) col=$c_grn ;;
			*) col=$c_dim ;;
			esac
			case ${F_STAT[$idx]} in OK | N/A | SKIPPED) [ "$OPT_QUIET" = 1 ] && continue; sev="" ;; *) sev=${F_SEV[$idx]} ;; esac
			refs=""
			if [ -n "${F_REM[$idx]}" ] && [ "$sev" != "" ]; then
				n=0
				for key in $rems; do n=$((n + 1)); [ "$key" = "${F_REM[$idx]}" ] && refs=" [$n]"; done
			fi
			printf '%-4s  %s%-10s%s  %-30s %s%s\n' "$sev" "$col" "${F_STAT[$idx]}" "$c_off" "${F_COMP[$idx]}" "${F_DETAIL[$idx]}" "$refs"
		done
	done
	printf '%s\n' "$rule"
	if [ -n "$rems" ]; then
		printf '%sRemediation%s\n' "$c_bold" "$c_off"
		n=0
		for key in $rems; do
			n=$((n + 1))
			printf '\n%s[%d] %s%s\n' "$c_bold" "$n" "$(rem_title "$key")" "$c_off"
			rem_body "$key" | sed 's/^/    /'
		done
		printf '%s\n' "$rule"
	else
		printf '%sNothing to fix from this list.%s\n' "$c_grn" "$c_off"
	fi
	[ "$IS_ROOT" = 1 ] || printf '%sNot root: nginx config, other users'"'"' files, containers, logs and process checks were limited. Re-run with sudo.%s\n' "$c_yel" "$c_off"
	[ "$OPT_DEEP" = 1 ] || printf '%sFor a full webshell scan of all PHP files and new WordPress admins, re-run with --deep.%s\n' "$c_dim" "$c_off"
	printf '%sUpdating stops new exploitation but does not remove an existing compromise. Re-run after patching/rebooting.%s\n' "$c_dim" "$c_off"
}

json_str() {
	local s=$1
	s=${s//\\/\\\\}
	s=${s//\"/\\\"}
	s=${s//$'\n'/\\n}
	s=${s//$'\t'/\\t}
	s=${s//$'\r'/}
	printf '"%s"' "$s"
}

render_json() {
	local idx first=1 keys=" " key
	printf '{"scanner":"oct2026-scan","version":%s,"data_date":%s,"host":%s,"os":%s,"kernel":%s,"root":%s,"since":%s,"verdict":%s,"findings":[' \
		"$(json_str "$SCAN_VERSION")" "$(json_str "$DATA_DATE")" "$(json_str "$HOST")" "$(json_str "$OS_PRETTY")" \
		"$(json_str "$KREL")" "$([ "$IS_ROOT" = 1 ] && echo true || echo false)" "$(json_str "$SINCE")" "$(json_str "$(verdict)")"
	for idx in $(sorted_indices); do
		[ "$first" = 1 ] || printf ','
		first=0
		printf '{"kind":%s,"severity":%s,"status":%s,"component":%s,"detail":%s,"remediation":%s}' \
			"$(json_str "${F_KIND[$idx]}")" "$(json_str "${F_SEV[$idx]}")" "$(json_str "${F_STAT[$idx]}")" "$(json_str "${F_COMP[$idx]}")" \
			"$(json_str "${F_DETAIL[$idx]}")" "$(json_str "${F_REM[$idx]}")"
		key=${F_REM[$idx]}
		[ -n "$key" ] && case $keys in *" $key "*) ;; *) keys="$keys$key " ;; esac
	done
	printf '],"remediation":{'
	first=1
	for key in $keys; do
		[ "$first" = 1 ] || printf ','
		first=0
		printf '%s:{"title":%s,"steps":%s}' "$(json_str "$key")" "$(json_str "$(rem_title "$key")")" "$(json_str "$(rem_body "$key")")"
	done
	printf '}}\n'
}

# INFO findings (e.g. the kernel flaw on a host without VMs) never change the exit code
exit_code() {
	local i code=0
	for ((i = 0; i < ${#F_STAT[@]}; i++)); do
		[ "${F_SEV[$i]}" = INFO ] && continue
		case ${F_STAT[$i]} in
		IOC | VULNERABLE) code=2 ;;
		CHECK) [ "$code" -lt 1 ] && code=1 ;;
		esac
	done
	return "$code"
}

main() {
	parse_args "$@"
	[ "$(uname -s)" = Linux ] || { echo "oct2026-scan only runs on Linux" >&2; exit 3; }
	detect_env
	local d
	d=$(( ($(date +%s) - $(date -d "$SINCE" +%s 2>/dev/null || date +%s)) / 86400 + 1 ))
	[ "$d" -gt 0 ] && DAYS=$d
	[ "$OPT_JSON" = 1 ] || [ ! -t 2 ] || printf 'scanning…\r' >&2
	CUR_KIND=vuln
	check_containers
	check_php
	check_nginx
	check_plex_host
	check_kernel
	check_nextcloud_host
	check_wordpress_host
	check_curl
	check_simple_pkg ghostscript ghostscript MED ghostscript "Ghostscript"
	check_siteguard
	check_exposure
	CUR_KIND=ioc
	check_containers_ioc
	check_wp_users_containers
	check_host_webroots_ioc
	check_host_logs
	check_web_children
	check_net_shells
	check_cpu
	check_persistence
	check_ioc
	[ "$OPT_JSON" = 1 ] || [ ! -t 2 ] || printf '           \r' >&2
	if [ "$OPT_JSON" = 1 ]; then render_json; else render_text; fi
	exit_code
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	main "$@"
fi
