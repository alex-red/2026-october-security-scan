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

SCAN_VERSION="1.0.0"
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

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
OPT_JSON=0
OPT_DOCKER=1
OPT_DEEP=0
OPT_QUIET=0
OPT_COLOR=auto

usage() {
	cat <<EOF
oct2026-scan $SCAN_VERSION — read-only check for the October 2026 Linux server vulnerabilities
(data as of $DATA_DATE)

Usage: sudo bash oct2026-scan.sh [options]

  --json        machine-readable output
  --no-docker   do not inspect running containers (docker exec / podman exec)
  --deep        wider filesystem search, rotated logs, and WordPress user audit via wp-cli
  -q, --quiet   hide OK / N/A rows
  --no-color    disable colors (NO_COLOR is honoured too)
  -h, --help    this help
  -V, --version print version

Exit codes: 0 nothing found, 1 needs review (CHECK), 2 vulnerable or indicator of compromise, 3 error
Latest version: https://github.com/alex-red/2026-october-security-scan
EOF
}

parse_args() {
	while [ $# -gt 0 ]; do
		case $1 in
		--json) OPT_JSON=1 ;;
		--no-docker) OPT_DOCKER=0 ;;
		--deep) OPT_DEEP=1 ;;
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

# add SEVERITY STATUS COMPONENT DETAIL [REMEDIATION-KEY]
# SEVERITY: CRIT HIGH MED LOW INFO
# STATUS:   IOC VULNERABLE CHECK OK N/A SKIPPED
add() {
	F_SEV[${#F_SEV[@]}]=$1
	F_STAT[${#F_STAT[@]}]=$2
	F_COMP[${#F_COMP[@]}]=$3
	F_DETAIL[${#F_DETAIL[@]}]=$4
	F_REM[${#F_REM[@]}]=${5:-}
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
	local pve=$1 os=$2 cn=$3 rel=$4 uv=$5 kvm=$6 ctx=$7 sev=LOW base fx="" row ref
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
$(src_versions '^php[0-9]+(\.[0-9]+)?$')
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
	check_plex_children
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
		found=1
		dir=${f%/appinfo/info.xml}
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
	local f site ver up recent mu sites=0 owner admins
	while IFS= read -r f; do
		[ -n "$f" ] || continue
		site=${f%/wp-includes/version.php}
		sites=$((sites + 1))
		up="$site/wp-content/plugins/updraftplus/updraftplus.php"
		[ -f "$up" ] || continue
		ver=$(sed -n 's/^[ *]*Version:[ ]*\([0-9][0-9.]*\).*/\1/p' "$up" | head -n1)
		eval_updraft "$site" "$ver"
		recent=$(newer_than "$site/wp-content/plugins" "$UPDRAFT_INCIDENT_START" | grep -v '/updraftplus$' | sed 's|.*/||' | head -n10)
		mu=$(newer_than "$site/wp-content/mu-plugins" "$UPDRAFT_INCIDENT_START" | sed 's|.*/||' | head -n10)
		[ -n "$recent" ] && add HIGH CHECK "WordPress plugins" "$site: plugins added/changed since $UPDRAFT_INCIDENT_START: $(oneline "$recent")" updraft
		[ -n "$mu" ] && add HIGH CHECK "WordPress mu-plugins" "$site: must-use plugins added/changed since $UPDRAFT_INCIDENT_START: $(oneline "$mu")" updraft
		if [ "$OPT_DEEP" = 1 ] && [ "$IS_ROOT" = 1 ] && have wp; then
			# Run wp-cli as the site owner without loading plugins/themes (they may be backdoored)
			owner=$(stat -c %U "$site/wp-config.php" 2>/dev/null || stat -c %U "$site" 2>/dev/null)
			admins=$(for role in administrator editor; do
				timeout 30 runuser -u "${owner:-www-data}" -- wp --path="$site" --skip-plugins --skip-themes \
					user list --role="$role" --fields=user_login,user_registered --format=csv 2>/dev/null
			done | awk -F, -v d="$UPDRAFT_INCIDENT_START" '$1 != "user_login" && $2 >= d { print $1 }')
			[ -n "$admins" ] && add CRIT IOC "WordPress users" "$site: admin/editor accounts created since $UPDRAFT_INCIDENT_START: $(oneline "$admins")" updraft
		fi
	done <<EOF
$(find_in_roots '*/wp-includes/version.php' 6)
EOF
	[ "$sites" = 0 ] && add HIGH N/A "WordPress / UpdraftPlus" "no WordPress sites found on host"
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
	local name image out n=0 noshell=""
	while IFS="$(printf '\t')" read -r name image; do
		[ -n "$name" ] || continue
		n=$((n + 1))
		if ! out=$(timeout 30 "$CTR" exec "$name" sh -c "$PROBE" 2>/dev/null); then
			[ -n "$out" ] || { noshell="$noshell $name"; continue; }
		fi
		eval_container "$name" "$image" "$out"
	done <<EOF
$("$CTR" ps --format '{{.Names}}\t{{.Image}}' 2>/dev/null)
EOF
	[ -n "$noshell" ] && add INFO CHECK "Containers without shell" "could not inspect:$noshell — check their image versions manually" containers
	add INFO OK "Containers" "$n running container(s) inspected via $CTR exec"
}

# eval_container NAME IMAGE PROBE-OUTPUT
eval_container() {
	local name=$1 image=$2 out=$3 line k v os="" cn="" php="" nginx="" plexflag=0 codecs="" sos=""
	local pkgs="" src ver lbl
	lbl="container $name"
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
# Generic indicators of compromise and exposure
# ---------------------------------------------------------------------------
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
	[ "$any" = 0 ] && add CRIT OK "IOC sweep" "no known miner/proxy processes, attacker IPs or temp-dir binaries"
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
	ioc) echo "Indicators of compromise" ;;
	containers) echo "Containers that could not be inspected" ;;
	*) echo "$1" ;;
	esac
}

rem_body() {
	case $1 in
	php) cat <<EOF
sudo apt update && sudo apt install --only-upgrade \$(dpkg-query -W -f='\${Package}\n' 'php*' 'libapache2-mod-php*' | grep -E '^(php|libapache2)')
then restart every PHP process: sudo systemctl restart 'php*-fpm' apache2 (whichever you run)
Containers: pull a fixed image (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35+), then recreate — restarting is not enough:
  docker compose pull && docker compose up -d --force-recreate
Stopgap only: session.upload_progress.enabled = Off, limit request body size, restart workers.
If this host was internet-facing before patching, look for webshells:
  sudo find /var/www -name '*.php' -newermt $PHP2SHELL_DISCLOSED -ls
Ref: https://ubuntu.com/blog/php2shell-vulnerability-fixes-available · https://security-tracker.debian.org/tracker/CVE-2026-109618
EOF
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
nginx.org repo: upgrade to 1.30.6+ (stable) or 1.31.7+ (mainline). Containers: pull nginx:1.30.6+ and recreate.
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
  Docker: docker compose pull && docker compose up -d --force-recreate
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
	containers) echo "Check those images' PHP / NGINX / Plex versions against the fixed versions above, e.g. docker image inspect." ;;
	esac
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

render_text() {
	local c_red="" c_yel="" c_grn="" c_dim="" c_bold="" c_off="" i idx keys=" " key n=0 col sev
	if [ "$OPT_COLOR" != never ] && [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
		c_red=$'\033[31m' c_yel=$'\033[33m' c_grn=$'\033[32m' c_dim=$'\033[2m' c_bold=$'\033[1m' c_off=$'\033[0m'
	fi
	local rule="──────────────────────────────────────────────────────────────────────"
	printf '%soct2026-scan %s%s · %s · %s · kernel %s · %s\n' "$c_bold" "$SCAN_VERSION" "$c_off" "$HOST" "$OS_PRETTY" "$KREL" \
		"$([ "$IS_ROOT" = 1 ] && echo "root ✓" || echo "not root: partial scan")"
	printf '%sfix data as of %s — latest: https://github.com/alex-red/2026-october-security-scan%s\n%s\n' "$c_dim" "$DATA_DATE" "$c_off" "$rule"
	local order rems="" refs
	order=$(sorted_indices)
	# Assign remediation numbers in display order
	for idx in $order; do
		key=${F_REM[$idx]}
		case ${F_STAT[$idx]} in OK | N/A | SKIPPED) continue ;; esac
		[ -n "$key" ] || continue
		case $keys in *" $key "*) ;; *) keys="$keys$key " rems="$rems $key" ;; esac
	done
	for idx in $order; do
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
	[ "$IS_ROOT" = 1 ] || printf '%sNot root: nginx config, other users'"'"' files, containers and stale-process checks were limited. Re-run with sudo.%s\n' "$c_yel" "$c_off"
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
	printf '{"scanner":"oct2026-scan","version":%s,"data_date":%s,"host":%s,"os":%s,"kernel":%s,"root":%s,"findings":[' \
		"$(json_str "$SCAN_VERSION")" "$(json_str "$DATA_DATE")" "$(json_str "$HOST")" "$(json_str "$OS_PRETTY")" \
		"$(json_str "$KREL")" "$([ "$IS_ROOT" = 1 ] && echo true || echo false)"
	for idx in $(sorted_indices); do
		[ "$first" = 1 ] || printf ','
		first=0
		printf '{"severity":%s,"status":%s,"component":%s,"detail":%s,"remediation":%s}' \
			"$(json_str "${F_SEV[$idx]}")" "$(json_str "${F_STAT[$idx]}")" "$(json_str "${F_COMP[$idx]}")" \
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

exit_code() {
	local i code=0
	for ((i = 0; i < ${#F_STAT[@]}; i++)); do
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
	[ "$OPT_JSON" = 1 ] || [ ! -t 2 ] || printf 'scanning…\r' >&2
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
	check_ioc
	check_exposure
	[ "$OPT_JSON" = 1 ] || [ ! -t 2 ] || printf '           \r' >&2
	if [ "$OPT_JSON" = 1 ]; then render_json; else render_text; fi
	exit_code
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	main "$@"
fi
