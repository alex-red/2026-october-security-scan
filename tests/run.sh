#!/usr/bin/env bash
# Unit tests for oct2026-scan.sh evaluators. No dependencies: bash tests/run.sh
# `cond && ok || bad` is intentional throughout: ok never fails.
# shellcheck disable=SC2015
set -u
cd "$(dirname "$0")/.." || exit 1
# shellcheck source=oct2026-scan.sh
. ./oct2026-scan.sh

PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $*"; }

reset() { F_SEV=(); F_STAT=(); F_COMP=(); F_DETAIL=(); F_REM=(); LISTEN=""; PLEX_SEEN=0; }
last_stat() { echo "${F_STAT[$((${#F_STAT[@]} - 1))]}"; }
last_detail() { echo "${F_DETAIL[$((${#F_DETAIL[@]} - 1))]}"; }

# expect_stat DESCRIPTION EXPECTED-STATUS command...
expect_stat() {
	local desc=$1 want=$2 got
	shift 2
	reset
	"$@"
	got=$(last_stat)
	[ "$got" = "$want" ] && ok || bad "$desc: want $want, got $got ($(last_detail))"
}

# --- version comparison (awk implementation of dpkg's algorithm) ---
vc() {
	local got
	got=$(vcmp_awk "$1" "$2")
	[ "$got" = "$3" ] && ok || bad "vcmp_awk $1 vs $2: want $3, got $got"
}
vc 1.0 1.0 0
vc 1.0~rc1 1.0 -1
vc 1.0 1.0+deb1 -1
vc 1:1.0 2.0 1
vc 8.3.6-0ubuntu0.24.04.12 8.3.6-0ubuntu0.24.04.13 -1
vc 8.3.6-0ubuntu0.24.04.13 8.3.6-0ubuntu0.24.04.13 0
vc 7.0.14-9 7.0.14-24 -1
vc 1.43.3.10861 1.43.3.9999 1
vc 1.43.2.10500 1.43.3.10861 -1
vc 8.2.35-1~deb12u1 8.2.32-1~deb12u1 1
vc 10.02.1~dfsg1-0ubuntu7.10 10.02.1~dfsg1-0ubuntu7.9 1
vc 7.4.3-4ubuntu2.29+esm5 7.4.3-4ubuntu2.29 1
vc 1.0a 1.0 1
vc 1.0 1.0.0 -1

# Use dpkg when available (CI runs the suite both ways via OCT_SCAN_VCMP=awk)
have dpkg || OCT_SCAN_VCMP=awk

# --- helpers ---
[ "$(upstream 1:8.3.6-0ubuntu0.24.04.13)" = 8.3.6 ] && ok || bad upstream-epoch
[ "$(upstream 10.02.1~dfsg1-0ubuntu7.10)" = 10.02.1 ] && ok || bad upstream-tilde
[ "$(upstream 1.43.3.10861-5b6d4c3b2)" = 1.43.3.10861 ] && ok || bad upstream-plex
[ "$(upstream 8.3.36-r0)" = 8.3.36 ] && ok || bad upstream-alpine
is_distro_build 1.24.0-2ubuntu7.4 && ok || bad distro-ubuntu
is_distro_build 1.22.1-9+deb12u2 && ok || bad distro-debian
is_distro_build 8.3.36-1+ubuntu24.04.1+deb.sury.org+1 && bad sury-not-distro || ok
is_distro_build 1.30.6-1~noble && bad nginx-org-not-distro || ok

# --- PHP ---
expect_stat "php noble old" VULNERABLE eval_php t php8.3 8.3.6-0ubuntu0.24.04.12 ubuntu noble pkg
expect_stat "php noble fixed" OK eval_php t php8.3 8.3.6-0ubuntu0.24.04.13 ubuntu noble pkg
expect_stat "php jammy fixed backport" OK eval_php t php8.1 8.1.2-1ubuntu2.28 ubuntu jammy pkg
expect_stat "php bookworm old" VULNERABLE eval_php t php8.2 8.2.32-1~deb12u1 debian bookworm pkg
expect_stat "php trixie fixed" OK eval_php t php8.4 8.4.27-1~deb13u1 debian trixie pkg
expect_stat "php xenial needs pro" VULNERABLE eval_php t php7.0 7.0.33-0ubuntu0.16.04.16 ubuntu xenial pkg
[ "${F_REM[0]}" = php_eol ] && ok || bad "xenial remediation should be php_eol"
expect_stat "php sury old" VULNERABLE eval_php t php8.3 8.3.35-1+ubuntu24.04.1+deb.sury.org+1 ubuntu noble pkg
expect_stat "php sury fixed" OK eval_php t php8.3 8.3.36-1+ubuntu24.04.1+deb.sury.org+1 ubuntu noble pkg
expect_stat "php unknown distro build" CHECK eval_php t php8.2 8.2.7-1+deb99u1 debian futura pkg
expect_stat "php raw 8.4.26" VULNERABLE eval_php t "" 8.4.26 "" "" raw
expect_stat "php raw 8.5.12" OK eval_php t "" 8.5.12 "" "" raw
expect_stat "php raw 7.4 eol" VULNERABLE eval_php t "" 7.4.33 "" "" raw
expect_stat "php raw 8.1 eol" VULNERABLE eval_php t "" 8.1.31 "" "" raw

# --- NGINX ---
expect_stat "nginx 1.30.5" VULNERABLE eval_nginx t 1.30.5
expect_stat "nginx 1.30.6" OK eval_nginx t 1.30.6
expect_stat "nginx 1.31.6" VULNERABLE eval_nginx t 1.31.6
expect_stat "nginx 1.31.8" OK eval_nginx t 1.31.8
expect_stat "nginx 1.27.4 container" VULNERABLE eval_nginx t 1.27.4
expect_stat "nginx.org pkg 1.30.6" OK eval_nginx t 1.30.6-1~noble
expect_stat "nginx ubuntu distro" CHECK eval_nginx t 1.24.0-2ubuntu7.4
expect_stat "nginx debian distro" CHECK eval_nginx t 1.22.1-9+deb12u2

# --- Plex ---
expect_stat "plex old" VULNERABLE eval_plex t 1.43.2.10500-abcdef
expect_stat "plex fixed" OK eval_plex t 1.43.3.10861-5b6d4c3b2
expect_stat "plex newer" OK eval_plex t 1.44.0.100-aaaa
reset
LISTEN="0.0.0.0:32400"
eval_plex t 1.42.0.1-a
case $(last_detail) in *"assume compromise"*) ok ;; *) bad "plex exposure note" ;; esac
reset
LISTEN="127.0.0.1:32400"
public_port 32400 && bad "loopback is not public" || ok
LISTEN="[::]:443"
public_port 443 && ok || bad "[::] is public"

reset
D="/c/Codecs"
plex_codecs_eval t "$D" "$D/abc-1.43-linux-x86_64/libhevc_decoder.so
$D/abc-1.43-linux-x86_64/libaac_encoder.so"
[ ${#F_STAT[@]} = 0 ] && ok || bad "normal codecs should be clean"
reset
plex_codecs_eval t "$D" "$D/evil.so"
[ "$(last_stat)" = IOC ] && ok || bad "top-level .so should be IOC"
reset
plex_codecs_eval t "$D" "$D/abc/libminer.so"
[ "$(last_stat)" = CHECK ] && ok || bad "odd codec name should be CHECK"

# --- Kernel ---
expect_stat "pve 7.0.14-9" VULNERABLE eval_kernel 1 debian trixie 7.0.14-9-pve "" 1 ctx
expect_stat "pve 7.0.14-24" OK eval_kernel 1 debian trixie 7.0.14-24-pve "" 1 ctx
expect_stat "pve 7.0.14-25" OK eval_kernel 1 debian trixie 7.0.14-25-pve "" 1 ctx
expect_stat "pve 6.8 eol series" VULNERABLE eval_kernel 1 debian bookworm 6.8.12-1-pve "" 1 ctx
[ "${F_SEV[0]}" = CRIT ] && ok || bad "kvm host should be CRIT"
expect_stat "debian 13 old" VULNERABLE eval_kernel 0 debian trixie 6.12.0-1-amd64 "#1 SMP PREEMPT_DYNAMIC Debian 6.12.110-1 (2026-09-01)" 0 ctx
[ "${F_SEV[0]}" = LOW ] && ok || bad "non-kvm should be LOW"
expect_stat "debian 13 fixed" OK eval_kernel 0 debian trixie 6.12.0-1-amd64 "#1 SMP PREEMPT_DYNAMIC Debian 6.12.113-1 (2026-10-16)" 0 ctx
expect_stat "debian 12 bpo" CHECK eval_kernel 0 debian bookworm 6.12.0-0.bpo-amd64 "#1 SMP Debian 6.12.48-1~bpo12+1 (2026-08-01)" 0 ctx
expect_stat "ubuntu no fix" CHECK eval_kernel 0 ubuntu noble 6.8.0-80-generic "#80-Ubuntu SMP" 1 ctx
expect_stat "upstream 6.18.54" VULNERABLE eval_kernel 0 arch "" 6.18.54-1-lts "#1 SMP" 0 ctx
expect_stat "upstream 6.18.57" OK eval_kernel 0 arch "" 6.18.57 "#1 SMP" 0 ctx
expect_stat "upstream unknown series" CHECK eval_kernel 0 arch "" 6.15.2 "#1 SMP" 0 ctx

# --- Nextcloud / UpdraftPlus ---
expect_stat "code old" VULNERABLE eval_nextcloud_code t 26.4.302
expect_stat "code fixed" OK eval_nextcloud_code t 26.4.303
expect_stat "code unreadable" CHECK eval_nextcloud_code t ""
expect_stat "updraft free old" VULNERABLE eval_updraft t 1.26.12
expect_stat "updraft free fixed" OK eval_updraft t 1.26.13
expect_stat "updraft premium old" VULNERABLE eval_updraft t 2.26.12
expect_stat "updraft premium fixed" OK eval_updraft t 2.26.13

# --- data table ---
[ "$(fixed_lookup ghostscript ubuntu noble ghostscript)" = "10.02.1~dfsg1-0ubuntu7.10 USN-8949-1" ] && ok || bad "fixed_lookup ghostscript"
[ -z "$(fixed_lookup ghostscript debian bookworm ghostscript)" ] && ok || bad "bookworm ghostscript has no fix"

# --- container probe parsing ---
reset
eval_container web nginx:1.30.4 "nginx=1.30.4
os=debian:bookworm"
[ "$(last_stat)" = VULNERABLE ] && ok || bad "container nginx raw"
reset
eval_container app php:8.3-apache "php=8.3.36
os=debian:trixie
updraft=/var/www/html|1.26.10"
[ "${F_STAT[0]}" = VULNERABLE ] && [ "${F_COMP[0]}" = "UpdraftPlus 1.26.10" ] && ok || bad "container updraft"
[ "$(last_stat)" = OK ] && ok || bad "container php 8.3.36 should be OK"
reset
eval_container plex lscr.io/linuxserver/plex "pkg=plexmediaserver=1.43.2.10500-abc
os=ubuntu:noble
plexcodecs=/config/Library/Application Support/Plex Media Server/Codecs
plexso=/config/Library/Application Support/Plex Media Server/Codecs/x.so"
[ "${F_STAT[0]}" = VULNERABLE ] && [ "${F_STAT[1]}" = IOC ] && ok || bad "container plex: ${F_STAT[*]}"

# --- JSON escaping and exit code ---
[ "$(json_str 'a"b\c')" = '"a\"b\\c"' ] && ok || bad "json_str: $(json_str 'a"b\c')"
expect_exit() { local rc=0; exit_code || rc=$?; [ "$rc" = "$1" ] && ok || bad "exit code: want $1, got $rc"; }
reset; add CRIT OK x y; expect_exit 0
reset; add CRIT CHECK x y; expect_exit 1
reset; add CRIT CHECK x y; add CRIT IOC x y; expect_exit 2

echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" = 0 ]
