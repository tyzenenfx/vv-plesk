#!/usr/bin/env bash
# plesk_php_audit.sh  (v3)
# Read-only PHP audit for Linux servers (Plesk shared, Plesk dedicated, or non-Plesk). Changes nothing.
#  - Verdict per PHP build: Plesk website PHP, Plesk panel PHP, OS PHP, CloudLinux alt-php
#  - Fails closed: EOL version (< 7.4) or unreadable build date = NOT PATCHED
#  - Counts domains by PHP status (no domain names unless --list-domains)
#  - Counts processes still running replaced (old) PHP binaries
#
# Usage:
#   CUTOFF="YYYY-MM-DD" bash plesk_php_audit.sh                 # readable report
#   CUTOFF="YYYY-MM-DD" bash plesk_php_audit.sh --csv           # one CSV row for this server
#   bash plesk_php_audit.sh --csv-header                        # the CSV header row only
#   CUTOFF="YYYY-MM-DD" bash plesk_php_audit.sh --list-domains  # report + domain names (for migration work)
#
#   CUTOFF = fix date from the Plesk security advisory for the current CVE.
#
# Domain counts:
#   unsupported = PHP below 7.4, or a version whose installed build is not patched  -> move now
#   stopgap     = patched Plesk 7.4 / 8.0 / 8.1 backport builds (allowed temporarily) -> plan move to 8.2+
#   supported   = PHP 8.2 or later on a patched build
# Exit code = number of problems found (0 = compliant).

CUTOFF="${CUTOFF:-2026-10-21}"
MODE="report"; LIST_DOMAINS=0
for a in "$@"; do
  case "$a" in
    --csv) MODE="csv" ;;
    --csv-header) MODE="header" ;;
    --list-domains) LIST_DOMAINS=1 ;;
    *) echo "Unknown option: $a" >&2; exit 98 ;;
  esac
done

HEADER="hostname,os,plesk_version,audit_date_utc,cutoff,php_builds_total,php_builds_not_patched,not_patched_versions,panel_php,domains_with_php,domains_unsupported,domains_stopgap,domains_supported,unsupported_breakdown,stale_php_processes,result"
if [ "$MODE" = "header" ]; then echo "$HEADER"; exit 0; fi

CUTOFF_TS=$(date -d "$CUTOFF" +%s) || { echo "Bad CUTOFF date: $CUTOFF" >&2; exit 99; }

# In CSV mode the readable report is discarded; only the final row is printed.
if [ "$MODE" = "csv" ]; then exec 3>&1 1>/dev/null; LIST_DOMAINS=0; fi
if [ -t 1 ]; then RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; NC=$'\e[0m'; else RED=; GRN=; YEL=; NC=; fi

FAILS=0; BUILDS=0; BUILDS_BAD=0; BAD_LIST=""; PANEL="n/a"
declare -A BAD_VER=()      # "7.0" -> reason, for versions whose build failed

is_eol() {                  # $1 = version like 5.6.40 or 7.4
  local major minor
  major=${1%%.*}; minor=${1#*.}; minor=${minor%%.*}
  [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] || return 0   # unknown version = treat as EOL
  [ "$major" -lt 7 ] || { [ "$major" -eq 7 ] && [ "$minor" -lt 4 ]; }
}

is_stopgap() {              # 7.4, 8.0, 8.1
  case "$1" in 7.4|8.0|8.1) return 0 ;; *) return 1 ;; esac
}

pkg_of() {
  if command -v rpm >/dev/null 2>&1; then
    rpm -qf "$1" --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' 2>/dev/null | grep -v 'not owned' | head -1
  elif command -v dpkg >/dev/null 2>&1; then
    local p; p=$(dpkg -S "$1" 2>/dev/null | head -1 | cut -d: -f1)
    [ -n "$p" ] && echo "$p $(dpkg-query -W -f='${Version}' "$p" 2>/dev/null)"
  fi
}

build_ts() {                # build date from "php -v": (built: Oct 21 2026 13:44:08)
  local b; b=$("$1" -v 2>/dev/null | head -1 | sed -n 's/.*built: \([^)]*\)).*/\1/p')
  [ -n "$b" ] && date -d "$b" +%s 2>/dev/null
}

verdict() {                 # $1 version  $2 build ts  -> prints verdict, returns 1 if not patched
  if is_eol "$1"; then echo "NOT PATCHED (EOL)"; return 1; fi
  if [ -z "$2" ]; then echo "NOT PATCHED (unknown build)"; return 1; fi
  if [ "$2" -lt "$CUTOFF_TS" ]; then echo "NOT PATCHED (old build)"; return 1; fi
  echo "PATCHED"; return 0
}

check_binary() {            # $1 label  $2 binary  $3 short tag for CSV
  local label="$1" bin="$2" tag="$3" ver ts v rc pkg built
  [ -x "$bin" ] || return 1
  ver=$("$bin" -v 2>/dev/null | head -1 | awk '{print $2}')
  [ -z "$ver" ] && ver="unknown"
  ts=$(build_ts "$bin")
  v=$(verdict "$ver" "$ts"); rc=$?
  built=$([ -n "$ts" ] && date -d "@$ts" +%Y-%m-%d || echo "unknown")
  BUILDS=$((BUILDS+1))
  LAST_VERDICT="$v"
  if [ $rc -eq 0 ]; then
    printf '%-30s %-22s %-10s built %s\n' "${GRN}${v}${NC}" "$label" "$ver" "$built"
  else
    printf '%-30s %-22s %-10s built %s\n' "${RED}${v}${NC}" "$label" "$ver" "$built"
    FAILS=$((FAILS+1)); BUILDS_BAD=$((BUILDS_BAD+1))
    BAD_VER["${ver%.*}"]="$v"
    BAD_LIST="${BAD_LIST:+$BAD_LIST }${tag}"
  fi
  pkg=$(pkg_of "$bin"); [ -n "$pkg" ] && printf '%-21s package: %s\n' "" "$pkg"
  return 0
}

HAS_PLESK=0; command -v plesk >/dev/null 2>&1 && HAS_PLESK=1
OS_NAME=$( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")
PLESK_VER="none"
[ $HAS_PLESK -eq 1 ] && PLESK_VER=$(plesk version 2>/dev/null | awk -F': *' '/[Pp]roduct version/{print $2; exit}')
[ -z "$PLESK_VER" ] && PLESK_VER="unknown"

echo "== $(hostname)   $OS_NAME   $(date -u '+%F %H:%M UTC')   fix-date cutoff: $CUTOFF"
echo "== Plesk: $PLESK_VER"

echo
echo "== Plesk website PHP"
for dir in /opt/plesk/php/*/; do
  [ -d "$dir" ] && check_binary "plesk-php $(basename "$dir")" "${dir}bin/php" "plesk$(basename "$dir")"
done

if [ -x /usr/local/psa/admin/bin/php ]; then
  echo
  echo "== Plesk panel PHP (sw-engine) - patched only by upgrading the Plesk release"
  check_binary "panel PHP" /usr/local/psa/admin/bin/php "panel" && PANEL="$LAST_VERDICT"
fi

if [ -x /usr/bin/php ]; then
  echo
  echo "== OS PHP (/usr/bin/php) - patched by the OS/vendor repo, not Plesk"
  check_binary "OS PHP" /usr/bin/php "os$(/usr/bin/php -v 2>/dev/null | head -1 | awk '{split($2,a,"."); print a[1]"."a[2]}')"
  OS_VER=$(/usr/bin/php -v 2>/dev/null | head -1 | awk '{print $2}')
fi

if ls -d /opt/alt/php*/ >/dev/null 2>&1; then
  echo
  echo "== CloudLinux alt-php - check the CloudLinux/TuxCare advisory too"
  for dir in /opt/alt/php*/; do
    [ -x "${dir}usr/bin/php" ] && check_binary "$(basename "$dir")" "${dir}usr/bin/php" "$(basename "$dir")"
  done
fi

# ---- Domain counts (Plesk only) ----
D_TOTAL="n/a"; D_UNSUP="n/a"; D_STOP="n/a"; D_SUP="n/a"; BREAKDOWN=""
if [ $HAS_PLESK -eq 1 ]; then
  D_TOTAL=0; D_UNSUP=0; D_STOP=0; D_SUP=0
  declare -A UNSUP_BY=()
  NAMES=""
  Q="SELECT d.name, h.php_handler_id FROM domains d JOIN hosting h ON h.dom_id=d.id"
  # Only domains with PHP switched on; fall back to all hosted domains if this Plesk schema lacks the column.
  if ! DOMAIN_ROWS=$(plesk db -Ne "$Q WHERE h.php='true' ORDER BY d.name" 2>/dev/null); then
    DOMAIN_ROWS=$(plesk db -Ne "$Q ORDER BY d.name" 2>/dev/null) || { DOMAIN_ROWS=""; D_TOTAL="error"; D_UNSUP="error"; D_STOP="error"; D_SUP="error"; FAILS=$((FAILS+1)); }
  fi
  while IFS=$'\t' read -r dom handler; do
    [ -z "$dom" ] && continue
    hv=""
    if [[ "$handler" =~ php([0-9])([0-9]+) ]]; then
      hv="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
    elif [[ "$handler" =~ ^(fpm|cgi|fastcgi|module)$ && -n "$OS_VER" ]]; then
      hv="${OS_VER%.*}"
    fi
    [ -z "$hv" ] && continue
    D_TOTAL=$((D_TOTAL+1))
    if is_eol "$hv" || [ -n "${BAD_VER[$hv]}" ]; then
      D_UNSUP=$((D_UNSUP+1)); UNSUP_BY[$hv]=$(( ${UNSUP_BY[$hv]:-0} + 1 ))
      [ $LIST_DOMAINS -eq 1 ] && NAMES+="  $dom  ($handler)"$'\n'
    elif is_stopgap "$hv"; then
      D_STOP=$((D_STOP+1))
    else
      D_SUP=$((D_SUP+1))
    fi
  done <<< "$DOMAIN_ROWS"
  for k in $(printf '%s\n' "${!UNSUP_BY[@]}" | sort -V); do BREAKDOWN="${BREAKDOWN:+$BREAKDOWN }PHP$k=${UNSUP_BY[$k]}"; done
  FAILS=$((FAILS+D_UNSUP))

  echo
  echo "== Domains by PHP status"
  printf '  %-36s %s\n' "Domains with PHP enabled" "$D_TOTAL"
  printf '  %-36s %s\n' "Unsupported (move now)" "${D_UNSUP}${BREAKDOWN:+   [$BREAKDOWN]}"
  printf '  %-36s %s\n' "Stop-gap 7.4/8.0/8.1 (plan to 8.2+)" "$D_STOP"
  printf '  %-36s %s\n' "Supported 8.2+" "$D_SUP"
  if [ $LIST_DOMAINS -eq 1 ] && [ -n "$NAMES" ]; then echo "  Unsupported domains:"; printf '%s' "$NAMES"; fi
fi

# ---- Stale processes ----
STALE_N=$(lsof -nP +L1 2>/dev/null | awk 'NR>1 && tolower($0) ~ /php|sw-engine/' | wc -l)
echo
echo "== Processes still running replaced PHP binaries: $STALE_N"
if [ "$STALE_N" -gt 0 ]; then
  echo "  -> systemctl restart 'plesk-php*-fpm' sw-engine ; reload httpd/apache2"
  FAILS=$((FAILS+1))
fi

echo
if [ "$FAILS" -eq 0 ]; then RESULT="OK"; echo "${GRN}RESULT: OK${NC}"
else RESULT="ACTION REQUIRED"; echo "${RED}RESULT: ACTION REQUIRED${NC} - $FAILS problem(s). Follow the SOP."; fi
echo "Note: checks build dates and versions, not exploitability. Confirm the fixed builds in the Plesk advisory."

if [ "$MODE" = "csv" ]; then
  csvq() { local s="${1//\"/\"\"}"; printf '"%s"' "$s"; }
  {
    csvq "$(hostname)"; printf ','; csvq "$OS_NAME"; printf ','; csvq "$PLESK_VER"; printf ','
    csvq "$(date -u '+%F %H:%M')"; printf ','; csvq "$CUTOFF"; printf ','
    printf '%s,%s,' "$BUILDS" "$BUILDS_BAD"; csvq "$BAD_LIST"; printf ','; csvq "$PANEL"; printf ','
    printf '%s,%s,%s,%s,' "$D_TOTAL" "$D_UNSUP" "$D_STOP" "$D_SUP"; csvq "$BREAKDOWN"; printf ','
    printf '%s,' "$STALE_N"; csvq "$RESULT"; printf '\n'
  } >&3
fi
exit "$FAILS"
