#!/usr/bin/env bash
# WADE - Wide-Area Data Extraction :: Idempotent Installer (soft-fail + interactive STIG)
# Author: Ian McConnell

### ---------- Prompt helpers ----------
prompt_with_default() {
  local q="$1"; local d="$2"; local ans
  read -r -p "$q [$d]: " ans
  ans="${ans:-$d}"
  printf "%s" "$ans"
}
yesno_with_default() {
  local q="$1"; local d="${2:-Y}"; local ans
  read -r -p "$q [${d}/$( [[ "$d" =~ ^[Yy]$ ]] && echo n || echo y )]: " ans
  ans="${ans:-$d}"
  [[ "$ans" =~ ^[Yy]$ ]]
}

set -Euo pipefail   # no -e (we soft-fail via step runner); still strict on unset + pipefail

# ---- Debug + transcript logging ----
WADE_DEBUG="${WADE_DEBUG:-0}"

LOG_DIR="/var/log/wade"
mkdir -p "$LOG_DIR"

# use UTC for easy cross-host correlation; change to +%Y%m%d_%H%M%S if you prefer local
LOG_FILE="$LOG_DIR/install_$(date -u +%F_%H%M%S).log"
export LOG_FILE

# tee everything (children inherit our stdout); keep Python unbuffered
export PYTHONUNBUFFERED=1
exec > >(tee -a "$LOG_FILE") 2>&1

# Optional: send xtrace to the log file only (keeps console cleaner)
if [[ "$WADE_DEBUG" = "1" ]]; then
  exec {__XFD}>>"$LOG_FILE"
  export BASH_XTRACEFD=${__XFD}
  export PS4='+ ${BASH_SOURCE##*/}:${LINENO}:${FUNCNAME[0]:-main}: '
  set -x
fi

# Pretty error frames without killing soft-fail flow
trap 'rc=$?; line=${BASH_LINENO[0]:-$LINENO}; cmd=${BASH_COMMAND}
echo "[ERR] ${BASH_SOURCE##*/}:${line} rc=${rc}  cmd: ${cmd}" >&2' ERR

#####################################
# Banner
#####################################
cat <<'WADE_BANNER'
[__      __  _____  ________  ___________                                                          
/  \    /  \/  _  \ \______ \ \_   _____/                                                          
\   \/\/   /  /_\  \ |    |  \ |    __)_                                                           
 \        /    |    \|    `   \|        \                                                          
  \__/\  /\____|__  /_______  /_______  /                                                          
       \/         \/        \/        \/                                                           
 __      __.__    .___                  _____                                                      
/  \    /  \__| __| _/____             /  _  \_______   ____ _____                                 
\   \/\/   /  |/ __ |/ __ \   ______  /  /_\  \_  __ \_/ __ \\__  \                                 
 \        /|  / /_/ \  ___/  /_____/ /    |    \  | \/\  ___/ / __ \_                              
  \__/\  / |__\____ |\___  >         \____|__  /__|    \___  >____  /                              
       \/          \/    \/                  \/            \/     \/                               
________          __           ___________         __                        __  .__                
\______ \ _____ _/  |______    \_   _____/__  ____/  |_____________    _____/  |_|__| ____   ____  
 |    |  \\__  \\   __\__  \    |    __)_\  \/  /\   __\_  __ \__  \ _/ ___\   __\  |/  _ \ /    \ 
 |    `   \/ __ \|  |  / __ \_  |        \>    <  |  |  |  | \// __ \\  \___|  | |  (  <_> )   |  \
/_______  (____  /__| (____  / /_______  /__/\_ \ |__|  |__|  (____  /\___  >__| |__|\____/|___|  /
        \/     \/          \/          \/      \/                  \/     \/                    \/ ]
WADE_BANNER

#####################################
# Script location & STIG source dir
#####################################
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" >/dev/null 2>&1 && pwd -P)"
STIG_SRC_DIR="${SCRIPT_DIR}/stigs"
SPLUNK_SRC_DIR="${SCRIPT_DIR}"
LOAD_PATCH_DIR="${SCRIPT_DIR}"

#####################################
# CLI flags & basic env
#####################################
NONINTERACTIVE=0
CHECK_ONLY=0
FORCE_ALL=0
ONLY_LIST=""

for arg in "$@"; do
  case "$arg" in
    -y|--yes|--noninteractive) NONINTERACTIVE=1 ;;
    --check) CHECK_ONLY=1 ;;
    --force) FORCE_ALL=1 ;;
    --only=*) ONLY_LIST="${arg#--only=}" ;;
  esac
done

NONINTERACTIVE="${WADE_NONINTERACTIVE:-${NONINTERACTIVE:-0}}"
OFFLINE="${OFFLINE:-0}"

#####################################
# Helpers
#####################################
require_root() { if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "[-] Run as root (sudo)."; exit 1; fi; }
confirm() { [[ "$NONINTERACTIVE" -eq 1 ]] && return 0; read -r -p "${1:-Proceed?} [y/N]: " a; [[ "$a" =~ ^[Yy]$ ]]; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }
validate_cidr() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$ ]]; }
die(){ echo "[-] $*"; exit 1; }
sha256_of(){ sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

# Soft-fail aggregation
FAILS=()
WARNS=()
fail_note(){ local mod="$1"; shift; local msg="${*:-failed}"; echo "[-] [$mod] $msg"; FAILS+=("$mod — $msg"); }
warn_note(){ local mod="$1"; shift; local msg="${*:-warning}"; echo "[!] [$mod] $msg"; WARNS+=("$mod — $msg"); }
finish_summary(){
  echo
  echo "================ WADE INSTALL SUMMARY ================"
  if ((${#FAILS[@]})); then echo "Failed components:"; printf ' - %s\n' "${FAILS[@]}"; else echo "No component failures recorded."; fi
  if ((${#WARNS[@]})); then echo; echo "Warnings:"; printf ' - %s\n' "${WARNS[@]}"; fi
  echo "======================================================"
  ((${#FAILS[@]}==0)) || exit 2
}

find_offline_src(){
  for d in /media/*/wade-offline /run/media/*/wade-offline /mnt/wade-offline /wade-offline; do
    [[ -d "$d" ]] && { echo "$d"; return 0; }
  done
  local dev; dev=$(lsblk -o NAME,LABEL,MOUNTPOINT -nr | awk '/wade-offline/ {print "/dev/"$1; exit}')
  if [[ -n "$dev" ]]; then local mnt="/mnt/wade-repo"; mkdir -p "$mnt"; mount "$dev" "$mnt" && { echo "$mnt"; return 0; }; fi
  return 1
}

# --- APT lock helper (Ubuntu/Debian) ---
apt_wait() {
  [[ "$PM" != "apt" ]] && return 0
  local tries=60
  local locks=(/var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock)
  echo "[apt] checking for package manager locks…"
  if command -v fuser >/dev/null 2>&1; then
    while fuser "${locks[@]}" >/dev/null 2>&1; do
      ((tries--)) || { echo "[apt] lock held too long; bailing"; return 1; }
      echo "[apt] lock held by another process; retrying in 5s… ($((60-tries))/60)"; sleep 5
    done
  elif command -v lsof >/dev/null 2>&1; then
    while lsof -t "${locks[@]}" >/dev/null 2>&1; do
      ((tries--)) || { echo "[apt] lock held too long; bailing"; return 1; }
      echo "[apt] lock held by another process (lsof); retrying in 5s… ($((60-tries))/60)"; sleep 5
    done
  else
    echo "[apt] no fuser/lsof; skipping wait"
  fi
  dpkg --configure -a >/dev/null 2>&1 || true
}

# Run apt/dnf/yum refresh exactly once
APT_REFRESHED=0
apt_refresh_once() {
  (( APT_REFRESHED )) && return 0
  if [[ -n "$PKG_UPDATE" ]]; then
    [[ "$PM" == "apt" ]] && apt_wait
    bash -lc "$PKG_UPDATE" || true
  fi
  APT_REFRESHED=1
}

# ---- pipx helpers ----
ensure_pipx_installed() {
  export PIPX_HOME=/opt/pipx
  export PIPX_BIN_DIR=/usr/local/bin
  mkdir -p "$PIPX_HOME" "$PIPX_BIN_DIR"
  if ! command -v pipx >/dev/null 2>&1; then
    if [[ "$PM" == "apt" ]]; then
      apt_refresh_once
      bash -lc "$PKG_INSTALL pipx" || true
    else
      python3 -m pip install --upgrade pip || true
      python3 -m pip install pipx || true
    fi
  fi
}

# ensure_pipx_pkg <package> [install-args...]
ensure_pipx_pkg() {
  local name="$1"; shift || true
  ensure_pipx_installed
  if pipx list 2>/dev/null | grep -qE "package ${name} "; then
    pipx upgrade "$name" || true
  else
    pipx install "$name" "$@" || pipx upgrade "$name" || true
  fi
}

# Queue systemd reload/enable once at end
_SYSTEMD_UNITS=()
systemd_queue_enable() { _SYSTEMD_UNITS+=("$1"); }
systemd_finalize_enable() {
  ((${#_SYSTEMD_UNITS[@]}==0)) && return 0
  systemctl daemon-reload || true
  for u in "${_SYSTEMD_UNITS[@]}"; do
    systemctl enable --now "$u" 2>/dev/null || true
  done
}

solr_wait_ready() {
  local url="http://127.0.0.1:8983/solr/admin/info/system?wt=json"
  local tries=40
  while (( tries-- )); do
    if curl -fsS "$url" >/dev/null; then
      return 0
    fi
    sleep 2
  done
  return 1
}

wade_oscap_eval() {
  # Pass everything through to oscap
  oscap "$@"; local rc=$?
  if [[ $rc -eq 2 ]]; then
    echo "[i] OpenSCAP eval completed with rule failures (expected on an un-hardened host)." >&2
    return 0
  fi
  return $rc
}

#####################################
# NEW: Package bundle aggregator (single install)
#####################################
APT_BUNDLE=()
RPM_BUNDLE=()
pkg_add() {
  # usage: pkg_add <apt_pkg> [<rpm_pkg>]
  if [[ "$PM" == "apt" ]]; then
    APT_BUNDLE+=("$1")
  else
    # if rpm alias not given, reuse $1
    RPM_BUNDLE+=("${2:-$1}")
  fi
}

pkg_install_bundle_once() {
  (( ${#APT_BUNDLE[@]} + ${#RPM_BUNDLE[@]} == 0 )) && return 0
  if [[ "$PM" == "apt" ]]; then
    apt_refresh_once
    mapfile -t APT_BUNDLE < <(printf '%s\n' "${APT_BUNDLE[@]}" | awk '!seen[$0]++')
    [[ ${#APT_BUNDLE[@]} -gt 0 ]] && bash -lc "$PKG_INSTALL ${APT_BUNDLE[*]}"
  else
    mapfile -t RPM_BUNDLE < <(printf '%s\n' "${RPM_BUNDLE[@]}" | awk '!seen[$0]++')
    [[ ${#RPM_BUNDLE[@]} -gt 0 ]] && bash -lc "$PKG_INSTALL ${RPM_BUNDLE[*]}"
  fi
}

pip_cached_install() {
  # usage: pip_cached_install <venv_bin_dir> <reqs_or_pkgs...>
  local vbin="$1"; shift || true
  local wheelhouse="${WADE_PKG_DIR:-/var/wade/pkg}/pipwheels"
  mkdir -p "$wheelhouse"

  # Always prime build tools into the wheelhouse (so PEP 517 can find them offline)
  "$vbin/pip" download -d "$wheelhouse" pip setuptools wheel >/dev/null 2>&1 || true

  # Pre-download requested pkgs (best-effort; sdists are fine)
  "$vbin/pip" download -d "$wheelhouse" "$@" >/dev/null 2>&1 || true

  # Prefer offline + NO build isolation (lets venv's setuptools satisfy sdists like intervaltree)
  "$vbin/pip" install --no-index --find-links "$wheelhouse" --no-build-isolation "$@" \
    || "$vbin/pip" install "$@"
}

#####################################
# Idempotency framework (step registry)
#####################################
WADE_VAR_DEFAULT="/var/wade"
STEPS_DIR="${WADE_VAR_DEFAULT}/state/steps"; mkdir -p "$STEPS_DIR"

_inlist(){ local item="$1" list_csv="$2"; [[ -z "$list_csv" ]] && return 0; IFS=',' read -ra arr <<< "$list_csv"; for x in "${arr[@]}"; do [[ "$item" == "$x" ]] && return 0; done; return 1; }
mark_done(){ local step="$1" ver="$2"; shift 2 || true; printf '%s\n' "$ver" > "${STEPS_DIR}/${step}.ver"; [[ $# -gt 0 ]] && printf '%s\n' "$*" > "${STEPS_DIR}/${step}.note"; }
report_step(){ printf " - %-16s want=%-12s have=%-14s [%s]\n" "$1" "${2:-n/a}" "${3:-n/a}" "$4"; }

get_mark_ver(){
  local step="$1"
  if [[ -f "${STEPS_DIR}/${step}.ver" ]]; then
    cat "${STEPS_DIR}/${step}.ver"
  else
    echo ""
  fi
}

# Caches/symbols for vol3 & friends
CACHEDIR="${CACHEDIR:-/var/wade/cache}"
mkdir -p "${CACHEDIR}"

run_step(){
  local name="$1" want="$2" get_have="$3" do_install="$4"
  _inlist "$name" "$ONLY_LIST" || { report_step "$name" "$want" "$($get_have 2>/dev/null || true)" "SKIP(--only)"; return 0; }
  local have; have="$($get_have 2>/dev/null || true)"
  if (( CHECK_ONLY )); then
    if [[ -z "$have" ]]; then report_step "$name" "$want" "<none>" "NEED"
    elif [[ -n "$want" && "$want" != "$have" ]]; then report_step "$name" "$want" "$have" "NEED"
    else report_step "$name" "$want" "$have" "OK"; fi
    return 0
  fi
  if (( ! FORCE_ALL )) && [[ -n "$have" && ( -z "$want" || "$want" == "$have" ) ]]; then
    report_step "$name" "$want" "$have" "OK"; return 0
  fi
  echo "[*] Installing/updating ${name} (want=${want:-n/a}, have=${have:-none})…"
  if ( set -Eeo pipefail; eval "$do_install" ); then
    have="$($get_have 2>/dev/null || true)"
    mark_done "$name" "${have:-unknown}"
    report_step "$name" "$want" "$have" "OK"
    return 0
  else
    report_step "$name" "$want" "$have" "FAIL"
    return 1
  fi
}

#####################################
# Version detectors (best-effort)
#####################################
get_ver_be(){ /usr/local/bin/bulk_extractor -V 2>&1 | grep -Eo '[0-9]+(\.[0-9]+)*' | head -1 || true; }
get_ver_hayabusa(){
  local bin="${HAYABUSA_DEST:-/usr/local/bin/hayabusa}"
  [[ -x "$bin" ]] || { echo ""; return; }
  if v="$("$bin" --version 2>/dev/null | sed -nE 's/.*v?([0-9]+(\.[0-9]+)+).*/\1/p' | head -1)"; then
    [[ -n "$v" ]] && { echo "$v"; return; }
  fi
  echo installed
}
get_ver_solr(){ /opt/solr/bin/solr -version 2>/dev/null | awk '{print $2}' || true; }
get_ver_zk(){ [[ -x /opt/zookeeper/bin/zkServer.sh ]] && ls /opt/zookeeper/lib/* 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo ""; }
get_ver_amq(){ /opt/activemq/bin/activemq --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9.]+' | head -1 || true; }
get_ver_pg(){ psql -V 2>/dev/null | awk '{print $3}' || true; }
get_ver_pipx_vol3(){ pipx list 2>/dev/null | awk '/package volatility3 /{print $3}' | tr -d '()' || true; }
get_ver_pipx_dissect(){ pipx list 2>/dev/null | awk '/package dissect /{print $3}' | tr -d '()' || true; }
get_ver_stig(){ [[ -f "${STIG_UBU_EXTRACT_DIR:-/var/wade/stigs/ubuntu2404}/ds.xml" ]] && sha256_of "${STIG_UBU_EXTRACT_DIR}/ds.xml" || echo ""; }
get_ver_qtgl(){ dpkg -s libegl1 >/dev/null 2>&1 && echo present || echo ""; }  # apt branch only
get_ver_splunkuf(){
  [[ -x /opt/splunkforwarder/bin/splunk ]] || { echo ""; return; }
  local outconf="/opt/splunkforwarder/etc/system/local/outputs.conf"
  if [[ -f "$outconf" ]] && grep -q '^\s*server\s*=' "$outconf"; then
    echo installed
  else
    echo ""
  fi
}
get_ver_uf(){
  [[ -x /opt/splunkforwarder/bin/splunk ]] || { echo ""; return; }
  /opt/splunkforwarder/bin/splunk version 2>/dev/null \
    | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+/) {print $i; exit}}'
}
get_ver_capa(){ /usr/local/bin/capa --version 2>/dev/null | sed -nE "s/.* ([0-9]+(\.[0-9]+)+).*/\1/p" | head -1 || echo ""; }
get_ver_capa_rules(){
  local dir="${WADE_CAPA_RULES_DIR:-/opt/capa-rules}"
  if [[ -d "$dir/.git" ]]; then
    git -C "$dir" rev-parse --short HEAD 2>/dev/null || echo ""
  elif [[ -d "$dir" ]]; then
    local rules_count
    rules_count="$(find "$dir" -type f -name '*.yml' 2>/dev/null | wc -l | tr -d ' ')"
    [[ "${rules_count:-0}" =~ ^[0-9]+$ ]] && echo "files-${rules_count}" || echo ""
  else
    echo ""
  fi
}

# == WADE Staging Daemon (detector)
get_ver_wade_stage(){
  local svc="/etc/systemd/system/wade-staging.service"
  local bin="/opt/wade/stage_daemon.py"
  systemctl is-enabled --quiet wade-staging.service >/dev/null 2>&1 || { echo ""; return; }
  [[ -f "$bin" ]] || { echo ""; return; }
  sha256sum "$bin" 2>/dev/null | awk '{print $1}'
}

get_ver_wade_mwex(){
  local bin="/opt/wade/wade_mw_extract.py"
  [[ -f "$bin" ]] || { echo ""; return; }
  sha256sum "$bin" 2>/dev/null | awk '{print $1}'
}

# === Staging & Malware Extractor source (from repo) ===
STAGE_SRC="${SCRIPT_DIR}/staging/stage_daemon.py"
STAGE_EXPECT_SHA="$(sha256_of "$STAGE_SRC" 2>/dev/null || true)"

MWEX_SRC="${SCRIPT_DIR}/malware/wade_mw_extract.py"
MWEX_EXPECT_SHA="$(sha256_of "$MWEX_SRC" 2>/dev/null || true)"

#####################################
# WADE Doctor (services, shares, Splunk UF)
#####################################
wade_doctor() {
  echo "=== WADE Doctor ==="
  if systemctl is-active --quiet smbd || systemctl is-active --quiet smb; then
    echo "[*] Samba: active"
      if testparm -s 2>/dev/null | grep -qiE '^\s*map to guest\s*=\s*never'; then
       echo "[+] Samba auth: map to guest = Never"
      else
       echo "[!] Samba auth: map to guest is not 'Never' (Windows may try Guest)"
      fi
       echo "[*] Samba users present:"; pdbedit -L 2>/dev/null | awk -F: '{print "   - "$1}' || echo "   (none)"
  else
    echo "[!] Samba: inactive"
  fi
  PATH_LINE=""
  SMB_CONF="/etc/samba/smb.conf"
  for SHARE in DataSources Cases Staging; do
    if testparm -s 2>/dev/null | grep -q "^\[$SHARE\]"; then
      PATH_LINE="$(awk '/^\['"$SHARE"'\]/{f=1;next} /^\[/{f=0} f && /path[[:space:]]*=/{print; exit}' "$SMB_CONF" 2>/dev/null | sed -E 's/^[[:space:]]*path[[:space:]]*=\s*//')"
      if [[ -n "$PATH_LINE" && -d "$PATH_LINE" ]]; then
        echo "[+] Share [$SHARE] mapped to $PATH_LINE"
      else
        echo "[!] Share [$SHARE] defined, but path missing or not a directory"
      fi
    else
      echo "[!] Share [$SHARE] not found in smb.conf (testparm)"
    fi
  done
  if [[ -x /opt/splunkforwarder/bin/splunk ]]; then
    echo "[*] Splunk UF present: version $(/opt/splunkforwarder/bin/splunk version 2>/dev/null | awk '{print $NF}')"
    OUTCONF="/opt/splunkforwarder/etc/system/local/outputs.conf"
    if [[ -f "$OUTCONF" ]]; then
      SERVER_LINE="$(awk -F= '/^\s*server\s*=/ {gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2; exit}' "$OUTCONF" 2>/dev/null)"
      if [[ -n "$SERVER_LINE" ]]; then
        echo "[+] UF forwarding to: $SERVER_LINE"
      else
        echo "[!] UF outputs.conf found but no 'server=' set"
      fi
    else
      echo "[!] UF outputs.conf missing at $OUTCONF"
    fi
    /opt/splunkforwarder/bin/splunk status 2>/dev/null | sed -n '1,8p' || true
  else
    echo "[!] Splunk UF not installed"
  fi
  echo "[*] Listening ports (smbd 139/445, solr 8983, postgres 5432):"
  ss -plnt | awk 'NR==1 || /:(139|445|8983|5432)\b/'
  echo "===================="
}

#####################################
# Preflight specs
#####################################
require_root
CPU_MIN=4; RAM_MIN_GB=16; DISK_MIN_GB=200
CPU_CORES=$(nproc || echo 1)
MEM_GB=$(( ( $(awk '/MemTotal/{print $2}' /proc/meminfo) + 1048575 ) / 1048576 ))
if (( MEM_GB < 32 )); then
  SOLR_JAVA_MEM='-Xms2g -Xmx4g'
fi
ROOT_AVAIL_GB=$(( ( $(df --output=avail / | tail -1) + 1048575 ) / 1048576 ))
echo "[*] Cores:${CPU_CORES} RAM:${MEM_GB}GB Free/:${ROOT_AVAIL_GB}GB"
WARN=false
(( CPU_CORES < CPU_MIN )) && echo "  WARN: < ${CPU_MIN} cores" && WARN=true
(( MEM_GB   < RAM_MIN_GB )) && echo "  WARN: < ${RAM_MIN_GB} GB RAM" && WARN=true
(( ROOT_AVAIL_GB < DISK_MIN_GB )) && echo "  WARN: < ${DISK_MIN_GB} GB free" && WARN=true
$WARN && ! confirm "Under recommended specs. Continue anyway?" && exit 1

#####################################
# OS detection
#####################################
. /etc/os-release
OS_ID="${ID:-}"; OS_LIKE="${ID_LIKE:-}"; OS_VER_ID="${VERSION_ID:-}"
PRETTY="${PRETTY_NAME:-$OS_ID $OS_VER_ID}"
echo "[*] Detected OS: ${PRETTY}"

PKG_INSTALL=""; PKG_UPDATE=""; PKG_REFRESH=""; FIREWALL=""; PM=""

#####################################
# OFFLINE repo setup & pkg managers
#####################################
OFFLINE_SRC=""
if [[ "$OFFLINE" == "1" ]]; then
  echo "[*] OFFLINE mode enabled…"
  OFFLINE_SRC="$(find_offline_src)" || die "Could not find 'wade-offline' media."
  echo "[+] Offline repo root: $OFFLINE_SRC"
fi

if [[ "$OFFLINE" == "1" ]]; then
  case "$OS_ID:$OS_LIKE" in
    ubuntu:*|*:"debian"*)
      echo "deb [trusted=yes] file:${OFFLINE_SRC}/ubuntu noble main" > /etc/apt/sources.list.d/wade-offline.list
      APT_FLAGS='-o Dir::Etc::sourcelist="sources.list.d/wade-offline.list" -o Dir::Etc::sourceparts="-" -o APT::Get::List-Cleanup="0"'
      PKG_UPDATE="apt-get update ${APT_FLAGS}"
      PKG_INSTALL="apt-get install -y --no-install-recommends ${APT_FLAGS}"
      PKG_REFRESH="$PKG_INSTALL"; FIREWALL="ufw"; PM="apt"
      ;;
    ol:*|*:"rhel"*|*:"fedora"*)
      cat >/etc/yum.repos.d/wade-offline.repo <<EOF
[WadeOffline]
name=Wade Offline
baseurl=file://${OFFLINE_SRC}/oracle10
enabled=1
gpgcheck=0
EOF
      if have_cmd dnf; then
        PKG_UPDATE="dnf -y --disablerepo='*' --enablerepo='WadeOffline' makecache"
        PKG_INSTALL="dnf -y --disablerepo='*' --enablerepo='WadeOffline' install"
        PKG_REFRESH="$PKG_INSTALL"; PM="dnf"
      else
        PKG_UPDATE="yum -y --disablerepo='*' --enablerepo='WadeOffline' makecache"
        PKG_INSTALL="yum -y --disablerepo='*' --enablerepo='WadeOffline' install"
        PKG_REFRESH="$PKG_INSTALL"; PM="yum"
      fi
      FIREWALL="firewalld"
      ;;
    *) die "Offline: unsupported distro ${OS_ID}/${OS_LIKE}." ;;
  esac
else
  case "$OS_ID:$OS_LIKE" in
    ubuntu:*|*:"debian"*)
      PKG_UPDATE="apt-get update -y"
      PKG_INSTALL="apt-get install -y --no-install-recommends"
      PKG_REFRESH="$PKG_INSTALL"; FIREWALL="ufw"; PM="apt"
      ;;
    ol:*|*:"rhel"*|*:"fedora"*)
      if have_cmd dnf; then
        PKG_UPDATE="dnf -y makecache"
        PKG_INSTALL="dnf -y install"
        PKG_REFRESH="$PKG_INSTALL"; PM="dnf"
      else
        PKG_UPDATE="yum -y makecache"
        PKG_INSTALL="yum -y install"
        PKG_REFRESH="$PKG_INSTALL"; PM="yum"
      fi
      FIREWALL="firewalld"
      ;;
    *) die "Unsupported distro (ID=${OS_ID}, LIKE=${OS_LIKE})." ;;
  esac
fi

# Minimal bootstrap: enable EPEL on RPM if online (package bundle below handles the rest)
bootstrap_fresh_install(){
  if [[ "$PM" != "apt" && "$OFFLINE" != "1" ]]; then
    bash -lc "$PKG_INSTALL oracle-epel-release-el10" || bash -lc "$PKG_INSTALL oracle-epel-release-el9" || bash -lc "$PKG_INSTALL epel-release" || true
  fi
}
export PM PKG_INSTALL PKG_UPDATE PKG_REFRESH FIREWALL
export NONINTERACTIVE OFFLINE LWADEUSER SMB_USERS_CSV ALLOW_NETS_CSV

bootstrap_fresh_install

#####################################
# WADE scaffolding & default config
#####################################
WADE_ETC="/etc/wade"
WADE_VAR="/var/wade"
mkdir -p "${WADE_ETC}/"{conf.d,modules,json_injection.d} \
         "${WADE_VAR}/"{logs,state,tmp,pkg,tools.d,pipelines.d}

# Seed default wade.conf if missing
if [[ ! -f "${WADE_ETC}/wade.conf" ]]; then
  cat >"${WADE_ETC}/wade.conf"<<'CONF'
### /etc/wade/wade.conf (defaults) ##############################
WADE_HOSTNAME=""
WADE_OWNER_USER="autopsy"
WADE_SMB_USERS="autopsy,KAPE"
WADE_ALLOW_NETS=""                       # "10.0.0.0/24,10.0.1.0/24"

WADE_BASE_VAR="/var/wade"
WADE_BASE_ETC="/etc/wade"
WADE_LOG_DIR="${WADE_BASE_VAR}/logs"
WADE_PKG_DIR="${WADE_BASE_VAR}/pkg"
WADE_TOOLS_DIR="${WADE_BASE_VAR}/tools.d"
WADE_PIPELINES_DIR="${WADE_BASE_VAR}/pipelines.d"

WADE_DATADIR="DataSources"
WADE_CASESDIR="Cases"
WADE_STAGINGDIR="Staging"

WADE_OFFLINE="${OFFLINE:-0}"
WADE_STRICT_FIREWALL="0"

# Pinned versions
ZOOKEEPER_VER="3.5.7"
SOLR_VER="8.6.3"
ACTIVEMQ_VER="5.14.0"

# Java (headless recommended)
JAVA_PACKAGE_APT="default-jre-headless"
JAVA_PACKAGE_RPM="java-11-openjdk-headless"
SOLR_HEAP=""
# Leave SOLR_HEAP blank so Solr uses SOLR_JAVA_MEM below (Xms 24G, Xmx 48G).
SOLR_JAVA_MEM='-Xms24G -Xmx48G'
SOLR_ZK_HOST="127.0.0.1"

# PostgreSQL lab settings (unsafe for prod)
PG_LISTEN_ADDR="0.0.0.0"
PG_PERF_FSYNC="off"
PG_PERF_SYNCCOMMIT="off"
PG_PERF_FULLPAGE="off"
PG_CREATE_AUTOPSY_USER="1"

# ===== Splunk (UF + ports) =====
SPLUNK_DEFAULT_INDEX="wade_custom"

# Universal Forwarder defaults (used by the installer prompts & env)
SPLUNK_UF_RCVR_HOSTS="splunk.example.org:9997"
SPLUNK_UF_DEFAULT_INDEX="wade_custom"
SPLUNK_UF_COMPRESSED="true"
SPLUNK_UF_USE_ACK="true"
SPLUNK_UF_SSL_VERIFY="false"
SPLUNK_UF_SSL_COMMON_NAME="*"
SPLUNK_UF_DEPLOYMENT_SERVER=""

# Ports (for summary/UI hints)
SPLUNK_WEB_PORT="8000"
SPLUNK_MGMT_PORT="8089"
SPLUNK_HEC_PORT="8088"
SPLUNK_FORWARD_PORT="9997"

# Module toggles
MOD_VOL_SYMBOLS_ENABLED="1"
MOD_BULK_EXTRACTOR_ENABLED="1"
MOD_PIRANHA_ENABLED="1"
MOD_BARRACUDA_ENABLED="1"
MOD_HAYABUSA_ENABLED="1"

# Volatility3 runtime dirs
VOL3_BASE_DIR="/var/wade/vol3"
VOL3_SYMBOLS_DIR="${VOL3_BASE_DIR}/symbols"
VOL3_CACHE_DIR="${VOL3_BASE_DIR}/cache"
VOL3_PLUGIN_DIR="${VOL3_BASE_DIR}/plugins"

# Sigma disabled in this build
SIGMA_ENABLED="0"
SIGMA_AUTOUPDATE="0"

# Hayabusa locations
HAYABUSA_ARCH_AUTO="1"
HAYABUSA_ARCH_OVERRIDE=""
HAYABUSA_DEST="/usr/local/bin/hayabusa"
HAYABUSA_RULES_DIR="/etc/wade/hayabusa/rules"
SIGMA_RULES_DIR="/etc/wade/sigma"

# ---- Mandiant capa (engine + rules) ----
CAPA_VERSION=""                         # blank = latest from PyPI
WADE_CAPA_VENV="/opt/wade/venvs/capa"   # dedicated venv for capa
WADE_CAPA_RULES_DIR="/opt/capa-rules"   # where rules live
WADE_CAPA_RULES_COMMIT=""               # optionally pin: commit SHA or tag

# ---- WHIFF (analyst assistant / KB) ----
WHIFF_ENABLE="1"                       # 1=offer install by default; will be prompted
WHIFF_BIND_ADDR="127.0.0.1"
WHIFF_PORT="8088"
# Backend choices you support in install_whiff.sh: ollama | openai | http
WHIFF_BACKEND="ollama"
# Default to Meta Llama (avoids Qwen, per your constraint)
WHIFF_MODEL="llama3.1:8b-instruct"
# For backends that need it (e.g., http/vLLM or hosted endpoints)
WHIFF_ENDPOINT=""
# API keys/creds should NOT be persisted by default; leave empty.
WHIFF_API_KEY=""

# ---- STIG (assessment only; interactive at end) ----
MOD_STIG_EVAL_ENABLED="1"         # keep prereqs enabled; eval runs interactively at end
MOD_STIG_REMEDIATE_ENABLED="0"    # do NOT apply fixes

# Reports
STIG_REPORT_DIR="/var/wade/logs/stig"

# Storage
STIG_STORE_DIR="/var/wade/stigs"
STIG_UBU_EXTRACT_DIR="${STIG_STORE_DIR}/ubuntu2404"
STIG_PROFILE_ID="xccdf_mil.disa.stig_profile_MAC-1_Classified"
STIG_SKIP_RULES=""

# ---- bulk_extractor installation mode ----
# "source" (build from GitHub) or "repo" (use distro package if available)
BULK_EXTRACTOR_MODE="source"
CONF
  chmod 0644 "${WADE_ETC}/wade.conf"
fi

# Seed universal jq injector
if [[ ! -f "${WADE_ETC}/json_injection.d/00-universal.jq" ]]; then
  cat >"${WADE_ETC}/json_injection.d/00-universal.jq"<<'JQ'
# Add WADE metadata to each JSON object
. as $o
| $o
| .wade |= ( .wade // {} )
| .wade.hostname = (env.WADE_HOSTNAME // env.HOSTNAME)
| .wade.module = (env.MODULE // null)
| .wade.pipeline = (env.PIPELINE // null)
| .wade.image_path = (env.IMAGE_PATH // null)
| .wade.case_id = (env.CASE_ID // null)
| .wade.location = (env.LOCATION // null)
JQ
  chmod 0644 "${WADE_ETC}/json_injection.d/00-universal.jq"
fi

# Load config stack
source "${WADE_ETC}/wade.conf"
for f in "${WADE_ETC}/conf.d/"*.conf; do [[ -f "$f" ]] && source "$f"; done
for f in "${WADE_ETC}/modules/"*.conf; do [[ -f "$f" ]] && source "$f"; done
OFFLINE="${OFFLINE:-${WADE_OFFLINE:-0}}"

# ---- Safe defaults so set -u never trips on older configs
: "${WADE_PKG_DIR:=/var/wade/pkg}"
: "${SOLR_HEAP:=}"                      # empty means "leave Jetty heap default"
: "${SOLR_JAVA_MEM:=-Xms24G -Xmx48G}"   # you override below for low-RAM hosts
: "${PG_PERF_FSYNC:=off}"
: "${PG_PERF_SYNCCOMMIT:=off}"
: "${PG_PERF_FULLPAGE:=off}"
: "${HAYABUSA_DEST:=/usr/local/bin/hayabusa}"
: "${HAYABUSA_RULES_DIR:=/etc/wade/hayabusa/rules}"
: "${SIGMA_RULES_DIR:=/etc/wade/sigma}"
: "${WADE_CAPA_VENV:=/opt/wade/venvs/capa}"
: "${WADE_CAPA_RULES_DIR:=/opt/capa-rules}"

if (( MEM_GB < 32 )); then
  SOLR_JAVA_MEM='-Xms2g -Xmx4g'
fi

#####################################
# NEW: Build the package bundle & install once
#####################################
# Core
pkg_add samba
pkg_add samba-common-bin samba-common-tools
pkg_add cifs-utils
pkg_add jq
pkg_add inotify-tools
pkg_add plocate
pkg_add zip
pkg_add unzip
pkg_add p7zip-full 'p7zip p7zip-plugins'
# Python/venv/pip
pkg_add python3-venv 'python3-virtualenv'
pkg_add python3-pip 'python3-pip'
# Java (for Solr)
pkg_add "${JAVA_PACKAGE_APT:-default-jre-headless}" "${JAVA_PACKAGE_RPM:-java-11-openjdk-headless}"
# Firewalls
if [[ "$PM" == "apt" ]]; then pkg_add ufw; else pkg_add firewalld; fi
# Qt/X11 libs only if Piranha/Barracuda toggles are on (apt only)
if [[ "$PM" == "apt" && ( "${MOD_PIRANHA_ENABLED:-1}" == "1" || "${MOD_BARRACUDA_ENABLED:-1}" == "1" ) ]]; then
  pkg_add libegl1
  pkg_add libopengl0
  pkg_add libgl1
  pkg_add libxkbcommon-x11-0
  pkg_add libxcb-icccm4
  pkg_add libxcb-image0
  pkg_add libxcb-keysyms1
  pkg_add libxcb-randr0
  pkg_add libxcb-render-util0
  pkg_add libxcb-shape0
  pkg_add libxcb-xfixes0
  pkg_add libxcb-xinerama0
  pkg_add libxcb-xkb1
  pkg_add libxcb-cursor0
  pkg_add fonts-dejavu-core
fi
# X11 fwd bits if using GUI tools
if [[ "${MOD_PIRANHA_ENABLED:-1}" == "1" || "${MOD_BARRACUDA_ENABLED:-1}" == "1" ]]; then
  if [[ "$PM" == "apt" ]]; then
    pkg_add xauth
    pkg_add x11-apps
  else
    pkg_add xorg-x11-xauth
  fi
fi
# STIG prereqs gated
if [[ "${MOD_STIG_EVAL_ENABLED:-0}" == "1" ]]; then
  if [[ "$PM" == "apt" ]]; then
    pkg_add openscap-scanner
    pkg_add ssg-base
    pkg_add ssg-debderived
    pkg_add ssg-debian
    pkg_add ssg-nondebian
    pkg_add ssg-applications
    # scap-security-guide may or may not exist on Ubuntu; leave to best-effort in the step
  else
    pkg_add openscap-scanner
    pkg_add scap-security-guide
  fi
fi
# Postgres (Ubuntu)
if [[ "$PM" == "apt" ]]; then
  pkg_add postgresql
fi

# Do the single consolidated install
pkg_install_bundle_once

#####################################
# Prompts (noninteractive honors defaults)
#####################################
DEFAULT_HOSTNAME="${WADE_HOSTNAME:-$(hostname)}"
DEFAULT_OWNER="${WADE_OWNER_USER:-autopsy}"
DEFAULT_SMB_USERS="${WADE_SMB_USERS:-${DEFAULT_OWNER},KAPE}"
DEFAULT_ALLOW_NETS="${WADE_ALLOW_NETS:-}"

if [[ "$NONINTERACTIVE" -eq 1 ]]; then
  LWADE="$DEFAULT_HOSTNAME"; LWADEUSER="$DEFAULT_OWNER"
  SMB_USERS_CSV="$DEFAULT_SMB_USERS"; ALLOW_NETS_CSV="$DEFAULT_ALLOW_NETS"
  echo "[*] Noninteractive: using wade.conf defaults."
else
  read -r -p "Hostname for this WADE server [${DEFAULT_HOSTNAME}]: " LWADE; LWADE="${LWADE:-$DEFAULT_HOSTNAME}"
  read -r -p "Primary Linux user to own shares [${DEFAULT_OWNER}]: " LWADEUSER; LWADEUSER="${LWADEUSER:-$DEFAULT_OWNER}"
  read -r -p "Samba users (comma-separated) [${DEFAULT_SMB_USERS}]: " SMB_USERS_CSV; SMB_USERS_CSV="${SMB_USERS_CSV:-$DEFAULT_SMB_USERS}"
  read -r -p "Allowed networks CSV (ex. 10.0.0.0/24,10.0.1.0/24) [${DEFAULT_ALLOW_NETS}]: " ALLOW_NETS_CSV; ALLOW_NETS_CSV="${ALLOW_NETS_CSV:-$DEFAULT_ALLOW_NETS}"
fi
hostnamectl set-hostname "$LWADE" || true

IFS=',' read -ra ALLOW_NETS_ARR <<< "${ALLOW_NETS_CSV// /}"
for net in "${ALLOW_NETS_ARR[@]:-}"; do [[ -n "$net" ]] && ! validate_cidr "$net" && warn_note "precheck" "Invalid CIDR ignored: $net"; done
IFS=',' read -ra SMBUSERS <<< "${SMB_USERS_CSV}"
VALID_USERS="$(printf '%s\n' "${SMB_USERS_CSV:-}" | tr ',;' '  ' | xargs)"

if ! id -u "$LWADEUSER" >/dev/null 2>&1; then
  echo "[*] Creating user ${LWADEUSER}…"
  useradd -m -s /bin/bash "$LWADEUSER" || warn_note "useradd" "could not create ${LWADEUSER}"
  if [[ "$NONINTERACTIVE" -eq 0 ]]; then
    while :; do read -s -p "Password for ${LWADEUSER}: " p1; echo; read -s -p "Confirm: " p2; echo; [[ "$p1" == "$p2" && -n "$p1" ]] && break; echo "Mismatch/empty. Try again."; done
    echo "${LWADEUSER}:${p1}" | chpasswd || warn_note "useradd" "could not set password for ${LWADEUSER}"
  fi
  usermod -aG sudo "$LWADEUSER" || true
fi
for u in "${SMBUSERS[@]}"; do u=$(echo "$u" | xargs); id -u "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u" || warn_note "useradd" "failed creating $u"; done

#####################################
# Unified Prompt Stack
#####################################
SMB_SET_PW_ALL="N"
if [[ "$NONINTERACTIVE" -eq 0 ]]; then
  read -r -p "Set one Samba password for ALL SMB users now? [y/N]: " SMB_SET_PW_ALL
  SMB_SET_PW_ALL="${SMB_SET_PW_ALL:-N}"
fi
SMB_ALL_PW=""
if [[ "$SMB_SET_PW_ALL" =~ ^[Yy]$ && "$NONINTERACTIVE" -eq 0 ]]; then
  while :; do
    read -s -p "Samba password (will apply to: ${SMB_USERS_CSV}): " p1; echo
    read -s -p "Confirm: " p2; echo
    [[ "$p1" == "$p2" && -n "$p1" ]] && SMB_ALL_PW="$p1" && break
    echo "Mismatch/empty. Try again."
  done
fi

# Splunk UF prompts (pre-captured)
DEFAULT_HOSTS="${SPLUNK_UF_RCVR_HOSTS:-splunk.example.org:9997}"
DEFAULT_INDEX="${SPLUNK_UF_DEFAULT_INDEX:-${SPLUNK_DEFAULT_INDEX:-wade_custom}}"
COMPRESSED="${SPLUNK_UF_COMPRESSED:-true}"
USE_ACK="${SPLUNK_UF_USE_ACK:-true}"
SSL_VERIFY="${SPLUNK_UF_SSL_VERIFY:-false}"
SSL_CN="${SPLUNK_UF_SSL_COMMON_NAME:-*}"
DS_TARGET="${SPLUNK_UF_DEPLOYMENT_SERVER:-}"

PRESET_SPLUNK_SERVER_LINE=""
PRESET_SPLUNK_INDEX="$DEFAULT_INDEX"
PRESET_SPLUNK_COMPRESSED="$COMPRESSED"
PRESET_SPLUNK_USEACK="$USE_ACK"
PRESET_SPLUNK_SSL_VERIFY="$SSL_VERIFY"
PRESET_SPLUNK_SSL_CN="$SSL_CN"
PRESET_SPLUNK_DS="$DS_TARGET"

if [[ "$NONINTERACTIVE" -eq 0 ]]; then
  echo
  echo ">> Splunk UF configuration (captured once, used later)"
  read -r -p "Indexer(s) host[:port], comma-separated [${DEFAULT_HOSTS}]: " IDXERS
  IDXERS="${IDXERS:-$DEFAULT_HOSTS}"
  DEFAULT_PORT="$(echo "${DEFAULT_HOSTS##*:}" | awk '{print $1}')"
  NORMALIZED=""
  IFS=',' read -r -a ARR <<< "$IDXERS"
  for h in "${ARR[@]}"; do
    h="$(echo "$h" | xargs)"; [[ -z "$h" ]] && continue
    if [[ "$h" == *:* ]]; then NORMALIZED+="${h},"; else NORMALIZED+="${h}:${DEFAULT_PORT},"; fi
  done
  PRESET_SPLUNK_SERVER_LINE="${NORMALIZED%,}"

  read -r -p "Default index for WADE logs [${DEFAULT_INDEX}]: " tmp; tmp="${tmp:-$DEFAULT_INDEX}"; PRESET_SPLUNK_INDEX="$tmp"
  read -r -p "Enable compression? (true/false) [${COMPRESSED}]: " tmp; PRESET_SPLUNK_COMPRESSED="${tmp:-$COMPRESSED}"
  read -r -p "Enable indexer ACKs? (true/false) [${USE_ACK}]: " tmp; PRESET_SPLUNK_USEACK="${tmp:-$USE_ACK}"
  read -r -p "Verify indexer SSL certs? (true/false) [${SSL_VERIFY}]: " tmp; PRESET_SPLUNK_SSL_VERIFY="${tmp:-$SSL_VERIFY}"
  if [[ "${PRESET_SPLUNK_SSL_VERIFY}" == "true" ]]; then
    read -r -p "sslCommonNameToCheck [${SSL_CN}]: " tmp; PRESET_SPLUNK_SSL_CN="${tmp:-$SSL_CN}"
  fi
  read -r -p "Deployment server host:port (blank to skip) [${DS_TARGET}]: " tmp; PRESET_SPLUNK_DS="${tmp:-$DS_TARGET}"
fi

export PRESET_SPLUNK=1
export PRESET_SPLUNK_SERVER_LINE PRESET_SPLUNK_INDEX PRESET_SPLUNK_COMPRESSED PRESET_SPLUNK_USEACK PRESET_SPLUNK_SSL_VERIFY PRESET_SPLUNK_SSL_CN PRESET_SPLUNK_DS
export SMB_ALL_PW

# ===== WHIFF (AI assistant / KB) prompts =====
DEFAULT_WHIFF_ENABLE="${WHIFF_ENABLE:-1}"
DEFAULT_WHIFF_BIND="${WHIFF_BIND_ADDR:-127.0.0.1}"
DEFAULT_WHIFF_PORT="${WHIFF_PORT:-8088}"
DEFAULT_WHIFF_BACKEND="${WHIFF_BACKEND:-ollama}"      # ollama|openai|http
DEFAULT_WHIFF_MODEL="${WHIFF_MODEL:-llama3.1:8b-instruct}"
DEFAULT_WHIFF_ENDPOINT="${WHIFF_ENDPOINT:-}"
DEFAULT_WHIFF_API_KEY="${WHIFF_API_KEY:-}"

PRESET_WHIFF_ENABLE="$DEFAULT_WHIFF_ENABLE"
PRESET_WHIFF_BIND="$DEFAULT_WHIFF_BIND"
PRESET_WHIFF_PORT="$DEFAULT_WHIFF_PORT"
PRESET_WHIFF_BACKEND="$DEFAULT_WHIFF_BACKEND"
PRESET_WHIFF_MODEL="$DEFAULT_WHIFF_MODEL"
PRESET_WHIFF_ENDPOINT="$DEFAULT_WHIFF_ENDPOINT"
PRESET_WHIFF_API_KEY=""

if [[ "$NONINTERACTIVE" -eq 0 ]]; then
  echo
  echo ">> WHIFF (analyst assistant / knowledge base)"
  read -r -p "Install and configure WHIFF now? (y/N) [$( [[ "$DEFAULT_WHIFF_ENABLE" = "1" ]] && echo y || echo N )]: " __ans
  if [[ "${__ans:-}" =~ ^[Yy]$ ]]; then
    PRESET_WHIFF_ENABLE="1"
    read -r -p "Bind address [${DEFAULT_WHIFF_BIND}]: " tmp; PRESET_WHIFF_BIND="${tmp:-$DEFAULT_WHIFF_BIND}"
    read -r -p "Port [${DEFAULT_WHIFF_PORT}]: " tmp; PRESET_WHIFF_PORT="${tmp:-$DEFAULT_WHIFF_PORT}"
    read -r -p "Backend (ollama|openai|http) [${DEFAULT_WHIFF_BACKEND}]: " tmp; PRESET_WHIFF_BACKEND="${tmp:-$DEFAULT_WHIFF_BACKEND}"
    read -r -p "Model name/tag [${DEFAULT_WHIFF_MODEL}]: " tmp; PRESET_WHIFF_MODEL="${tmp:-$DEFAULT_WHIFF_MODEL}"
    if [[ "$PRESET_WHIFF_BACKEND" != "ollama" ]]; then
      read -r -p "Backend endpoint URL (blank to skip) [${DEFAULT_WHIFF_ENDPOINT}]: " tmp
      PRESET_WHIFF_ENDPOINT="${tmp:-$DEFAULT_WHIFF_ENDPOINT}"
    fi
    if [[ "$PRESET_WHIFF_BACKEND" == "openai" ]]; then
      echo "If using OpenAI (or compatible) enter API key (leave blank to skip)."
      read -r -s -p "API key: " tmp; echo
      PRESET_WHIFF_API_KEY="${tmp:-}"
      if [[ -n "$PRESET_WHIFF_API_KEY" ]]; then
        read -r -p "Persist API key to /etc/wade/wade.env? (NOT RECOMMENDED) [y/N]: " tmp
        if [[ "${tmp:-}" =~ ^[Yy]$ ]]; then
          WHIFF_PERSIST_API_KEY="1"
        else
          WHIFF_PERSIST_API_KEY="0"
        fi
      fi
    fi
  else
    PRESET_WHIFF_ENABLE="0"
  fi
fi

export PRESET_WHIFF="1"
export PRESET_WHIFF_ENABLE PRESET_WHIFF_BIND PRESET_WHIFF_PORT PRESET_WHIFF_BACKEND PRESET_WHIFF_MODEL PRESET_WHIFF_ENDPOINT PRESET_WHIFF_API_KEY WHIFF_PERSIST_API_KEY

RUN_STIG_NOW="N"
if [[ "$NONINTERACTIVE" -eq 0 ]]; then
  read -r -p "Run DISA STIG assessment at the end? [y/N]: " RUN_STIG_NOW; RUN_STIG_NOW="${RUN_STIG_NOW:-N}"
fi
export RUN_STIG_NOW

if [[ "$NONINTERACTIVE" -eq 0 ]]; then
  echo; echo "===== Summary ====="
  echo " Hostname     : $LWADE"
  echo " Linux Owner  : $LWADEUSER"
  echo " SMB users    : ${SMB_USERS_CSV}"
  echo " Allow nets   : ${ALLOW_NETS_CSV:-<none>}"
  echo " WHIFF       : $( [[ "$PRESET_WHIFF_ENABLE" = "1" ]] && echo enabled || echo disabled )  backend=${PRESET_WHIFF_BACKEND}  model=${PRESET_WHIFF_MODEL}  bind=${PRESET_WHIFF_BIND}:${PRESET_WHIFF_PORT}"
  echo " Offline mode : ${OFFLINE}"
  confirm "Proceed with installation?" || exit 0
fi

######################
# Samba non-sense
######################
wade_install_samba() {
  set -e
  SMB_CONF="/etc/samba/smb.conf"
  install -d /etc/samba

  # Seed minimal global if missing (literal heredoc)
  if [[ ! -f "$SMB_CONF" ]]; then
    cat >"$SMB_CONF" <<'EOF'
[global]
   workgroup = WORKGROUP
   server string = WADE
   server role = standalone server
   security = user

   # Never map unknowns to guest (prevents Windows "unauthenticated guest" policy error)
   map to guest = Never
   usershare allow guests = no

   # Require modern SMB (avoid SMB1 guest dances)
   server min protocol = SMB2_10
   client min protocol = SMB2

   # Sensible auth defaults for Win10/11
   encrypt passwords = yes
   # ntlm auth defaults to 'no' in modern Samba; Windows uses NTLMv2/Kerberos anyway.
   dns proxy = no
EOF
fi

  [[ -f "${SMB_CONF}.bak" ]] || cp "$SMB_CONF" "${SMB_CONF}.bak"

  DATADIR="/home/${LWADEUSER}/${WADE_DATADIR}"
  CASESDIR="/home/${LWADEUSER}/${WADE_CASESDIR}"
  STAGINGDIR="/home/${LWADEUSER}/${WADE_STAGINGDIR}"

  mkdir -p "$DATADIR" "$CASESDIR" "$STAGINGDIR"
  chown -R "${LWADEUSER}:${LWADEUSER}" "$DATADIR" "$CASESDIR" "$STAGINGDIR"
  chmod 755 "/home/${LWADEUSER}" "$DATADIR" "$CASESDIR" "$STAGINGDIR"

  # Optional allow/deny block
  HOSTS_BLOCK=""
  if [[ -n "${ALLOW_NETS_CSV:-}" ]]; then
    HOSTS_BLOCK="   hosts allow ="
    IFS=',' read -ra __nets <<< "${ALLOW_NETS_CSV// /}"
    for net in "${__nets[@]}"; do [[ -n "$net" ]] && HOSTS_BLOCK+=" ${net}"; done
    HOSTS_BLOCK+=$'\n   hosts deny = 0.0.0.0/0'
  fi

  # Replace prior WADE section
  sed -e '/^\[WADE-BEGIN\]/,/^\[WADE-END\]/d' -i "$SMB_CONF"

  # Expanding heredoc (uses vars)
  cat >>"$SMB_CONF" <<EOF
[WADE-BEGIN]
[DataSources]
   path = ${DATADIR}
   read only = no
   browsable = yes
   public = no
   guest ok = no
   writable = yes
   valid users = ${VALID_USERS}
${HOSTS_BLOCK}

[Cases]
   path = ${CASESDIR}
   read only = no
   browsable = yes
   public = no
   guest ok = no
   writable = yes
   valid users = ${VALID_USERS}
${HOSTS_BLOCK}

[Staging]
   path = ${STAGINGDIR}
   read only = no
   browsable = yes
   public = no
   guest ok = no
   writable = yes
   valid users = ${VALID_USERS}
${HOSTS_BLOCK}
[WADE-END]
EOF

  if ! testparm -s >/dev/null 2>&1; then
    echo "[!] testparm failed; restoring ${SMB_CONF}.bak"
    cp -f "${SMB_CONF}.bak" "$SMB_CONF"
    return 1
  fi

IFS=',' read -ra users <<< "${SMB_USERS_CSV}"
need_pw_note=0

gen_pw() {
  # 20-char safe default for noninteractive runs
  tr -dc 'A-Za-z0-9@#%+=' </dev/urandom | head -c 20
}

for u in "${users[@]}"; do
  u="$(echo "$u" | xargs)"; [[ -z "$u" ]] && continue
  if ! pdbedit -L 2>/dev/null | awk -F: '{print $1}' | grep -qx "$u"; then
    if [[ -n "${SMB_ALL_PW:-}" ]]; then
      ( printf "%s\n%s\n" "$SMB_ALL_PW" "$SMB_ALL_PW" ) | smbpasswd -s -a "$u" >/dev/null || true
    elif [[ "$NONINTERACTIVE" -eq 1 ]]; then
      AUTOPW="$(gen_pw)"
      ( printf "%s\n%s\n" "$AUTOPW" "$AUTOPW" ) | smbpasswd -s -a "$u" >/dev/null || true
      echo "[wade] SMB password for user '$u' (auto-generated): ${AUTOPW}" >> "$LOG_FILE"
      need_pw_note=1
    else
      echo "Set Samba password for user '$u':"
      smbpasswd -a "$u" || true
    fi
  fi
done

if (( need_pw_note )); then
  echo "[wade] NOTE: Auto-generated Samba passwords were written to ${LOG_FILE}. Change them with 'smbpasswd <user>'." >&2
fi

  systemd_queue_enable smbd || systemd_queue_enable smb
  systemd_queue_enable nmbd || systemd_queue_enable nmb || true

  # Firewall open
  if [[ "$FIREWALL" == "ufw" ]] && command -v ufw >/dev/null 2>&1; then
    ufw allow Samba || true
  elif command -v firewall-cmd >/dev/null 2>&1; then
    systemctl enable firewalld --now || true
    firewall-cmd --permanent --add-service=samba || true
    firewall-cmd --reload || true
  fi
}

#####################################
# Samba shares (DataSources, Cases, Staging)
#####################################
get_ver_samba(){
  local SMB_CONF="/etc/samba/smb.conf"
  grep -q '^\[WADE-BEGIN\]' "$SMB_CONF" 2>/dev/null || { echo ""; return; }
  [[ -d "/home/${LWADEUSER}/${WADE_DATADIR}" ]]    || { echo ""; return; }
  [[ -d "/home/${LWADEUSER}/${WADE_CASESDIR}" ]]   || { echo ""; return; }
  [[ -d "/home/${LWADEUSER}/${WADE_STAGINGDIR}" ]] || { echo ""; return; }
  echo configured
}

run_step "samba" "configured" get_ver_samba 'wade_install_samba' || fail_note "samba" "share setup failed"

#####################################
# Staging Service Install (venv-managed)
#####################################
VENV_DIR="/home/${LWADEUSER}/.venvs/wade"

run_step "wade-stage" "${STAGE_EXPECT_SHA}" get_ver_wade_stage '
  set -e

  install -d -m 0755 /opt/wade
  install -m 0755 "'"$STAGE_SRC"'" /opt/wade/stage_daemon.py

  install -d -m 0755 "/home/'"${LWADEUSER}"'/.venvs"
  python3 -m venv "'"$VENV_DIR"'"
  chown -R "'"${LWADEUSER}:${LWADEUSER}"'" "'"$VENV_DIR"'"

  "'"$VENV_DIR"'/bin/python" -m pip install -U pip setuptools wheel >/dev/null 2>&1 || true
  # speed-up: use shared wheelhouse
  '"pip_cached_install \"$VENV_DIR/bin\" inotify-simple"'

  "'"$VENV_DIR"'/bin/python" - <<'"'"'PY'"'"'
import json, os, re, shutil, signal, sqlite3, subprocess, sys, time, string, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple
from inotify_simple import INotify, flags
import difflib
print("WADE staging imports OK from", sys.executable)
PY

  install -d -m 0755 /var/wade/logs/stage /var/wade/state
  chown -R "'"${LWADEUSER}:${LWADEUSER}"'" /var/wade

  STAGING_ROOT="/home/'"${LWADEUSER}"'/'"${WADE_STAGINGDIR}"'"
  DATAS_ROOT="/home/'"${LWADEUSER}"'/'"${WADE_DATADIR}"'"
  QUEUE_DIR="${WADE_QUEUE_DIR:-_queue}"

  install -d -o "'"${LWADEUSER}"'" -g "'"${LWADEUSER}"'" -m 0755 \
      "${STAGING_ROOT}/full" "${STAGING_ROOT}/light" \
      "${DATAS_ROOT}/Hosts" "${DATAS_ROOT}/Network" "${DATAS_ROOT}/${QUEUE_DIR}"

  cat >/etc/systemd/system/wade-staging.service <<EOF
[Unit]
Description=WADE Staging Daemon (full vs light)
After=network-online.target
Wants=network-online.target
ConditionPathExists=/opt/wade/stage_daemon.py

[Service]
Type=simple
User=${LWADEUSER}
Group=${LWADEUSER}
EnvironmentFile=-/etc/wade/wade.env
Environment=PYTHONUNBUFFERED=1
WorkingDirectory=/opt/wade
ExecStart=${VENV_DIR}/bin/python /opt/wade/stage_daemon.py
Restart=on-failure
RestartSec=3
UMask=002
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=false
ReadWritePaths=/home/${LWADEUSER} /var/wade

[Install]
WantedBy=multi-user.target
EOF

  systemd_queue_enable wade-staging.service
  sha256sum /opt/wade/stage_daemon.py | awk '"'"'{print $1}'"'"' > "'"${STEPS_DIR}/wade-stage.ver"'"
  install -d -m 0755 /home/'"${LWADEUSER}"'/WADE 2>/dev/null || true
  "'"$VENV_DIR"'/bin/pip" freeze > /home/'"${LWADEUSER}"'/WADE/requirements.lock || true
' || fail_note "wade-stage" "service install/start failed"

#####################################
# pipx tools: volatility3 + dissect (consolidated)
#####################################
run_step "pipx-vol3" "" get_ver_pipx_vol3 '
  set -e
  ensure_pipx_pkg volatility3
' || fail_note "pipx-vol3" "install failed"

run_step "pipx-dissect" "" get_ver_pipx_dissect '
  set -e
  ensure_pipx_pkg "dissect[cli]" --include-deps
' || fail_note "pipx-dissect" "install failed"

run_step "vol3-runtime" "ready" 'get_mark_ver vol3-runtime' '
  set -e
  : "${VOL3_BASE_DIR:=/var/wade/vol3}"
  : "${VOL3_SYMBOLS_DIR:=${VOL3_BASE_DIR}/symbols}"
  : "${VOL3_CACHE_DIR:=${VOL3_BASE_DIR}/cache}"
  : "${VOL3_PLUGIN_DIR:=${VOL3_BASE_DIR}/plugins}"
  : "${LWADEUSER:=autopsy}"

  install -d -m 2775 "$VOL3_SYMBOLS_DIR" "$VOL3_CACHE_DIR" "$VOL3_PLUGIN_DIR"
  chown -R "$LWADEUSER:$LWADEUSER" "$VOL3_BASE_DIR" || true

  VOL_BIN="$(command -v vol || true)"
  [[ -x "$VOL_BIN" ]] || { echo "vol not found; run with --only=pipx-vol3,vol3-runtime or full install"; exit 1; }

  cat >/usr/local/bin/vol3 <<\EOF
#!/usr/bin/env bash
set -euo pipefail
SYMDIR="${VOL3_SYMBOLS_DIR:-/var/wade/vol3/symbols}"
CACHEDIR="${VOL3_CACHE_DIR:-/var/wade/vol3/cache}"
PLUGDIR="${VOL3_PLUGIN_DIR:-/var/wade/vol3/plugins}"
exec vol \
  --cache-path "$CACHEDIR" \
  --plugin-dirs "$PLUGDIR" \
  -s "$SYMDIR" \
  "$@"
EOF
  chmod 0755 /usr/local/bin/vol3

  echo "$(date -Iseconds)" > "${STEPS_DIR}/vol3-runtime.ver"
' || fail_note "vol3-runtime" "wrapper/setup failed"

#####################################
# Mandiant capa (engine)
#####################################
run_step "capa" "${CAPA_VERSION:-}" get_ver_capa '
  set -e
  : "${WADE_CAPA_VENV:=/opt/wade/venvs/capa}"

  install -d "$(dirname "$WADE_CAPA_VENV")"
  [[ -x "$WADE_CAPA_VENV/bin/python" ]] || python3 -m venv "$WADE_CAPA_VENV"
  "$WADE_CAPA_VENV/bin/python" -m pip install -U pip wheel setuptools >/dev/null 2>&1 || true

  # Build the package string inside the subshell so it exists where it is used
  PKG="flare-capa"
  [[ -n "${CAPA_VERSION:-}" ]] && PKG="flare-capa==${CAPA_VERSION}"

  # Use the shared wheelhouse helper entirely inside the step
  pip_cached_install "$WADE_CAPA_VENV/bin" "$PKG"

  install -d /usr/local/bin
  ln -sf "$WADE_CAPA_VENV/bin/capa" /usr/local/bin/capa
  /usr/local/bin/capa --version >/dev/null 2>&1 || { echo "capa not runnable"; exit 1; }
' || fail_note "capa" "engine install failed"

#####################################
# Mandiant capa-rules (repo or tarball)
#####################################
run_step "capa-rules" "${WADE_CAPA_RULES_COMMIT:-}" get_ver_capa_rules '
  set -e
  : "${WADE_CAPA_RULES_DIR:=/opt/capa-rules}"
  : "${WADE_CAPA_RULES_COMMIT:=}"

  install -d /opt
  if [[ -f "${WADE_PKG_DIR:-/var/wade/pkg}/capa-rules.tar.gz" ]]; then
    echo "[*] Using offline rules from ${WADE_PKG_DIR}/capa-rules.tar.gz"
    rm -rf "$WADE_CAPA_RULES_DIR.tmp" "$WADE_CAPA_RULES_DIR"
    mkdir -p "$WADE_CAPA_RULES_DIR.tmp"
    tar -xzf "${WADE_PKG_DIR}/capa-rules.tar.gz" -C "$WADE_CAPA_RULES_DIR.tmp" --strip-components=1
    mv "$WADE_CAPA_RULES_DIR.tmp" "$WADE_CAPA_RULES_DIR"
  elif [[ "${OFFLINE:-0}" == "1" && -f "${OFFLINE_SRC:-}/capa-rules.tar.gz" ]]; then
    echo "[*] Using offline rules from ${OFFLINE_SRC}/capa-rules.tar.gz"
    rm -rf "$WADE_CAPA_RULES_DIR.tmp" "$WADE_CAPA_RULES_DIR"
    mkdir -p "$WADE_CAPA_RULES_DIR.tmp"
    tar -xzf "${OFFLINE_SRC}/capa-rules.tar.gz" -C "$WADE_CAPA_RULES_DIR.tmp" --strip-components=1
    mv "$WADE_CAPA_RULES_DIR.tmp" "$WADE_CAPA_RULES_DIR"
  else
    if [[ -d "$WADE_CAPA_RULES_DIR/.git" ]]; then
      git -C "$WADE_CAPA_RULES_DIR" pull --ff-only || true
    else
      rm -rf "$WADE_CAPA_RULES_DIR"
      git clone --depth=1 https://github.com/mandiant/capa-rules "$WADE_CAPA_RULES_DIR"
    fi
    if [[ -n "$WADE_CAPA_RULES_COMMIT" ]]; then
      git -C "$WADE_CAPA_RULES_DIR" fetch --depth=1 origin "$WADE_CAPA_RULES_COMMIT" || true
      git -C "$WADE_CAPA_RULES_DIR" checkout -q "$WADE_CAPA_RULES_COMMIT" || true
    fi
  fi

  chown -R root:root "$WADE_CAPA_RULES_DIR" && chmod -R a+rX "$WADE_CAPA_RULES_DIR"

  cat >/etc/profile.d/wade-capa.sh <<EOF
export WADE_CAPA_RULES="${WADE_CAPA_RULES_DIR}"
EOF
  chmod 0644 /etc/profile.d/wade-capa.sh

  cat >/usr/local/sbin/update-capa-rules <<'"'"'EOF'"'"'
#!/usr/bin/env bash
set -euo pipefail
RULES_DIR="${WADE_CAPA_RULES:-/opt/capa-rules}"
if [[ -d "$RULES_DIR/.git" ]]; then
  git -C "$RULES_DIR" pull --ff-only
else
  echo "capa-rules is not a git repo (likely from tarball). Replace ${RULES_DIR} to update."
fi
EOF
  chmod 0755 /usr/local/sbin/update-capa-rules

  rules_count="$(find "$WADE_CAPA_RULES_DIR" -type f -name "*.yml" 2>/dev/null | wc -l | tr -d " " || echo 0)"
  [[ "${rules_count:-0}" -gt 0 ]] || { echo "no rules found"; exit 1; }
' || fail_note "capa-rules" "rules install failed"

#####################################
# WADE Malware Extractor (CLI)
#####################################
run_step "wade-mw-extractor" "${MWEX_EXPECT_SHA}" get_ver_wade_mwex '
  set -e

  install -d -m 0755 /opt/wade /var/wade/logs/malware
  install -m 0755 "'"$MWEX_SRC"'" /opt/wade/wade_mw_extract.py

  cat >/usr/local/bin/wade-mw-extract <<'"'"'EOF'"'"'
#!/usr/bin/env bash
set -euo pipefail
export WADE_CAPA_RULES="${WADE_CAPA_RULES:-/opt/capa-rules}"
exec /usr/bin/env python3 /opt/wade/wade_mw_extract.py "$@"
EOF
  chmod 0755 /usr/local/bin/wade-mw-extract

  command -v target-fs >/dev/null 2>&1     || echo "[WARN] Dissect CLI (target-fs) not found; disk mode unavailable."
  command -v vol >/dev/null 2>&1 || command -v volatility3 >/dev/null 2>&1 \
                                         || echo "[WARN] Volatility 3 not found; memory mode unavailable."
  command -v capa >/dev/null 2>&1          || echo "[WARN] capa not found; capability analysis disabled."
  command -v 7zz >/dev/null 2>&1 || command -v zip >/dev/null 2>&1 \
                                         || echo "[WARN] Neither 7zz nor zip in PATH; passworded ZIPs unavailable."

  sha256sum /opt/wade/wade_mw_extract.py | awk "{print \$1}" > "'"${STEPS_DIR}/wade-mw-extractor.ver"'"
' || fail_note "wade-mw-extractor" "install failed"

#####################################
# Helpers for packages & hayabusa arch
#####################################
fetch_pkg(){
  local sub="$1" file="$2"
  local local_pkg="${WADE_PKG_DIR}/${sub}/${file}"
  if [[ -f "$local_pkg" ]]; then cp "$local_pkg" .; return 0; fi
  if [[ "$OFFLINE" == "1" ]]; then
    local off="${OFFLINE_SRC}/${sub}/${file}"
    [[ -f "$off" ]] && { cp "$off" .; return 0; }
  fi
  return 1
}
detect_hayabusa_arch(){
  case "$(uname -m)" in
    x86_64|amd64)  echo "linux-x64" ;;
    aarch64|arm64) echo "linux-arm64" ;;
    *)             echo "linux-x64" ;;
  esac
}

#####################################
# Volatility3 symbol packs (soft-fail)
#####################################
if [[ "${MOD_VOL_SYMBOLS_ENABLED:-1}" == "1" ]]; then
run_step "vol3-symbols" "current" 'get_mark_ver vol3-symbols' '
  set -e
  : "${VOL3_SYMBOLS_DIR:=/var/wade/vol3/symbols}"
  mkdir -p "${VOL3_SYMBOLS_DIR}"

  for z in windows.zip mac.zip linux.zip; do
    [[ -f "${VOL3_SYMBOLS_DIR}/${z}" ]] && continue
    fetch_pkg "volatility3/symbols" "$z" || curl -L "https://downloads.volatilityfoundation.org/volatility3/symbols/${z}" -o "$z"
    cp -f "$z" "${VOL3_SYMBOLS_DIR}/"
  done

  chown -R "${LWADEUSER}:${LWADEUSER}" "${VOL3_SYMBOLS_DIR}" || true
  echo "$(date -Iseconds)" > "${STEPS_DIR}/vol3-symbols.ver"
' || fail_note "volatility_symbols" "download/verify failed"
fi

#####################################
# bulk_extractor (repo or source build; soft-fail)
#####################################
if [[ "${MOD_BULK_EXTRACTOR_ENABLED:-1}" == "1" ]]; then
if [[ "${BULK_EXTRACTOR_MODE:-source}" == "repo" ]]; then
run_step "bulk_extractor" "repo" get_ver_be '
  set -e
  if [[ "$PM" == "apt" ]]; then
    bash -lc "$PKG_INSTALL bulk-extractor" || true
    command -v bulk_extractor >/dev/null 2>&1 || { echo "bulk_extractor not found"; exit 1; }
    ln -sf "$(command -v bulk_extractor)" /usr/local/bin/bulk_extractor || true
  else
    bash -lc "$PKG_INSTALL bulk_extractor" || true
    command -v bulk_extractor >/dev/null 2>&1 || { echo "bulk_extractor not found"; exit 1; }
    ln -sf "$(command -v bulk_extractor)" /usr/local/bin/bulk_extractor || true
  fi
' || fail_note "bulk_extractor" "repo install failed"
else
run_step "bulk_extractor" "${BE_GIT_REF:-master}" get_ver_be '
  set -e
  echo "[*] Installing bulk_extractor from source…"
  BE_PREFIX="${WADE_TOOLS_DIR:-/opt/wade/tools.d}/bulk_extractor"
  mkdir -p "$BE_PREFIX" /var/tmp/wade/build
  BUILD_DIR="$(mktemp -d /var/tmp/wade/build/be.XXXXXX)"

  if [[ "$PM" == "apt" ]]; then
    bash -lc "$PKG_INSTALL --no-install-recommends \
      git ca-certificates build-essential autoconf automake libtool pkg-config \
      flex bison libewf-dev libssl-dev zlib1g-dev libxml2-dev libexiv2-dev \
      libtre-dev libsqlite3-dev libpcap-dev libre2-dev libpcre3-dev libexpat1-dev" || true
  else
    if have_cmd dnf; then dnf -y groupinstall "Development Tools" || true; else yum -y groupinstall "Development Tools" || true; fi
    bash -lc "$PKG_INSTALL \
      git ca-certificates libewf-devel openssl-devel zlib-devel libxml2-devel \
      exiv2-devel tre-devel sqlite-devel libpcap-devel re2-devel pcre-devel \
      expat-devel flex bison" || true
  fi

  OFFLINE_TGZ="${WADE_PKG_DIR:-/var/wade/pkg}/bulk_extractor/bulk_extractor-src.tar.gz"
  BE_GIT_REF="${BE_GIT_REF:-master}"

  pushd "$BUILD_DIR" >/dev/null
  if [[ "$OFFLINE" == "1" && -f "$OFFLINE_TGZ" ]]; then
    echo "[*] Using offline bulk_extractor source tarball: $OFFLINE_TGZ"
    tar -xzf "$OFFLINE_TGZ"
    [[ -d bulk_extractor ]] || { echo "bulk_extractor folder not found in tarball"; exit 1; }
    cd bulk_extractor
  else
    echo "[*] Cloning bulk_extractor (with submodules)…"
    git clone --recurse-submodules https://github.com/simsong/bulk_extractor.git
    cd bulk_extractor
    [[ "$BE_GIT_REF" != "master" ]] && git checkout "$BE_GIT_REF" || true
    git submodule update --init --recursive
  fi

  ./bootstrap.sh || true
  ./configure --prefix="$BE_PREFIX"
  make -j"$(nproc)"
  make install

  install -d /usr/local/bin
  ln -sf "$BE_PREFIX/bin/bulk_extractor" /usr/local/bin/bulk_extractor
  /usr/local/bin/bulk_extractor -V >/dev/null 2>&1 || { echo "version check failed"; exit 1; }

  popd >/dev/null
  rm -rf "$BUILD_DIR"
' || fail_note "bulk_extractor" "build/install failed (see ${LOG_FILE})"
fi
fi

#####################################
# Qt/GL runtime libs (apt branch) – short-circuits if present
#####################################
if [[ "$PM" == "apt" && ( "${MOD_PIRANHA_ENABLED:-1}" == "1" || "${MOD_BARRACUDA_ENABLED:-1}" == "1" ) ]]; then
run_step "qtgl-runtime" "present" get_ver_qtgl '
  set -e
  # libs already installed via bundle; nothing to do
  true
' || fail_note "qtgl-runtime" "Qt/GL libs missing"
fi

#####################################
# SSH X11 forwarding (server-side GUI over ssh -X)
#####################################
get_ver_x11fwd(){
  if [[ "$PM" == "apt" ]]; then
    dpkg -s xauth >/dev/null 2>&1 || { echo ""; return; }
  else
    rpm -q xorg-x11-xauth >/dev/null 2>&1 || rpm -q xauth >/dev/null 2>&1 || { echo ""; return; }
  fi
  grep -qiE '^\s*X11Forwarding\s+yes' /etc/ssh/sshd_config && echo configured || echo ""
}

run_step "x11-forwarding" "configured" get_ver_x11fwd '
  set -e
  sed -ri "s/^\s*#?\s*X11Forwarding.*/X11Forwarding yes/" /etc/ssh/sshd_config
  if grep -qiE "^\s*X11UseLocalhost" /etc/ssh/sshd_config; then
    sed -ri "s/^\s*#?\s*X11UseLocalhost.*/X11UseLocalhost yes/" /etc/ssh/sshd_config
  else
    echo "X11UseLocalhost yes" >> /etc/ssh/sshd_config
  fi
  if ! grep -qiE "^\s*X11DisplayOffset" /etc/ssh/sshd_config; then
    echo "X11DisplayOffset 10" >> /etc/ssh/sshd_config
  fi

  systemctl restart ssh || systemctl restart sshd || true
  su - "'"${LWADEUSER}"'" -c "mkdir -p ~/.config/matplotlib; touch ~/.Xauthority; chmod 600 ~/.Xauthority" || true
' || fail_note "x11-forwarding" "setup failed"

#####################################
# Piranha (install only; GUI via ssh -X, no systemd) – no shallow clone per your request
#####################################
get_ver_piranha(){ [[ -x /usr/local/bin/piranha && -d /opt/piranha/.venv && -f /opt/piranha/piranha.py ]] && echo installed || echo ""; }

if [[ "${MOD_PIRANHA_ENABLED:-1}" == "1" ]]; then
run_step "piranha" "installed" get_ver_piranha '
  set -e
  install -d /opt/piranha /var/log/wade/piranha
  chown -R "'"${LWADEUSER}:${LWADEUSER}"'" /opt/piranha /var/log/wade/piranha

  install -d /opt/piranha/Documents/PiranhaLogs
  chown -R "'"${LWADEUSER}:${LWADEUSER}"'" /opt/piranha/Documents
  ln -sf /var/log/wade/piranha/APT_Report.log /opt/piranha/Documents/PiranhaLogs/APT_Report.log || true

  if [[ "$OFFLINE" == "1" ]]; then
    PKG_ARC="$(ls "'"${WADE_PKG_DIR}"'/piranha"/"piranha"*.tar.gz "'"${WADE_PKG_DIR}"'/piranha"/"piranha"*.zip 2>/dev/null | head -1 || true)"
    if [[ -z "$PKG_ARC" ]]; then
      PKG_ARC="$(ls "'"${WADE_PKG_DIR}"'/piranha/piranha*.tar.gz "'"${WADE_PKG_DIR}"'/piranha/piranha*.zip 2>/dev/null | head -1 || true)"
    fi
    [[ -n "$PKG_ARC" ]] || { echo "offline Piranha archive missing"; exit 1; }
    cp "$PKG_ARC" /opt/piranha/
    pushd /opt/piranha >/dev/null
    [[ "$PKG_ARC" == *.zip ]] && unzip -o "$(basename "$PKG_ARC")" || tar -xzf "$(basename "$PKG_ARC")"
    popd >/dev/null
  else
    if [[ ! -d /opt/piranha/.git ]]; then
      rm -rf /opt/piranha/*
      git clone https://github.com/williamjsmail/piranha /opt/piranha
    fi
  fi

  [[ -f /opt/piranha/piranha.py ]] || { echo "Piranha sources missing under /opt/piranha"; exit 1; }

  python3 -m venv /opt/piranha/.venv || python3 -m virtualenv /opt/piranha/.venv
  /opt/piranha/.venv/bin/pip install --upgrade pip >/dev/null 2>&1 || true
  if [[ -f /opt/piranha/requirements.txt ]]; then
    pip_cached_install "/opt/piranha/.venv/bin" -r /opt/piranha/requirements.txt
  fi

  FEIX="$(ls "'"$LOAD_PATCH_DIR"'"/*patch.py 2>/dev/null | sort -V | tail -1)"
  if [[ -n "$FEIX" ]]; then
    rm -f /opt/piranha/backend/loader.py
    cp "$FEIX" /opt/piranha/backend/loader.py || true
  fi

  # Safer launcher: falls back to offscreen if DISPLAY is not usable
  cat >/usr/local/bin/piranha <<'\''EOF'\''
#!/usr/bin/env bash
set -euo pipefail
if [[ -z "${DISPLAY:-}" ]] || ! command -v xdpyinfo >/dev/null 2>&1 || ! xdpyinfo >/dev/null 2>&1; then
  echo "[wade] No working X11 DISPLAY detected; launching Piranha with QT_QPA_PLATFORM=offscreen" >&2
  export QT_QPA_PLATFORM=offscreen
fi
exec /opt/piranha/.venv/bin/python /opt/piranha/piranha.py "$@"
EOF
  chmod 0755 /usr/local/bin/piranha
  chown "'"${LWADEUSER}:${LWADEUSER}"'" /usr/local/bin/piranha || true
' || fail_note "piranha" "setup failed"
fi

#####################################
# Barracuda
#####################################

get_ver_barracuda(){
  [[ -x /usr/local/bin/barracuda && -d /opt/barracuda/.venv ]] || { echo ""; return; }
  [[ -f /opt/barracuda/enterprise-attack.json ]] && echo installed || echo ""
}
if [[ "${MOD_BARRACUDA_ENABLED:-1}" == "1" ]]; then
run_step "barracuda" "installed" get_ver_barracuda '
  set -e
  install -d /opt/barracuda
  chown -R "'"${LWADEUSER}:${LWADEUSER}"'" /opt/barracuda

  # --- source acquisition (online or offline) ---
  if [[ "$OFFLINE" == "1" ]]; then
    PKG_ARC="$(ls "'"${WADE_PKG_DIR}"'/barracuda"/"barracuda"*.tar.gz "'"${WADE_PKG_DIR}"'/barracuda"/"barracuda"*.zip 2>/dev/null | head -1 || true)"
    if [[ -z "$PKG_ARC" ]]; then
      PKG_ARC="$(ls "'"${WADE_PKG_DIR}"'/barracuda/barracuda*.tar.gz "'"${WADE_PKG_DIR}"'/barracuda/barracuda*.zip 2>/dev/null | head -1 || true)"
    fi
    [[ -n "$PKG_ARC" ]] || { echo "offline Barracuda archive missing"; exit 1; }
    cp "$PKG_ARC" /opt/barracuda/
    pushd /opt/barracuda >/dev/null
    if [[ "$PKG_ARC" == *.zip ]]; then unzip -o "$(basename "$PKG_ARC")"
    else tar -xzf "$(basename "$PKG_ARC")"
    fi
    popd >/dev/null
  else
    [[ -d /opt/barracuda/.git ]] || git clone https://github.com/williamjsmail/Barracuda /opt/barracuda || true
  fi

  [[ -f /opt/barracuda/app.py ]] || { echo "Barracuda sources missing under /opt/barracuda"; exit 1; }

  # --- venv + deps (make sure pandas and numpy are present) ---
  if [[ ! -d /opt/barracuda/.venv ]]; then
    python3 -m venv /opt/barracuda/.venv
  fi
  /opt/barracuda/.venv/bin/pip install -U pip setuptools wheel >/dev/null 2>&1 || true

  # Install repo requirements (if present) first
  if [[ -f /opt/barracuda/requirements.txt ]]; then
    pip_cached_install "/opt/barracuda/.venv/bin" -r /opt/barracuda/requirements.txt
  fi
  # Ensure hard deps that often aren’t listed
  pip_cached_install "/opt/barracuda/.venv/bin" pandas numpy

  # --- MITRE CTI file path fix + acquisition ---
  if [[ ! -f /opt/barracuda/enterprise-attack.json ]]; then
    if [[ -f "'"${WADE_PKG_DIR}"'/mitre/enterprise-attack.json" ]]; then
      cp "'"${WADE_PKG_DIR}"'/mitre/enterprise-attack.json" /opt/barracuda/enterprise-attack.json
    elif [[ "$OFFLINE" == "1" && -f "'"${OFFLINE_SRC}"'/mitre/enterprise-attack.json" ]]; then
      cp "'"${OFFLINE_SRC}"'/mitre/enterprise-attack.json" /opt/barracuda/enterprise-attack.json
    else
      curl -fsSL https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json \
        -o /opt/barracuda/enterprise-attack.json
    fi
  fi

  # Force app to use the absolute CTI path
  sed -i -E \
    '\''s|load_techniques_enriched\("enterprise-attack\.json"\)|load_techniques_enriched("/opt/barracuda/enterprise-attack.json")|'\'' \
    /opt/barracuda/app.py || true

  install -d -o "'"${LWADEUSER}"'" -g "'"${LWADEUSER}"'" -m 0750 /opt/barracuda/uploads

  # CLI shim
  cat >/usr/local/bin/barracuda <<'\''EOF'\''
#!/usr/bin/env bash
set -euo pipefail
export QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-offscreen}"   # headless-safe
cd /opt/barracuda
exec /opt/barracuda/.venv/bin/python /opt/barracuda/app.py "$@"
EOF
  chmod 0755 /usr/local/bin/barracuda

  # systemd service (kept, runs headless)
  cat >/etc/systemd/system/barracuda.service <<EOF
[Unit]
Description=WADE Barracuda (DFIR helper)
After=network-online.target
Wants=network-online.target
ConditionPathExists=/opt/barracuda/.venv/bin/python
ConditionPathExists=/opt/barracuda/app.py

[Service]
Type=simple
User=${LWADEUSER}
Group=${LWADEUSER}
WorkingDirectory=/opt/barracuda
EnvironmentFile=-/etc/wade/wade.env
Environment=PYTHONUNBUFFERED=1
Environment=QT_QPA_PLATFORM=offscreen
ExecStart=/opt/barracuda/.venv/bin/python /opt/barracuda/app.py
Restart=on-failure
RestartSec=5s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF

  systemd_queue_enable barracuda.service
' || fail_note "barracuda" "setup failed"
fi

#####################################
# Hayabusa
#####################################

if [[ "${MOD_HAYABUSA_ENABLED:-1}" == "1" ]]; then
run_step "hayabusa" "" get_ver_hayabusa '
  set -e
  echo "[*] Installing Hayabusa…"
  install -d "$(dirname "${HAYABUSA_DEST}")"

  HAY_ARCH="${HAY_ARCH:-$(detect_hayabusa_arch)}"
  HAY_ZIP=""

  # look in WADE_PKG_DIR first
  HAY_ZIP_LOCAL="$(ls "${WADE_PKG_DIR}/hayabusa"/hayabusa-*-"${HAY_ARCH:-}".zip 2>/dev/null | sort -V | tail -1 || true)"

  if [[ -n "$HAY_ZIP_LOCAL" ]]; then
    cp "$HAY_ZIP_LOCAL" .
    HAY_ZIP="$(basename "$HAY_ZIP_LOCAL")"

  elif [[ "$OFFLINE" == "1" ]]; then
    HAY_ZIP_USB="$(ls "${OFFLINE_SRC}/hayabusa"/hayabusa-*-"${HAY_ARCH:-}".zip 2>/dev/null | sort -V | tail -1 || true)"
    [[ -n "$HAY_ZIP_USB" ]] || { echo "Hayabusa zip for arch '"'"'${HAY_ARCH:-}'"'"' not found offline"; exit 1; }
    cp "$HAY_ZIP_USB" .
    HAY_ZIP="$(basename "$HAY_ZIP_USB")"

  else
    if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
      echo "[*] Downloading latest Hayabusa release for ${HAY_ARCH:-}…"

      # Get latest release JSON from GitHub
      JSON="$(curl -fsSL https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest)"

      # Map our arch tokens to matching asset names
      case "${HAY_ARCH:-$(detect_hayabusa_arch)}" in
        linux-x64)   ARCH_RE="x86_64|amd64|x64" ;;
        linux-arm64) ARCH_RE="aarch64|arm64"    ;;
        *)           ARCH_RE="x86_64|amd64|x64" ;;
      esac

      # Use jq without inner single quotes (so it plays nice with the outer run_step quotes)
      DL_URL="$(
        jq -r --arg archre "$ARCH_RE" \
          "[ .assets[]
              | select(
                  (.name | test(\"(?i)(^|[-_])lin(ux)?([-_]|$)\")) and
                  (.name | test(\$archre)) and
                  (.name | test(\"\\.zip$\")) 
                )
           ]
           | ( map(select(.name | test(\"(?i)gnu\"))) + map(select(.name | test(\"(?i)musl\"))) )
           | .[0].browser_download_url // empty" \
          <<< "$JSON"
      )"

      [[ -n "$DL_URL" ]] || { echo "Could not resolve a Linux asset for arch regex ${ARCH_RE}"; exit 1; }

      HAY_ZIP="$(basename "$DL_URL")"
      curl -fL "$DL_URL" -o "$HAY_ZIP"
    else
      echo "curl/jq required to auto-fetch Hayabusa online"; exit 1
    fi
  fi

  # --- Extract & verify arch before install ---
  TMPDIR="$(mktemp -d)"; cleanup(){ rm -rf "$TMPDIR"; }; trap cleanup EXIT
  bsdtar -xf "$HAY_ZIP" -C "$TMPDIR"

  HAY_BIN_PATH="$(find "$TMPDIR" -type f -name "hayabusa*" ! -name "*.exe" | head -1 || true)"
  if [[ -z "$HAY_BIN_PATH" ]]; then
    echo "Hayabusa binary not found in ${HAY_ZIP}"
    find "$TMPDIR" -maxdepth 3 -type f -printf "  %P\n"
    exit 1
  fi

  if ! file "$HAY_BIN_PATH" | grep -qiE "ELF 64-bit.*(x86-64|aarch64)"; then
    echo "Downloaded binary is not the right CPU arch for this host ($(uname -m))"
    exit 1
  fi

  install -m 0755 "$HAY_BIN_PATH" "${HAYABUSA_DEST}"
  echo "[+] Installed Hayabusa to ${HAYABUSA_DEST}"

  install -d -m 0755 "${HAYABUSA_RULES_DIR}"
  [[ -d "$TMPDIR/rules"  ]] && { cp -r "$TMPDIR/rules/"*  "${HAYABUSA_RULES_DIR}/"; echo "[+] Copied Hayabusa rules → ${HAYABUSA_RULES_DIR}"; }

  mkdir -p /etc/wade/hayabusa
  [[ -d "$TMPDIR/config" ]] && { cp -r "$TMPDIR/config"/* /etc/wade/hayabusa/; echo "[+] Copied Hayabusa config → /etc/wade/hayabusa/"; }

  # (kept on purpose for your convenience)
  [[ -d "$TMPDIR/rules"  ]] && { cp -r "$TMPDIR/rules"  /usr/local/bin/; echo "[+] Copied Hayabusa rules/ to /usr/local/bin/rules"; }
  [[ -d "$TMPDIR/config" ]] && { cp -r "$TMPDIR/config" /usr/local/bin/; echo "[+] Copied Hayabusa config/ to /usr/local/bin/config"; }

  "${HAYABUSA_DEST}" --help >/dev/null 2>&1 || { echo "Hayabusa post-install test failed"; exit 1; }
' || fail_note "hayabusa" "binary/rules copy failed"
fi

#####################################
# ZooKeeper (pinned; soft-fail)
#####################################
run_step "zookeeper" "${ZOOKEEPER_VER}" get_ver_zk '
  set -e
  ZOOKEEPER_TGZ="apache-zookeeper-${ZOOKEEPER_VER}-bin.tar.gz"
  fetch_pkg zookeeper "$ZOOKEEPER_TGZ" || curl -L "https://archive.apache.org/dist/zookeeper/zookeeper-${ZOOKEEPER_VER}/${ZOOKEEPER_TGZ}" -o "$ZOOKEEPER_TGZ"
  [[ -f "$ZOOKEEPER_TGZ" ]] || { echo "ZooKeeper tarball missing"; exit 1; }
  id zookeeper >/dev/null 2>&1 || useradd --system -s /usr/sbin/nologin zookeeper
  mkdir -p /opt/zookeeper /var/lib/zookeeper
  tar -xzf "$ZOOKEEPER_TGZ" -C /opt/zookeeper --strip-components 1
  cat >/opt/zookeeper/conf/zoo.cfg <<'"'"'EOF'"'"'
tickTime=2000
dataDir=/var/lib/zookeeper
clientPort=2181
maxClientCnxns=60
4lw.commands.whitelist=mntr,conf,ruok
EOF
  chown -R zookeeper:zookeeper /opt/zookeeper /var/lib/zookeeper
  cat >/etc/systemd/system/zookeeper.service <<'"'"'EOF'"'"'
[Unit]
Description=Zookeeper Daemon
After=network.target
[Service]
Type=forking
WorkingDirectory=/opt/zookeeper
User=zookeeper
Group=zookeeper
ExecStart=/opt/zookeeper/bin/zkServer.sh start /opt/zookeeper/conf/zoo.cfg
ExecStop=/opt/zookeeper/bin/zkServer.sh stop /opt/zookeeper/conf/zoo.cfg
ExecReload=/opt/zookeeper/bin/zkServer.sh restart /opt/zookeeper/conf/zoo.cfg
TimeoutSec=30
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
  systemd_queue_enable zookeeper
  systemctl start zookeeper.service
' || fail_note "zookeeper" "install/config failed"

#####################################
# Solr (pinned; soft-fail)
#####################################
run_step "solr" "${SOLR_VER}" get_ver_solr '
  sudo apt-get install -y openjdk-11-jre-headless
  set -e
  SOLR_TGZ="solr-${SOLR_VER}.tgz"
  fetch_pkg solr "$SOLR_TGZ" || curl -L "https://archive.apache.org/dist/lucene/solr/${SOLR_VER}/${SOLR_TGZ}" -o "$SOLR_TGZ"
  [[ -f "$SOLR_TGZ" ]] || { echo "Solr tgz missing"; exit 1; }
  tar -xvzf "$SOLR_TGZ" "solr-${SOLR_VER}/bin/install_solr_service.sh" --strip-components=2
  bash ./install_solr_service.sh "$SOLR_TGZ" || true
  IPV4=$(hostname -I 2>/dev/null | awk '"'"'{print $1}'"'"')
  sed -i "s/^#\?SOLR_HEAP=.*/SOLR_HEAP=\"${SOLR_HEAP}\"/" /etc/default/solr.in.sh
  sed -i "s|^#\?SOLR_JAVA_MEM=.*|SOLR_JAVA_MEM=\"${SOLR_JAVA_MEM}\"|" /etc/default/solr.in.sh
  if grep -q "^#\?ZK_HOST=" /etc/default/solr.in.sh; then
    sed -i "s|^#\?ZK_HOST=.*|ZK_HOST=\"${SOLR_ZK_HOST}\"|" /etc/default/solr.in.sh
  else
    echo "ZK_HOST=\"${SOLR_ZK_HOST}\"" >> /etc/default/solr.in.sh
  fi
  sed -i "s|^#\?SOLR_JETTY_HOST=.*|SOLR_JETTY_HOST=\"${IPV4}\"|" /etc/default/solr.in.sh
  systemctl restart solr


  # After service start:
  if solr_wait_ready; then
    echo "[OK] Solr responded to /admin/info/system"
  else
    echo "[!] Solr did not become ready in time; check logs:"
    echo "    tail -n 200 /var/solr/logs/solr.log"
  fi

  AUTOPSY_ZIP="SOLR_8.6.3_AutopsyService.zip"
  fetch_pkg autopsy "$AUTOPSY_ZIP" || curl -L "https://sourceforge.net/projects/autopsy/files/CollaborativeServices/Solr/${AUTOPSY_ZIP}/download" -o "$AUTOPSY_ZIP"
  [[ -f "$AUTOPSY_ZIP" ]] || { echo "Autopsy Solr config zip missing"; exit 1; }
  mkdir -p /opt/autopsy-solr; unzip -o "$AUTOPSY_ZIP" -d /opt/autopsy-solr >/dev/null
  CONF_DIR=$(find /opt/autopsy-solr -type d -path "*/AutopsyConfig/conf" | head -1 || true)
  chown -R solr:solr /opt/autopsy-solr
  [[ -n "$CONF_DIR" ]] && sudo -u solr /opt/solr/bin/solr create_collection -c AutopsyConfig -d "$CONF_DIR" || true
' || fail_note "solr" "install/config failed"

#####################################
# ActiveMQ (pinned; soft-fail)
#####################################
run_step "activemq" "${ACTIVEMQ_VER}" get_ver_amq '
  set -e
  ACTIVEMQ_TGZ="apache-activemq-${ACTIVEMQ_VER}-bin.tar.gz"
  fetch_pkg activemq "$ACTIVEMQ_TGZ" || curl -L "https://archive.apache.org/dist/activemq/${ACTIVEMQ_VER}/${ACTIVEMQ_TGZ}" -o "$ACTIVEMQ_TGZ"
  [[ -f "$ACTIVEMQ_TGZ" ]] || { echo "ActiveMQ tarball missing"; exit 1; }
  id activemq >/dev/null 2>&1 || useradd --system -s /usr/sbin/nologin activemq
  mkdir -p /opt/activemq; tar -xzf "$ACTIVEMQ_TGZ" -C /opt/activemq --strip-components 1
  chown -R activemq:activemq /opt/activemq
  cat >/etc/systemd/system/activemq.service <<'"'"'EOF'"'"'
[Unit]
Description=Apache ActiveMQ
After=network.target
[Service]
Type=forking
User=activemq
Group=activemq
ExecStart=/opt/activemq/bin/activemq start
ExecStop=/opt/activemq/bin/activemq stop
[Install]
WantedBy=multi-user.target
EOF
  systemd_queue_enable activemq
' || fail_note "activemq" "install/config failed"

#####################################
# PostgreSQL (Ubuntu path; soft-fail)
#####################################
run_step "postgresql" "configured" get_ver_pg '
  set -e
  if [[ "$PM" == "apt" ]]; then
    systemctl enable postgresql || true
    PG_VER=$(psql -V | awk "{print \$3}" | cut -d. -f1)
    PG_DIR="/etc/postgresql/${PG_VER}/main"
    sed -ri "s/^#?fsync\s*=.*/fsync = ${PG_PERF_FSYNC}/" "${PG_DIR}/postgresql.conf"
    sed -ri "s/^#?synchronous_commit\s*=.*/synchronous_commit = ${PG_PERF_SYNCCOMMIT}/" "${PG_DIR}/postgresql.conf"
    sed -ri "s/^#?full_page_writes\s*=.*/full_page_writes = ${PG_PERF_FULLPAGE}/" "${PG_DIR}/postgresql.conf"
    grep -q "listen_addresses" "${PG_DIR}/postgresql.conf" && \
      sed -ri "s/^#?listen_addresses\s*=.*/listen_addresses = '"'"'${PG_LISTEN_ADDR}'"'"'/" "${PG_DIR}/postgresql.conf" \
      || echo "listen_addresses = '"'"'${PG_LISTEN_ADDR}'"'"'" >> "${PG_DIR}/postgresql.conf"
    for net in ${ALLOW_NETS_CSV//,/ }; do
      grep -qE "^\s*host\s+all\s+all\s+${net}\s+md5" "${PG_DIR}/pg_hba.conf" || echo "host all all ${net} md5" >> "${PG_DIR}/pg_hba.conf"
    done
    systemctl restart postgresql || true
  fi
' || fail_note "postgresql" "install/config failed"

#####################################
# STIG prerequisites (OpenSCAP + SSG)
#####################################
get_ver_stig_pkgs() {
  if [[ "$PM" == "apt" ]]; then
    dpkg -s openscap-scanner ssg-base ssg-debderived ssg-debian ssg-nondebian ssg-applications >/dev/null 2>&1 \
      && echo "installed" || echo ""
  else
    rpm -q openscap-scanner scap-security-guide >/dev/null 2>&1 && echo "installed" || echo ""
  fi
}

if [[ "${MOD_STIG_EVAL_ENABLED:-0}" == "1" ]]; then
run_step "stig-prereqs" "installed" get_ver_stig_pkgs '
  set -e
  if [[ "$PM" == "apt" ]]; then
    bash -lc "apt-cache show scap-security-guide >/dev/null 2>&1 && $PKG_INSTALL scap-security-guide || true"
  else
    true
  fi
' || fail_note "stig" "could not install prerequisites"
fi

#####################################
# Splunk Universal Forwarder (UF-only)
#####################################
run_step "splunk-uf" "installed" get_ver_splunkuf '
  set -e

  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y --no-install-recommends procps curl || true
  fi

  id splunkfwd >/dev/null 2>&1 || useradd --system --home-dir /opt/splunkforwarder --shell /usr/sbin/nologin splunkfwd || true

  PKG=""   # initialize to satisfy `set -u`

  if [[ -n "${SPLUNK_UF_DEB_URL:-}" ]]; then
    PKG="/tmp/$(basename "${SPLUNK_UF_DEB_URL}")"
    curl -L "${SPLUNK_UF_DEB_URL}" -o "$PKG"
  elif ls "${WADE_PKG_DIR:-/var/wade/pkg}"/splunkforwarder/*.deb >/dev/null 2>&1; then
    PKG="$(ls "${WADE_PKG_DIR:-/var/wade/pkg}"/splunkforwarder/*.deb | sort -V | tail -1)"
  elif [[ -n "${SPLUNK_SRC_DIR:-}" ]] && ls "${SPLUNK_SRC_DIR}"/splunkforwarder*.deb >/dev/null 2>&1; then
    PKG="$(ls "${SPLUNK_SRC_DIR}"/splunkforwarder*.deb | sort -V | tail -1)"
  fi

  if [[ -z "${PKG:-}" || ! -f "${PKG:-/dev/null}" ]]; then
    echo "[!] No UF .deb provided. Set SPLUNK_UF_DEB_URL or place a .deb under ${WADE_PKG_DIR:-/var/wade/pkg}/splunkforwarder/"
    exit 0
  fi

  dpkg -i "$PKG" || apt-get -f install -y

  /opt/splunkforwarder/bin/splunk enable boot-start -systemd-managed 1 -user splunkfwd --accept-license --answer-yes || true

  SERVER_LINE="${SPLUNK_UF_RCVR_HOSTS:-splunk.example.org:9997}"
  DEFAULT_INDEX="${SPLUNK_UF_DEFAULT_INDEX:-${SPLUNK_DEFAULT_INDEX:-wade_custom}}"
  COMPRESSED="${SPLUNK_UF_COMPRESSED:-true}"
  USE_ACK="${SPLUNK_UF_USE_ACK:-true}"
  SSL_VERIFY="${SPLUNK_UF_SSL_VERIFY:-false}"
  SSL_CN="${SPLUNK_UF_SSL_COMMON_NAME:-*}"
  DS_TARGET="${SPLUNK_UF_DEPLOYMENT_SERVER:-}"

  if [[ "${PRESET_SPLUNK:-0}" -eq 1 ]]; then
    SERVER_LINE="${PRESET_SPLUNK_SERVER_LINE:-$SERVER_LINE}"
    DEFAULT_INDEX="${PRESET_SPLUNK_INDEX:-$DEFAULT_INDEX}"
    COMPRESSED="${PRESET_SPLUNK_COMPRESSED:-$COMPRESSED}"
    USE_ACK="${PRESET_SPLUNK_USEACK:-$USE_ACK}"
    SSL_VERIFY="${PRESET_SPLUNK_SSL_VERIFY:-$SSL_VERIFY}"
    SSL_CN="${PRESET_SPLUNK_SSL_CN:-$SSL_CN}"
    DS_TARGET="${PRESET_SPLUNK_DS:-$DS_TARGET}"
  fi

  mkdir -p /opt/splunkforwarder/etc/system/local

  cat >/opt/splunkforwarder/etc/system/local/outputs.conf <<EOF
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = ${SERVER_LINE}
compressed = ${COMPRESSED}
useACK = ${USE_ACK}
EOF

  if [[ "$SSL_VERIFY" == "true" ]]; then
    cat >>/opt/splunkforwarder/etc/system/local/outputs.conf <<EOF
sslVerifyServerCert = true
sslCommonNameToCheck = ${SSL_CN}
EOF
  fi

  if [[ -n "$DS_TARGET" ]]; then
    cat >/opt/splunkforwarder/etc/system/local/deploymentclient.conf <<EOF
[deployment-client]
clientName = wade-uf

[target-broker:deploymentServer]
targetUri = ${DS_TARGET}
EOF
  fi

  systemctl enable --now SplunkForwarder.service 2>/dev/null || systemctl enable --now splunkforwarder.service || true
' || fail_note "splunk-uf" "install/config failed"

#####################################
# WADE Workers
#####################################
install -d -m 0755 /opt/wade/wade_workers/bin
rsync -a "${SCRIPT_DIR}/wade_workers/wade_workers/" /opt/wade/wade_workers/
rsync -a "${SCRIPT_DIR}/wade_workers/bin/" /opt/wade/wade_workers/bin/

# Runner systemd
cat >/etc/systemd/system/wade-queue@.service <<'EOF'
[Unit]
Description=WADE Queue Runner (%i)
Wants=network-online.target
After=network-online.target
ConditionPathExists=/opt/wade/wade_workers/bin/wade_queue_runner.py

[Service]
Type=simple
User=%i
Group=%i
EnvironmentFile=-/etc/wade/wade.env
WorkingDirectory=/opt/wade/wade_workers
ExecStart=/usr/bin/env python3 /opt/wade/wade_workers/bin/wade_queue_runner.py
Restart=always
RestartSec=2
UMask=002
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=false
ReadWritePaths=/home/%i /var/wade

[Install]
WantedBy=multi-user.target
EOF

# Ensure logs dir exists
install -d -m 0775 /var/wade/logs/workers
chown -R autopsy:autopsy /var/wade /opt/wade

systemd_queue_enable wade-queue@autopsy.service

# ---- Splunk UF inputs overlay (if UF installed)
if [[ -d "/opt/splunkforwarder/etc/apps/TA-wade-uf" ]]; then
  install -d -m 0755 /opt/splunkforwarder/etc/apps/TA-wade-uf/local
  cat >/opt/splunkforwarder/etc/apps/TA-wade-uf/local/inputs.conf <<'EOF'
# (inputs overlay from Phase 2)
EOF
  /opt/splunkforwarder/bin/splunk restart || true
fi

#####################################
# WHIFF (install & configure)
#####################################
# Decide final values (prompted if interactive; else defaults from wade.conf/env)
WHIFF_ENABLE_EFF="${PRESET_WHIFF_ENABLE:-${WHIFF_ENABLE:-1}}"
WHIFF_BIND_EFF="${PRESET_WHIFF_BIND:-${WHIFF_BIND_ADDR:-127.0.0.1}}"
WHIFF_PORT_EFF="${PRESET_WHIFF_PORT:-${WHIFF_PORT:-8088}}"
WHIFF_BACKEND_EFF="${PRESET_WHIFF_BACKEND:-${WHIFF_BACKEND:-ollama}}"
WHIFF_MODEL_EFF="${PRESET_WHIFF_MODEL:-${WHIFF_MODEL:-llama3.1:8b-instruct}}"
WHIFF_ENDPOINT_EFF="${PRESET_WHIFF_ENDPOINT:-${WHIFF_ENDPOINT:-}}"
WHIFF_API_KEY_EFF="${PRESET_WHIFF_API_KEY:-${WHIFF_API_KEY:-}}"

if [[ "${WHIFF_ENABLE_EFF}" == "1" ]]; then
  echo "[*] Installing/configuring WHIFF…"
  # If install_whiff.sh uses pip, allow it to leverage our wheelhouse via env
  env \
    PIP_FIND_LINKS="${WADE_PKG_DIR:-/var/wade/pkg}/pipwheels" \
    PIP_NO_INDEX=0 \
    WHIFF_ENABLE="1" \
    WHIFF_BIND_ADDR="${WHIFF_BIND_EFF}" \
    WHIFF_PORT="${WHIFF_PORT_EFF}" \
    WHIFF_BACKEND="${WHIFF_BACKEND_EFF}" \
    WHIFF_MODEL="${WHIFF_MODEL_EFF}" \
    WHIFF_ENDPOINT="${WHIFF_ENDPOINT_EFF}" \
    WHIFF_API_KEY="${WHIFF_API_KEY_EFF}" \
    bash "${SCRIPT_DIR}/WHIFF/install_whiff.sh" || warn_note "whiff" "install reported issues"
else
  echo "[*] WHIFF disabled by user choice."
fi

#####################################
# WADE: logrotate setup (per-service)
#####################################
_wade_ensure_logrotate() {
  if command -v logrotate >/dev/null 2>&1; then return 0; fi
  if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y logrotate >/dev/null 2>&1 || true
  fi
}
_wade_default_logdir_for_service() {
  local svc="$1"
  local base="${svc#wade-}"
  printf "/var/wade/logs/%s" "${base}"
}
install_wade_logrotate() {
  local svc="${1:?service name required}"
  local logdir="${2:-$(_wade_default_logdir_for_service "$svc")}"
  local user="${3:-autopsy}"
  local group="${4:-$user}"
  local rotate_count="${5:-14}"
  local period="${6:-daily}"
  local method="${7:-signal:USR1}"

  echo "[wade] configuring logrotate for ${svc} → ${logdir}"

  _wade_ensure_logrotate

  mkdir -p "${logdir}"
  if id -u "${user}" >/dev/null 2>&1 && getent group "${group}" >/dev/null 2>&1; then
    chown -R "${user}:${group}" "${logdir}" || true
  else
    echo "[wade] note: user/group ${user}:${group} not present; defaulting to root:root for ${logdir}"
    user="root"; group="root"
    chown -R root:root "${logdir}" || true
  fi
  chmod 0750 "${logdir}" || true

  if [[ "${method}" == signal:* ]]; then
    local sig="${method#signal:}"
    mkdir -p "/etc/systemd/system/${svc}.service.d"
    cat > "/etc/systemd/system/${svc}.service.d/logrotate-reload.conf" <<EOF
[Service]
ExecReload=
ExecReload=/bin/kill -s ${sig} \$MAINPID
EOF
  fi

  local postrotate_cmd
  if [[ "${method}" == copytruncate ]]; then
    postrotate_cmd=": # no signal; using copytruncate"
  else
    local sig="${method#signal:}"
    postrotate_cmd="systemctl kill -s ${sig} ${svc}.service 2>/dev/null || true"
  fi

  local policy="/etc/logrotate.d/${svc}"
  cat > "${policy}" <<EOF
${logdir%/}/*.log {
  ${period}
  rotate ${rotate_count}
  compress
  missingok
  notifempty
  su ${user} ${group}
  create 0640 ${user} ${group}
  sharedscripts
$( [[ "${method}" == copytruncate ]] && echo "  copytruncate" )
  postrotate
    ${postrotate_cmd}
  endscript
}
EOF

  chmod 0644 "${policy}"
  chown root:root "${policy}"
}

install_wade_logrotate "wade-mw-extractor" "/var/wade/logs/malware" "${LWADEUSER:-autopsy}" "${LWADEUSER:-autopsy}" 14 "weekly" "copytruncate"
install_wade_logrotate "wade-staging" "/var/wade/logs/stage" "${LWADEUSER:-autopsy}" "${LWADEUSER:-autopsy}" 14 "daily" "copytruncate"

#####################################
# Persist facts & endpoints
#####################################
ENV_FILE="${WADE_ETC}/wade.env"
IPV4="$(hostname -I 2>/dev/null | awk '{print $1}')"

OUTCONF="/opt/splunkforwarder/etc/system/local/outputs.conf"
INCONF="/opt/splunkforwarder/etc/system/local/inputs.conf"
DCONF="/opt/splunkforwarder/etc/system/local/deploymentclient.conf"

UF_RCVR=""; UF_COMP=""; UF_ACKS=""; UF_SSLV=""; UF_SSLN=""; UF_DS=""; UF_IDX=""

# Only parse if the file exists; also add `|| true` to suppress ERR trap
if [[ -r "$OUTCONF" ]]; then
  UF_RCVR="$(awk -F= '/^\s*server\s*=/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' "$OUTCONF" 2>/dev/null || true)"
  UF_COMP="$(awk -F= '/^\s*compressed\s*=/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print tolower($2); exit}' "$OUTCONF" 2>/dev/null || true)"
  UF_ACKS="$(awk -F= '/^\s*useACK\s*=/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print tolower($2); exit}' "$OUTCONF" 2>/dev/null || true)"
  UF_SSLV="$(awk -F= '/^\s*sslVerifyServerCert\s*=/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print tolower($2); exit}' "$OUTCONF" 2>/dev/null || true)"
  UF_SSLN="$(awk -F= '/^\s*sslCommonNameToCheck\s*=/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' "$OUTCONF" 2>/dev/null || true)"
fi
if [[ -r "$DCONF" ]]; then
  UF_DS="$(awk -F= '/^\s*targetUri\s*=/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' "$DCONF" 2>/dev/null || true)"
fi
if [[ -r "$INCONF" ]]; then
  UF_IDX="$(awk -F= '/^\s*index\s*=/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}' "$INCONF" 2>/dev/null || true)"
fi

UF_RCVR="${UF_RCVR:-${SPLUNK_UF_RCVR_HOSTS:-${SPLUNK_UF_RCVR_HOST:-}}}"
UF_COMP="${UF_COMP:-${SPLUNK_UF_COMPRESSED:-true}}"
UF_ACKS="${UF_ACKS:-${SPLUNK_UF_USE_ACK:-true}}"
UF_SSLV="${UF_SSLV:-${SPLUNK_UF_SSL_VERIFY:-false}}"
UF_SSLN="${UF_SSLN:-${SPLUNK_UF_SSL_COMMON_NAME:-*}}"
UF_DS="${UF_DS:-${SPLUNK_UF_DEPLOYMENT_SERVER:-}}"
UF_IDX="${UF_IDX:-${SPLUNK_UF_DEFAULT_INDEX:-${SPLUNK_DEFAULT_INDEX:-wade_custom}}}"

cat > "$ENV_FILE" <<ENV
# ===== WADE runtime facts =====
WADE_HOSTNAME="${LWADE}"
WADE_HOST_IPV4="${IPV4}"
WADE_OWNER_USER="${LWADEUSER}"
WADE_SMB_USERS="${SMB_USERS_CSV}"
WADE_ALLOW_NETS="${ALLOW_NETS_CSV}"

# Directories
WADE_DATADIR="${WADE_DATADIR}"
WADE_CASESDIR="${WADE_CASESDIR}"
WADE_STAGINGDIR="${WADE_STAGINGDIR}"
WADE_LOG_DIR="${WADE_LOG_DIR}"
WADE_PKG_DIR="${WADE_PKG_DIR}"
WADE_TOOLS_DIR="${WADE_TOOLS_DIR}"
WADE_PIPELINES_DIR="${WADE_PIPELINES_DIR}"

# Splunk settings (UF actuals if present, else defaults)
SPLUNK_DEFAULT_INDEX="${SPLUNK_DEFAULT_INDEX:-wade_custom}"
SPLUNK_UF_RCVR_HOSTS="${UF_RCVR}"
SPLUNK_UF_DEFAULT_INDEX="${UF_IDX}"
SPLUNK_UF_COMPRESSED="${UF_COMP}"
SPLUNK_UF_USE_ACK="${UF_ACKS}"
SPLUNK_UF_SSL_VERIFY="${UF_SSLV}"
SPLUNK_UF_SSL_COMMON_NAME="${UF_SSLN}"
SPLUNK_UF_DEPLOYMENT_SERVER="${UF_DS}"

# Hayabusa locations
HAYABUSA_DEST="${HAYABUSA_DEST}"
HAYABUSA_RULES_DIR="${HAYABUSA_RULES_DIR}"
SIGMA_RULES_DIR="${SIGMA_RULES_DIR}"

# Staging safety & performance
WADE_STAGE_STABLE_SECONDS=180
WADE_STAGE_REQUIRE_CLOSE_WRITE=1
WADE_STAGE_VERIFY_NO_WRITERS=1
WADE_STAGE_RECURSIVE=1
WADE_STAGE_ACCEPT_DOCS=1
WADE_STAGE_SMALL_FILE_BYTES=2097152
WADE_STAGE_SMALL_FILE_STABLE=5

# Offline flag
OFFLINE="${OFFLINE}"

# Queue 
WADE_QUEUE_DIR=_queue

# WHIFF (non-secret settings)
WHIFF_ENABLE="${WHIFF_ENABLE_EFF}"
WHIFF_BIND_ADDR="${WHIFF_BIND_EFF}"
WHIFF_PORT="${WHIFF_PORT_EFF}"
WHIFF_BACKEND="${WHIFF_BACKEND_EFF}"
WHIFF_MODEL="${WHIFF_MODEL_EFF}"
WHIFF_ENDPOINT="${WHIFF_ENDPOINT_EFF}"

# Derived convenience URL used by dashboards/integrations
WHIFF_URL="http://${WHIFF_BIND_ADDR}:${WHIFF_PORT}/annotate"

# NOTE: If you must persist tokens (NOT RECOMMENDED), uncomment the next line and paste carefully.
# WHIFF_API_KEY="<REDACTED>"

# ===== Network ports in use =====
SSH_PORT="22"
SMB_TCP_139="139"
SMB_TCP_445="445"
SMB_UDP_137="137"
SMB_UDP_138="138"
ZK_CLIENT_PORT="2181"
ZK_QUORUM_PORT="2888"
ZK_ELECTION_PORT="3888"
SOLR_PORT="8983"
ACTIVEMQ_OPENWIRE_PORT="61616"
ACTIVEMQ_WEB_CONSOLE_PORT="8161"
ACTIVEMQ_AMQP_PORT="5672"
ACTIVEMQ_STOMP_PORT="61613"
ACTIVEMQ_MQTT_PORT="1883"
ACTIVEMQ_WS_PORT="61614"
POSTGRES_PORT="5432"
PIRANHA_PORT="5001"
BARRACUDA_PORT="5000"
SPLUNK_WEB_PORT="\${SPLUNK_WEB_PORT}"
SPLUNK_MGMT_PORT="\${SPLUNK_MGMT_PORT}"
SPLUNK_HEC_PORT="\${SPLUNK_HEC_PORT}"
SPLUNK_FORWARD_PORT="\${SPLUNK_FORWARD_PORT}"

WADE_SERVICE_PORTS_CSV="\${SSH_PORT},\${SMB_TCP_139},\${SMB_TCP_445},\${SMB_UDP_137},\${SMB_UDP_138},\${ZK_CLIENT_PORT},\${ZK_QUORUM_PORT},\${ZK_ELECTION_PORT},\${SOLR_PORT},\${ACTIVEMQ_OPENWIRE_PORT},\${ACTIVEMQ_WEB_CONSOLE_PORT},\${ACTIVEMQ_AMQP_PORT},\${ACTIVEMQ_STOMP_PORT},\${ACTIVEMQ_MQTT_PORT},\${ACTIVEMQ_WS_PORT},\${POSTGRES_PORT},\${PIRANHA_PORT},\${BARRACUDA_PORT},\${WHIFF_PORT},\${SPLUNK_WEB_PORT},\${SPLUNK_MGMT_PORT},\${SPLUNK_HEC_PORT},\${SPLUNK_FORWARD_PORT}"
ENV

chown root:"${LWADEUSER}" "$ENV_FILE"
chmod 0640 "$ENV_FILE"

echo
echo "[+] WADE install attempted."
echo "    Shares: //${IPV4}/${WADE_DATADIR} //${IPV4}/${WADE_CASESDIR} //${IPV4}/${WADE_STAGINGDIR}"
echo "    Zookeeper : 127.0.0.1:${ZK_CLIENT_PORT:-2181}"
echo "    Solr (UI) : http://${IPV4}:${SOLR_PORT:-8983}/solr/#/~cloud"
echo "    ActiveMQ  : ${IPV4}:${ACTIVEMQ_OPENWIRE_PORT:-61616} (web console :${ACTIVEMQ_WEB_CONSOLE_PORT:-8161})"
echo "    Postgres  : ${IPV4}:${POSTGRES_PORT:-5432}"
echo "    Barracuda : ${IPV4}:5000"
echo "    WHIFF     : $( [[ "$WHIFF_ENABLE_EFF" = "1" ]] && echo "http://${WHIFF_BIND_EFF}:${WHIFF_PORT_EFF}" || echo "disabled" )"
echo "    Tools     : vol3, dissect, bulk_extractor (+ piranha, barracuda, hayabusa, whiff)"
echo "    STIG      : reports (if run) under ${STIG_REPORT_DIR}"
echo "    Config    : ${WADE_ETC}/wade.conf (defaults), ${WADE_ETC}/wade.env (facts & ports)"
UF_PRESENT="no"
UF_OUT_TARGETS=""
UF_DS_TARGET=""
if [[ -x /opt/splunkforwarder/bin/splunk ]]; then
  UF_PRESENT="yes"
  UF_OUT_TARGETS="$(awk -F= '/^\s*server\s*=/ {gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2; exit}' /opt/splunkforwarder/etc/system/local/outputs.conf 2>/dev/null)"
  UF_DS_TARGET="$(awk -F= '/^\s*targetUri\s*=/ {gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2; exit}' /opt/splunkforwarder/etc/system/local/deploymentclient.conf 2>/dev/null)"
fi

if [[ "$UF_PRESENT" == "yes" ]]; then
  echo "    Splunk UF : forwarding to ${UF_OUT_TARGETS:-<not configured>} (DS: ${UF_DS_TARGET:-none})"
  echo "                compressed=${SPLUNK_UF_COMPRESSED:-${UF_COMP:-true}}, useACK=${SPLUNK_UF_USE_ACK:-${UF_ACKS:-true}}, sslVerify=${SPLUNK_UF_SSL_VERIFY:-${UF_SSLV:-false}}"
else
  echo "    Splunk UF : not installed"
fi
echo "    Log       : ${LOG_FILE}"
echo
echo "NOTE: New tools default to SPLUNK index: '${SPLUNK_DEFAULT_INDEX:-wade_custom}'."

#####################################
# Call The Doctor
#####################################
wade_doctor

#####################################
# Interactive STIG assessment (end; reads from ./stigs)
#####################################
stig_list_profiles() {
  local info
  info="$(oscap info "$1" 2>/dev/null || true)"

  {
    printf '%s\n' "$info" | awk '
      BEGIN{inside=0}
      /^[[:space:]]*Profiles:/ {inside=1; next}
      inside && /^[[:space:]]*Id:[[:space:]]*/ {
        sub(/^[[:space:]]*Id:[[:space:]]*/,"")
        print $1
      }
    '
    printf '%s\n' "$info" | sed -nE 's/^[[:space:]]*Profile[[:space:]]*:[[:space:]]*([[:alnum:]_.:-]+).*/\1/p'
    printf '%s\n' "$info" | sed -nE 's/^[[:space:]]*Profile.*\(([[:alnum:]_.:-]+)\).*/\1/p'
  } | awk 'NF' | sort -u
}

stig_pick_profile_interactive() {
  local ds="$1"
  mapfile -t PROFILES < <(stig_list_profiles "$ds")

  if [[ ${#PROFILES[@]} -eq 0 ]]; then
    >&2 echo "[!] No profiles parsed from 'oscap info'."
    >&2 echo "    Type a profile ID manually, or press Enter to use default:"
    >&2 echo "    Default: ${STIG_PROFILE_ID:-<none set>}"
    read -r -p "Profile ID: " manual
    [[ -n "$manual" ]] && { printf '%s\n' "$manual"; return 0; }
    [[ -n "${STIG_PROFILE_ID:-}" ]] && { printf '%s\n' "${STIG_PROFILE_ID}"; return 0; }
    return 1
  fi

  >&2 echo "Available profiles:"
  local i=1
  for p in "${PROFILES[@]}"; do >&2 printf "  %2d) %s\n" "$i" "$p"; ((i++)); done
  local def=1
  read -r -p "Choose profile [${def}]: " idx
  idx="${idx:-$def}"
  if ! [[ "$idx" =~ ^[0-9]+$ ]] || (( idx < 1 || idx > ${#PROFILES[@]} )); then
    >&2 echo "[!] Invalid selection."
    return 1
  fi
  printf '%s\n' "${PROFILES[$((idx-1))]}"
}

stig_skip_args() {
  local s="${STIG_SKIP_RULES:-}"; [[ -z "$s" ]] && return 0
  IFS=',' read -ra arr <<< "$s"
  for r in "${arr[@]}"; do echo -n " --skip-rule ${r}"; done
}

if [[ "${MOD_STIG_EVAL_ENABLED:-0}" == "1" && "$OS_ID" == "ubuntu" ]]; then
  echo
  echo "==> Optional: Run DISA STIG assessment now"
  echo "    Looking for STIG zips/XML under: ${STIG_SRC_DIR}"
  if [[ "$NONINTERACTIVE" -eq 1 ]]; then
    echo "    (NONINTERACTIVE mode: skipping STIG assessment prompt.)"
  else
    read -r -p "Run STIG assessment now? [y/N]: " __ans
    if [[ "$__ans" =~ ^[Yy]$ ]]; then
      install -d "${STIG_REPORT_DIR}" "${STIG_UBU_EXTRACT_DIR}"
      CAND_ZIP="$(ls -1 "${STIG_SRC_DIR}"/*.zip 2>/dev/null | sort -V | tail -1 || true)"
      CAND_XML="$(ls -1 "${STIG_SRC_DIR}"/*.xml "${STIG_SRC_DIR}"/*.XML 2>/dev/null | sort -V | tail -1 || true)"
      DS_FILE=""; TMP_EXTRACT=""

      if [[ -n "$CAND_ZIP" ]]; then
        echo "[*] Using ZIP: $(basename "$CAND_ZIP")"
        TMP_EXTRACT="$(mktemp -d)"
        unzip -oq "$CAND_ZIP" -d "$TMP_EXTRACT"
        for pat in '*-ds.xml' '*-datastream.xml' '*-xccdf.xml' '*Benchmark*.xml'; do
          DS_FILE="$(find "$TMP_EXTRACT" -type f -iname "$pat" | head -1 || true)"
          [[ -n "$DS_FILE" ]] && break
        done
      elif [[ -n "$CAND_XML" ]]; then
        echo "[*] Using XML: $(basename "$CAND_XML")"
        DS_FILE="$CAND_XML"
      fi

      if [[ -z "$DS_FILE" || ! -f "$DS_FILE" ]]; then
        echo "[!] No usable DISA STIG DS/XML found under ${STIG_SRC_DIR}."
        echo "    Put the official zip/XML there and re-run: ./install.sh --only=stig-prereqs"
        fail_note "stig-eval" "no DS/XML found"
      else
        CHOSEN_PROFILE="$(stig_pick_profile_interactive "$DS_FILE")" || { fail_note "stig-eval" "no profile chosen"; CHOSEN_PROFILE=""; }
        if [[ -n "$CHOSEN_PROFILE" ]]; then
          echo "[*] Running oscap with profile: ${CHOSEN_PROFILE}"
          SKIP_ARGS="$(stig_skip_args)"
          TS="$(date +%Y%m%d_%H%M%S)"
          REP_HTML="${STIG_REPORT_DIR}/stig-ubuntu-${OS_VER_ID}-${TS}.html"
          REP_ARF="${STIG_REPORT_DIR}/stig-ubuntu-${OS_VER_ID}-${TS}.arf.xml"
          if wade_oscap_eval xccdf eval --skip-valid ${SKIP_ARGS} \
                --profile "${CHOSEN_PROFILE}" \
                --results-arf "${REP_ARF}" \
                --report "${REP_HTML}" \
                "${DS_FILE}"
            ec=$?
            if [[ $ec -eq 0 || $ec -eq 1 ]]; then
                echo "[+] STIG report: ${REP_HTML}"
                echo "[+] STIG ARF   : ${REP_ARF}"
                cp -f "${DS_FILE}" "${STIG_UBU_EXTRACT_DIR}/ds.xml" 2>/dev/null || true
                mark_done "stig-eval" "$(sha256_of "${STIG_UBU_EXTRACT_DIR}/ds.xml" 2>/dev/null || echo run-${TS})"
            else
                fail_note "stig-eval" "oscap eval failed (exit ${ec})"
            fi
          fi
        fi
      fi
      [[ -n "$TMP_EXTRACT" ]] && rm -rf "$TMP_EXTRACT"
    fi
  fi
fi

# One-and-done systemd reload/enables
systemd_finalize_enable

finish_summary
