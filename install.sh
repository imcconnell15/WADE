#!/usr/bin/env bash
# WADE - Wide-Area Data Extraction :: Idempotent Installer (soft-fail + interactive STIG)
# Author: Ian McConnell

# NOTE: keep LF endings (use `dos2unix install.sh` if needed)

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

for arg in "${@:-}"; do
  case "$arg" in
    -y|--yes|--noninteractive) NONINTERACTIVE=1 ;;
    --check) CHECK_ONLY=1 ;;
    --force) FORCE_ALL=1 ;;
    --only=*) ONLY_LIST="${arg#--only=}" ;;
  esac
done

NONINTERACTIVE=${WADE_NONINTERACTIVE:-$NONINTERACTIVE}
OFFLINE="${OFFLINE:-0}"

#####################################
# Logging
#####################################
LOG_DIR="/var/log/wade"; mkdir -p "$LOG_DIR"
LOG_FILE="${LOG_DIR}/install_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

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

#####################################
# Idempotency framework (step registry)
#####################################
WADE_VAR_DEFAULT="/var/wade"
STEPS_DIR="${WADE_VAR_DEFAULT}/state/steps"; mkdir -p "$STEPS_DIR"

_inlist(){ local item="$1" list_csv="$2"; [[ -z "$list_csv" ]] && return 0; IFS=',' read -ra arr <<< "$list_csv"; for x in "${arr[@]}"; do [[ "$item" == "$x" ]] && return 0; done; return 1; }
mark_done(){ local step="$1" ver="$2"; shift 2 || true; printf '%s\n' "$ver" > "${STEPS_DIR}/${step}.ver"; [[ $# -gt 0 ]] && printf '%s\n' "$*" > "${STEPS_DIR}/${step}.note"; }
get_mark_ver(){ local step="$1" [[ -f "${STEPS_DIR}/${step}.ver" ]] && cat "${STEPS_DIR}/${step}.ver" || echo ""; }
report_step(){ printf " - %-16s want=%-12s have=%-14s [%s]\n" "$1" "${2:-n/a}" "${3:-n/a}" "$4"; }

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
  if ( set -e; eval "$do_install" ); then
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
    local n; n=$(find "$dir" -type f -name '*.yml' 2>/dev/null | wc -l | tr -d ' ')
    [[ "$n" =~ ^[0-9]+$ ]] && echo "files-${n}" || echo ""
  else
    echo ""
  fi
}

# == WADE Staging Daemon (detector)
get_ver_wade_stage(){
  # Return script hash if staged+enabled, else blank so run_step knows to install
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
STAGE_SRC="${SCRIPT_DIR}/scripts/staging/stage_daemon.py"
STAGE_EXPECT_SHA="$(sha256_of "$STAGE_SRC" 2>/dev/null || true)"

MWEX_SRC="${SCRIPT_DIR}/scripts/malware/wade_mw_extract.py"
MWEX_EXPECT_SHA="$(sha256_of "$MWEX_SRC" 2>/dev/null || true)"

#####################################
# WADE Doctor (services, shares, Splunk UF)
#####################################
wade_doctor() {
  echo "=== WADE Doctor ==="
  if systemctl is-active --quiet smbd || systemctl is-active --quiet smb; then
    echo "[*] Samba: active"
  else
    echo "[!] Samba: inactive"
  fi
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
  ss -plnt | awk 'NR==1 || /:139 |:445 |:8983 |:5432 /'
  echo "===================="
}

#####################################
# Preflight specs
#####################################
require_root
CPU_MIN=4; RAM_MIN_GB=16; DISK_MIN_GB=200
CPU_CORES=$(nproc || echo 1)
MEM_GB=$(( ( $(awk '/MemTotal/{print $2}' /proc/meminfo) + 1048575 ) / 1048576 ))
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
# Default index new WADE tools should use (kept for backwards-compat)
SPLUNK_DEFAULT_INDEX="wade_custom"

# Universal Forwarder defaults (used by the installer prompts & env)
# One or more indexers, comma-separated, each as host:port
SPLUNK_UF_RCVR_HOSTS="splunk.example.org:9997"
SPLUNK_UF_DEFAULT_INDEX="wade_custom"
SPLUNK_UF_COMPRESSED="true"     # tcpout: compressed = true|false
SPLUNK_UF_USE_ACK="true"        # tcpout: useACK = true|false
SPLUNK_UF_SSL_VERIFY="false"    # tcpout: sslVerifyServerCert = true|false
SPLUNK_UF_SSL_COMMON_NAME="*"   # tcpout: sslCommonNameToCheck (only if verify true)
SPLUNK_UF_DEPLOYMENT_SERVER=""  # e.g. "ds.example.org:8089" or blank to skip

# Ports (for summary/UI hints; *not* proof of local Splunk Enterprise)
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

# Volatility3 runtime dirs (writable by primary owner)
VOL3_BASE_DIR="/var/wade/vol3"
VOL3_SYMBOLS_DIR="${VOL3_BASE_DIR}/symbols"
VOL3_CACHE_DIR="${VOL3_BASE_DIR}/cache"
VOL3_PLUGIN_DIR="${VOL3_BASE_DIR}/plugins"   # optional, for custom plugins later

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

# ---- STIG (assessment only; interactive at end) ----
MOD_STIG_EVAL_ENABLED="1"         # keep prereqs enabled; eval runs interactively at end
MOD_STIG_REMEDIATE_ENABLED="0"    # do NOT apply fixes

# Reports
STIG_REPORT_DIR="/var/wade/logs/stig"

# Storage for a stable copy of the DS/XML we evaluated (for idempotent checks)
STIG_STORE_DIR="/var/wade/stigs"
STIG_UBU_EXTRACT_DIR="${STIG_STORE_DIR}/ubuntu2404"

# Default profile (can override; menu will still be shown)
STIG_PROFILE_ID="xccdf_mil.disa.stig_profile_MAC-1_Classified"

# Optional: comma-separated rule IDs to skip
STIG_SKIP_RULES=""
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

# ---- Guard against set -u for expected vars (defaults if config missing) ----
: "${VOL3_BASE_DIR:=/var/wade/vol3}"
: "${VOL3_SYMBOLS_DIR:=${VOL3_BASE_DIR}/symbols}"
: "${VOL3_CACHE_DIR:=${VOL3_BASE_DIR}/cache}"
: "${VOL3_PLUGIN_DIR:=${VOL3_BASE_DIR}/plugins}"
: "${LWADEUSER:=${WADE_OWNER_USER:-autopsy}}"

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

#####################################
# Fresh-install bootstrap
#####################################
bootstrap_fresh_install(){
  echo "[*] Fresh-install bootstrap…"
  if [[ "$PM" == "apt" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    bash -lc "$PKG_UPDATE"
    bash -lc "$PKG_INSTALL ca-certificates curl gnupg lsb-release git python3-venv unzip"
    bash -lc "$PKG_INSTALL ufw" || true
  else
    bash -lc "$PKG_UPDATE"
    bash -lc "$PKG_INSTALL firewalld curl tar git python3 python3-virtualenv unzip" || true
    systemctl enable firewalld --now || true
    if [[ "$OFFLINE" != "1" ]]; then
      bash -lc "$PKG_INSTALL oracle-epel-release-el10" || bash -lc "$PKG_INSTALL oracle-epel-release-el9" || bash -lc "$PKG_INSTALL epel-release" || true
      bash -lc "$PKG_UPDATE" || true
    fi
  fi
}
bootstrap_fresh_install

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

if [[ "$NONINTERACTIVE" -eq 0 ]]; then
  echo; echo "===== Summary ====="
  echo " Hostname     : $LWADE"
  echo " Linux Owner  : $LWADEUSER"
  echo " SMB users    : ${SMB_USERS_CSV}"
  echo " Allow nets   : ${ALLOW_NETS_CSV:-<none>}"
  echo " Offline mode : ${OFFLINE}"
  confirm "Proceed with installation?" || exit 0
fi

#####################################
# Core packages (+ headless Java & truststore)
#####################################
( set -e
  WANTED_PKGS_COMMON=(samba cifs-utils jq inotify-tools plocate libewf2 ewf-tools pipx zip unzip p7zip-full)
  if [[ "$PM" == "apt" ]]; then
    JAVA_PKG="${JAVA_PACKAGE_APT:-default-jre-headless}"
    bash -lc "$PKG_UPDATE"
    bash -lc "$PKG_INSTALL ${WANTED_PKGS_COMMON[*]} ufw ${JAVA_PKG}"
    if command -v keytool >/dev/null 2>&1; then
      /var/lib/dpkg/info/ca-certificates-java.postinst configure || true
      bash -lc "$PKG_INSTALL --reinstall ca-certificates-java" || true
    fi
  else
    JAVA_PKG="${JAVA_PACKAGE_RPM:-java-11-openjdk-headless}"
    bash -lc "$PKG_UPDATE"
    EXTRA_RPM=(policycoreutils policycoreutils-python-utils setools-console "$JAVA_PKG")
    bash -lc "$PKG_INSTALL ${WANTED_PKGS_COMMON[*]} firewalld ${EXTRA_RPM[*]}" || true
    systemctl enable firewalld --now || true
  fi
) || fail_note "core_packages" "base packages failed"

#####################################
# Samba shares (DataSources, Cases, Staging)
#####################################
get_ver_samba(){
  local SMB_CONF="/etc/samba/smb.conf"
  grep -q '^\[WADE-BEGIN\]' "$SMB_CONF" 2>/dev/null || { echo ""; return; }
  [[ -d "/home/${LWADEUSER}/${WADE_DATADIR}" ]]   || { echo ""; return; }
  [[ -d "/home/${LWADEUSER}/${WADE_CASESDIR}" ]]  || { echo ""; return; }
  [[ -d "/home/${LWADEUSER}/${WADE_STAGINGDIR}" ]]|| { echo ""; return; }
  echo configured
}

run_step "samba" "configured" get_ver_samba '
  set -e

  # Ensure samba present
  if [[ "$PM" == "apt" ]]; then
    bash -lc "$PKG_INSTALL samba cifs-utils" >/dev/null 2>&1 || true
  else
    bash -lc "$PKG_INSTALL samba cifs-utils" >/dev/null 2>&1 || true
  fi

  SMB_CONF="/etc/samba/smb.conf"
  install -d /etc/samba

  # Seed minimal config if missing
  if [[ ! -f "$SMB_CONF" ]]; then
    cat >"$SMB_CONF"<<EOF
[global]
   workgroup = WORKGROUP
   server string = WADE
   security = user
   map to guest = Bad User
   dns proxy = no
EOF
  fi

  [[ -f "${SMB_CONF}.bak" ]] || cp "$SMB_CONF" "${SMB_CONF}.bak"

  DATADIR="/home/${LWADEUSER}/${WADE_DATADIR}"
  CASESDIR="/home/${LWADEUSER}/${WADE_CASESDIR}"
  STAGINGDIR="/home/${LWADEUSER}/${WADE_STAGINGDIR}"
  mkdir -p "$DATADIR" "$CASESDIR" "$STAGINGDIR"
  chown -R "${LWADEUSER}:${LWADEUSER}" "/home/${LWADEUSER}"
  chmod 755 "/home/${LWADEUSER}" "$DATADIR" "$CASESDIR" "$STAGINGDIR"

  HOSTS_DENY_LINE="   hosts deny = 0.0.0.0/0"
  HOSTS_ALLOW_BLOCK=""
  if [[ "${#ALLOW_NETS_ARR[@]}" -gt 0 ]]; then
    HOSTS_ALLOW_BLOCK="   hosts allow ="
    for n in "${ALLOW_NETS_ARR[@]}"; do HOSTS_ALLOW_BLOCK+=" ${n}"; done
  fi
  VALID_USERS="$(echo "${SMB_USERS_CSV}" | sed "s/[[:space:]]//g")"

  # Strip our managed block if present, then append new one
  awk '"'"'BEGIN{skip=0} /^\[WADE-BEGIN\]/{skip=1;next} /^\[WADE-END\]/{skip=0;next} skip==0{print}'"'"' "$SMB_CONF" > "${SMB_CONF}.tmp" && mv "${SMB_CONF}.tmp" "$SMB_CONF"

  cat >>"$SMB_CONF"<<EOF
[WADE-BEGIN]
[DataSources]
   path = ${DATADIR}
   read only = no
   browsable = yes
   public = no
   guest ok = no
   writable = yes
   valid users = ${VALID_USERS}
${HOSTS_ALLOW_BLOCK}
${HOSTS_DENY_LINE}

[Cases]
   path = ${CASESDIR}
   read only = no
   browsable = yes
   public = no
   guest ok = no
   writable = yes
   valid users = ${VALID_USERS}
${HOSTS_ALLOW_BLOCK}
${HOSTS_DENY_LINE}

[Staging]
   path = ${STAGINGDIR}
   read only = no
   browsable = yes
   public = no
   guest ok = no
   writable = yes
   valid users = ${VALID_USERS}
${HOSTS_ALLOW_BLOCK}
${HOSTS_DENY_LINE}
[WADE-END]
EOF

  if ! testparm -s >/dev/null 2>&1; then
    echo "[!] testparm failed; restoring ${SMB_CONF}.bak"
    cp -f "${SMB_CONF}.bak" "$SMB_CONF"
    exit 1
  fi

  # Set Samba passwords (only in interactive)
  if [[ "$NONINTERACTIVE" -eq 0 ]]; then
    for u in "${SMBUSERS[@]}"; do
      u="$(echo "$u" | xargs)"; [[ -z "$u" ]] && continue
      if ! pdbedit -L | cut -d: -f1 | grep -qx "$u"; then
        echo "[*] Set Samba password for $u"
        while :; do
          read -s -p "Password for $u: " sp1; echo
          read -s -p "Confirm: " sp2; echo
          [[ "$sp1" == "$sp2" && -n "$sp1" ]] && break
          echo "Mismatch/empty. Try again."
        done
        ( printf "%s\n%s\n" "$sp1" "$sp1" ) | smbpasswd -s -a "$u" >/dev/null
      fi
    done
  fi

  # Enable services
  if systemctl list-unit-files | grep -q "^smbd\.service"; then
    systemctl enable smbd --now
    systemctl list-unit-files | grep -q "^nmbd\.service" && systemctl enable nmbd --now || true
  elif systemctl list-unit-files | grep -q "^smb\.service"; then
    systemctl enable smb --now
    systemctl list-unit-files | grep -q "^nmb\.service" && systemctl enable nmb --now || true
  fi

  # Firewall
  if [[ "$FIREWALL" == "ufw" ]] && command -v ufw >/dev/null 2>&1; then
    ufw allow Samba || true
  elif command -v firewall-cmd >/dev/null 2>&1; then
    systemctl enable firewalld --now || true
    if [[ "${WADE_STRICT_FIREWALL:-0}" -eq 1 ]]; then
      firewall-cmd --permanent --remove-service=samba >/dev/null 2>&1 || true
      for n in "${ALLOW_NETS_ARR[@]}"; do
        firewall-cmd --permanent --add-rich-rule="rule family='"'"'ipv4'"'"' source address='"'"'${n}'"'"' service name='"'"'samba'"'"' accept" || true
      done
    else
      firewall-cmd --permanent --add-service=samba || true
      for n in "${ALLOW_NETS_ARR[@]}"; do
        firewall-cmd --permanent --add-rich-rule="rule family='"'"'ipv4'"'"' source address='"'"'${n}'"'"' service name='"'"'samba'"'"' accept" || true
      done
    fi
    firewall-cmd --reload || true
  fi
' || fail_note "samba" "share setup failed"

#####################################
# Staging Service Install (venv-managed)
#####################################

VENV_DIR="/home/${LWADEUSER}/.venvs/wade"

run_step "wade-stage" "${STAGE_EXPECT_SHA}" get_ver_wade_stage '
  set -e

  # Load config if present (non-fatal)
  . "'"${WADE_ETC}/wade.conf"'" 2>/dev/null || true
  . "'"${WADE_ETC}/wade.env"'" 2>/dev/null || true

  # 1) Install the daemon script
  install -d -m 0755 /opt/wade
  install -m 0755 "'"$STAGE_SRC"'" /opt/wade/stage_daemon.py

  # 2) Create the WADE venv for the service (owned by the runtime user)
  install -d -m 0755 "/home/'"${LWADEUSER}"'/.venvs"
  python3 -m venv "'"$VENV_DIR"'"
  chown -R "'"${LWADEUSER}:${LWADEUSER}"'" "'"$VENV_DIR"'"

  # 3) Install deps into the venv (no system Python writes → PEP 668-safe)
  "'"$VENV_DIR"'/bin/python" -m pip install -U pip setuptools wheel
  "'"$VENV_DIR"'/bin/pip" install inotify-simple

  # 4) Smoke test: verify all imports you listed resolve from the venv
  "'"$VENV_DIR"'/bin/python" - <<'"'"'PY'"'"'
import json, os, re, shutil, signal, sqlite3, subprocess, sys, time, string, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple
from inotify_simple import INotify, flags
import difflib
print("WADE staging imports OK from", sys.executable)
PY

  # 5) Ensure logs/state + staging/share structure exists
  install -d -m 0755 /var/wade/logs/stage /var/wade/state
  chown -R "'"${LWADEUSER}:${LWADEUSER}"'" /var/wade

  STAGING_ROOT="/home/'"${LWADEUSER}"'/'"${WADE_STAGINGDIR}"'"
  DATAS_ROOT="/home/'"${LWADEUSER}"'/'"${WADE_DATADIR}"'"
  QUEUE_DIR="${WADE_QUEUE_DIR:-_queue}"

  install -d -o "'"${LWADEUSER}"'" -g "'"${LWADEUSER}"'" -m 0755 \
      "${STAGING_ROOT}/full" "${STAGING_ROOT}/light" \
      "${DATAS_ROOT}/Hosts" "${DATAS_ROOT}/Network" "${DATAS_ROOT}/${QUEUE_DIR}"

  # 6) Systemd unit — explicitly run with the venv’s interpreter
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
# If your Splunk UF runs as another user and needs to read outputs, consider:
# SupplementaryGroups=splunk
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

  # 7) Enable & start
  systemctl daemon-reload
  systemctl enable --now wade-staging.service

  # 8) Version marker (lets your idempotency skip next run)
  sha256sum /opt/wade/stage_daemon.py | awk '"'"'{print $1}'"'"' > "'"${STEPS_DIR}/wade-stage.ver"'"

  # Optional: freeze for reproducibility alongside your repo
  install -d -m 0755 /home/'"${LWADEUSER}"'/WADE 2>/dev/null || true
  "'"$VENV_DIR"'/bin/pip" freeze > /home/'"${LWADEUSER}"'/WADE/requirements.lock || true
' || fail_note "wade-stage" "service install/start failed"

#####################################
# pipx tools: volatility3 + dissect
#####################################
run_step "pipx-vol3" "installed" get_ver_pipx_vol3 '
  set -e
  export PIPX_HOME=/opt/pipx
  export PIPX_BIN_DIR=/usr/local/bin
  mkdir -p "$PIPX_HOME" "$PIPX_BIN_DIR"

  if ! command -v pipx >/dev/null 2>&1; then
    if [[ "$PM" == "apt" ]]; then
      bash -lc "$PKG_UPDATE"
      bash -lc "$PKG_INSTALL pipx"
    else
      python3 -m pip install --upgrade pip || true
      python3 -m pip install pipx || true
    fi
  fi

  python3 -m pipx ensurepath || true
  pipx install volatility3 || pipx upgrade volatility3
' || fail_note "pipx-vol3" "install failed"

run_step "pipx-dissect" "installed" get_ver_pipx_dissect '
  set -e
  export PIPX_HOME=/opt/pipx
  export PIPX_BIN_DIR=/usr/local/bin
  mkdir -p "$PIPX_HOME" "$PIPX_BIN_DIR"

  if ! command -v pipx >/dev/null 2>&1; then
    if [[ "$PM" == "apt" ]]; then
      bash -lc "$PKG_UPDATE"
      bash -lc "$PKG_INSTALL pipx"
    else
      python3 -m pip install --upgrade pip || true
      python3 -m pip install pipx || true
    fi
  fi

  python3 -m pipx ensurepath || true
  pipx install "dissect[cli]" --include-deps || pipx upgrade "dissect[cli]"
' || fail_note "pipx-dissect" "install failed"

run_step "vol3-runtime" "ready" 'get_mark_ver vol3-runtime' '
  set -e

  # Safe defaults inside the subshell too (defend against set -u and --only runs)
  : "${VOL3_BASE_DIR:=/var/wade/vol3}"
  : "${VOL3_SYMBOLS_DIR:=${VOL3_BASE_DIR}/symbols}"
  : "${VOL3_CACHE_DIR:=${VOL3_BASE_DIR}/cache}"
  : "${VOL3_PLUGIN_DIR:=${VOL3_BASE_DIR}/plugins}"
  : "${LWADEUSER:=autopsy}"

  install -d -m 2775 "$VOL3_SYMBOLS_DIR" "$VOL3_CACHE_DIR" "$VOL3_PLUGIN_DIR"
  chown -R "$LWADEUSER:$LWADEUSER" "$VOL3_BASE_DIR" || true

  # Locate vol (ensure pipx step ran, or fail clearly)
  VOL_BIN="$(command -v vol || true)"
  [[ -x "$VOL_BIN" ]] || { echo "vol not found; run with --only=pipx-vol3,vol3-runtime or full install"; exit 1; }

  # Wrapper that forces writable symbols/cache/plugin dirs
  cat >/usr/local/bin/vol3 <<'EOF'
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

  # Pre-reqs
  if [[ "$PM" == "apt" ]]; then
    bash -lc "$PKG_INSTALL python3-venv python3-pip git ca-certificates zip p7zip-full"
  else
    bash -lc "$PKG_INSTALL python3 python3-virtualenv git ca-certificates zip" || true
    bash -lc "$PKG_INSTALL p7zip p7zip-plugins" || true
  fi

  # venv
  install -d "$(dirname "$WADE_CAPA_VENV")"
  [[ -x "$WADE_CAPA_VENV/bin/python" ]] || python3 -m venv "$WADE_CAPA_VENV"
  "$WADE_CAPA_VENV/bin/python" -m pip install -U pip wheel setuptools >/dev/null 2>&1 || true

  # Correct package is flare-capa (provides "capa" CLI)
  PKG="flare-capa"
  [[ -n "${CAPA_VERSION:-}" ]] && PKG="flare-capa==${CAPA_VERSION}"

  WHEEL_DIR=""
  if [[ -d "${WADE_PKG_DIR:-/var/wade/pkg}/pipwheels" ]]; then
    WHEEL_DIR="${WADE_PKG_DIR:-/var/wade/pkg}/pipwheels"
  elif [[ "${OFFLINE:-0}" == "1" && -d "${OFFLINE_SRC:-}/pipwheels" ]]; then
    WHEEL_DIR="${OFFLINE_SRC}/pipwheels"
  fi

  if [[ -n "$WHEEL_DIR" ]]; then
    "$WADE_CAPA_VENV/bin/pip" install --no-index --find-links "$WHEEL_DIR" "$PKG"
  else
    "$WADE_CAPA_VENV/bin/pip" install "$PKG"
  fi

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

  # Export for shells/tools
  cat >/etc/profile.d/wade-capa.sh <<EOF
export WADE_CAPA_RULES="${WADE_CAPA_RULES_DIR}"
EOF
  chmod 0644 /etc/profile.d/wade-capa.sh

  # Handy updater (for online use)
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

  # Smoke check: have rules?
  n=$(find "$WADE_CAPA_RULES_DIR" -type f -name "*.yml" 2>/dev/null | wc -l | tr -d " ")
  [[ "${n:-0}" -gt 0 ]] || { echo "no rules found"; exit 1; }
' || fail_note "capa-rules" "rules install failed"

#####################################
# WADE Malware Extractor (CLI)
#####################################
run_step "wade-mw-extractor" "${MWEX_EXPECT_SHA}" get_ver_wade_mwex '
  set -e

  # Install script & dirs
  install -d -m 0755 /opt/wade /var/wade/logs/malware
  install -m 0755 "'"$MWEX_SRC"'" /opt/wade/wade_mw_extract.py

  # Lightweight wrapper in PATH (passes through args)
  cat >/usr/local/bin/wade-mw-extract <<'"'"'EOF'"'"'
#!/usr/bin/env bash
set -euo pipefail
# Default capa rules for convenience; user can override per-invocation
export WADE_CAPA_RULES="${WADE_CAPA_RULES:-/opt/capa-rules}"
exec /usr/bin/env python3 /opt/wade/wade_mw_extract.py "$@"
EOF
  chmod 0755 /usr/local/bin/wade-mw-extract

  # Sanity hints (non-fatal)
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
  local arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) echo "lin-x64-gnu" ;;
    aarch64|arm64) echo "lin-aarch64-gnu" ;;
    *) echo "lin-x64-gnu" ;;
  esac
}

#####################################
# Volatility3 symbol packs (soft-fail)
#####################################
if [[ "${MOD_VOL_SYMBOLS_ENABLED:-1}" == "1" ]]; then
run_step "vol3-symbols" "current" 'get_mark_ver vol3-symbols' '
  set -e
  mkdir -p "'"${VOL3_SYMBOLS_DIR}"'"

  # Pull the official prebuilt packs when online, or use offline cache if present
  for z in windows.zip mac.zip linux.zip; do
    test -f "'"${VOL3_SYMBOLS_DIR}"'/$z" && continue
    fetch_pkg "volatility3/symbols" "$z" || curl -L "https://downloads.volatilityfoundation.org/volatility3/symbols/${z}" -o "$z"
    cp -f "$z" "'"${VOL3_SYMBOLS_DIR}"'/"
  done

  # Ownership so your primary operator can add symbols later
  chown -R "'"${LWADEUSER}:${LWADEUSER}"'" "'"${VOL3_SYMBOLS_DIR}"'" || true

  echo "$(date -Iseconds)" > "${STEPS_DIR}/vol3-symbols.ver"
' || fail_note "volatility_symbols" "download/verify failed"
fi

#####################################
# bulk_extractor (source build; soft-fail)
#####################################
if [[ "${MOD_BULK_EXTRACTOR_ENABLED:-1}" == "1" ]]; then
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
    if have_cmd dnf; then
      dnf -y groupinstall "Development Tools" || true
    else
      yum -y groupinstall "Development Tools" || true
    fi
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

#####################################
# Qt/GL runtime libs (for Piranha/Barracuda UIs; apt branch)
#####################################
if [[ "$PM" == "apt" && ( "${MOD_PIRANHA_ENABLED:-1}" == "1" || "${MOD_BARRACUDA_ENABLED:-1}" == "1" ) ]]; then
run_step "qtgl-runtime" "present" get_ver_qtgl '
  set -e
  bash -lc "$PKG_INSTALL \
    libegl1 libopengl0 libgl1 libxkbcommon-x11-0 \
    libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 \
    libxcb-render-util0 libxcb-shape0 libxcb-xfixes0 libxcb-xinerama0 libxcb-xkb1 \
    libxcb-cursor0 \
    fonts-dejavu-core"
' || fail_note "qtgl-runtime" "Qt/GL libs missing"

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
  if [[ "$PM" == "apt" ]]; then
    bash -lc "$PKG_INSTALL xauth x11-apps"
  else
    bash -lc "$PKG_INSTALL xorg-x11-xauth || $PKG_INSTALL xauth || true"
  fi

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

  su - "${LWADEUSER}" -c "mkdir -p ~/.config/matplotlib; touch ~/.Xauthority; chmod 600 ~/.Xauthority" || true
' || fail_note "x11-forwarding" "setup failed"

fi

#####################################
# Piranha (install only; GUI via ssh -X, no systemd)
#####################################
get_ver_piranha(){ [[ -x /usr/local/bin/piranha && -d /opt/piranha/.venv && -f /opt/piranha/piranha.py ]] && echo installed || echo ""; }

if [[ "${MOD_PIRANHA_ENABLED:-1}" == "1" ]]; then
run_step "piranha" "installed" get_ver_piranha '
  set -e
  install -d /opt/piranha /var/log/wade/piranha
  chown -R "${LWADEUSER}:${LWADEUSER}" /opt/piranha /var/log/wade/piranha

  install -d /opt/piranha/Documents/PiranhaLogs
  chown -R "${LWADEUSER}:${LWADEUSER}" /opt/piranha/Documents
  ln -sf /var/log/wade/piranha/APT_Report.log /opt/piranha/Documents/PiranhaLogs/APT_Report.log || true

  if [[ "$OFFLINE" == "1" ]]; then
    PKG_ARC="$(ls "${WADE_PKG_DIR}/piranha/"piranha*.tar.gz "${WADE_PKG_DIR}/piranha/"piranha*.zip 2>/dev/null | head -1 || true)"
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
  /opt/piranha/.venv/bin/pip install --upgrade pip
  [[ -f /opt/piranha/requirements.txt ]] && /opt/piranha/.venv/bin/pip install -r /opt/piranha/requirements.txt || true

  FEIX="$(ls "$LOAD_PATCH_DIR"/*patch.py 2>/dev/null | sort -V | tail -1)"
  if [[ -n "$FEIX" ]]; then
    rm -f /opt/piranha/backend/loader.py
    cp "$FEIX" /opt/piranha/backend/loader.py || true
  fi

  echo 'exec /opt/piranha/.venv/bin/python /opt/piranha/piranha.py "$@"' > /usr/local/bin/piranha
  chmod 0755 /usr/local/bin/piranha
  chown "${LWADEUSER}:${LWADEUSER}" /usr/local/bin/piranha || true
' || fail_note "piranha" "setup failed"
fi

#####################################
# Barracuda (soft-fail; fetch MITRE JSON; cd wrapper; absolute JSON path)
#####################################
get_ver_barracuda(){
  [[ -x /usr/local/bin/barracuda && -d /opt/barracuda/.venv ]] || { echo ""; return; }
  [[ -f /opt/barracuda/enterprise-attack.json ]] && echo installed || echo ""
}
if [[ "${MOD_BARRACUDA_ENABLED:-1}" == "1" ]]; then
run_step "barracuda" "installed" get_ver_barracuda '
  set -e
  install -d /opt/barracuda
  if [[ "$OFFLINE" == "1" ]]; then
    PKG_ARC="$(ls "${WADE_PKG_DIR}/barracuda/"barracuda*.tar.gz "${WADE_PKG_DIR}/barracuda/"barracuda*.zip 2>/dev/null | head -1 || true)"
    [[ -n "$PKG_ARC" ]] || { echo "offline Barracuda archive missing"; exit 1; }
    cp "$PKG_ARC" /opt/barracuda/
    pushd /opt/barracuda >/dev/null
    [[ "$PKG_ARC" == *.zip ]] && unzip -o "$(basename "$PKG_ARC")" || tar -xzf "$(basename "$PKG_ARC")"
    popd >/dev/null
  else
    [[ -d /opt/barracuda/.git ]] || git clone https://github.com/williamjsmail/Barracuda /opt/barracuda || true
  fi

  python3 -m venv /opt/barracuda/.venv || python3 -m virtualenv /opt/barracuda/.venv
  /opt/barracuda/.venv/bin/pip install --upgrade pip
  [[ -f /opt/barracuda/requirements.txt ]] && /opt/barracuda/.venv/bin/pip install -r /opt/barracuda/requirements.txt || true

  if [[ ! -f /opt/barracuda/enterprise-attack.json ]]; then
    if [[ -f "${WADE_PKG_DIR}/mitre/enterprise-attack.json" ]]; then
      cp "${WADE_PKG_DIR}/mitre/enterprise-attack.json" /opt/barracuda/enterprise-attack.json
    elif [[ "$OFFLINE" == "1" && -f "${OFFLINE_SRC}/mitre/enterprise-attack.json" ]]; then
      cp "${OFFLINE_SRC}/mitre/enterprise-attack.json" /opt/barracuda/enterprise-attack.json
    else
      curl -fsSL https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json \
        -o /opt/barracuda/enterprise-attack.json
    fi
  fi

  sed -i -E \
    '\''s|load_techniques_enriched\("enterprise-attack\.json"\)|load_techniques_enriched("/opt/barracuda/enterprise-attack.json")|'\'' \
    /opt/barracuda/app.py || true

  install -d -o autopsy -g autopsy -m 0750 /opt/barracuda/uploads

  cat >/usr/local/bin/barracuda <<'\''EOF'\''
#!/usr/bin/env bash
export QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-offscreen}"
cd /opt/barracuda
exec /opt/barracuda/.venv/bin/python /opt/barracuda/app.py "$@"
EOF
  chmod 0755 /usr/local/bin/barracuda

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

  systemctl daemon-reload
  systemctl enable --now barracuda.service || true
' || fail_note "barracuda" "setup failed"
fi

#####################################
# Hayabusa (robust extract; soft-fail)
#####################################
if [[ "${MOD_HAYABUSA_ENABLED:-1}" == "1" ]]; then
run_step "hayabusa" "" get_ver_hayabusa '
  set -e
  echo "[*] Installing Hayabusa…"
  install -d "$(dirname "${HAYABUSA_DEST}")"

  HAY_ARCH="${HAY_ARCH:-$(detect_hayabusa_arch)}"
  HAY_ZIP=""
  HAY_ZIP_LOCAL="$(ls "${WADE_PKG_DIR}/hayabusa/"hayabusa-*-"${HAY_ARCH:-}".zip 2>/dev/null | sort -V | tail -1 || true)"

  if [[ -n "$HAY_ZIP_LOCAL" ]]; then
    cp "$HAY_ZIP_LOCAL" .
    HAY_ZIP="$(basename "$HAY_ZIP_LOCAL")"
  elif [[ "$OFFLINE" == "1" ]]; then
    HAY_ZIP_USB="$(ls "${OFFLINE_SRC}/hayabusa/"hayabusa-*-"${HAY_ARCH:-}".zip 2>/dev/null | sort -V | tail -1 || true)"
    [[ -n "$HAY_ZIP_USB" ]] || { echo "Hayabusa zip for arch '${HAY_ARCH:-}' not found offline"; exit 1; }
    cp "$HAY_ZIP_USB" .
    HAY_ZIP="$(basename "$HAY_ZIP_USB")"
  else
    if have_cmd curl && have_cmd jq; then
      echo "[*] Downloading latest Hayabusa release for ${HAY_ARCH:-}…"
      DL_URL="$(curl -fsSL https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest \
        | jq -r --arg pat "${HAY_ARCH:-}" ".assets[] | select(.name | test(\$pat)) | .browser_download_url" | head -1)"
      [[ -n "$DL_URL" ]] || { echo "Could not resolve latest Hayabusa asset for ${HAY_ARCH:-}"; exit 1; }
      HAY_ZIP="$(basename "$DL_URL")"
      curl -L "$DL_URL" -o "$HAY_ZIP"
    else
      echo "curl/jq required to auto-fetch Hayabusa online"; exit 1
    fi
  fi

  TMPDIR="$(mktemp -d)"; cleanup(){ rm -rf "$TMPDIR"; }; trap cleanup EXIT
  unzip -qo "$HAY_ZIP" -d "$TMPDIR"

  HAY_BIN_PATH="$(find "$TMPDIR" -type f \( -name "hayabusa" -o -name "hayabusa-*" \) ! -path "*/rules/*" ! -path "*/config/*" | head -1 || true)"
  if [[ -z "$HAY_BIN_PATH" ]]; then
    echo "Hayabusa binary not found in ${HAY_ZIP}. Contents:"; find "$TMPDIR" -maxdepth 3 -type f -printf "  %P\n"; exit 1
  fi

  install -m 0755 "$HAY_BIN_PATH" "${HAYABUSA_DEST}"
  echo "[+] Installed Hayabusa to ${HAYABUSA_DEST}"

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
  systemctl daemon-reload; systemctl enable zookeeper --now
' || fail_note "zookeeper" "install/config failed"

#####################################
# Solr (pinned; soft-fail)
#####################################
run_step "solr" "${SOLR_VER}" get_ver_solr '
  set -e
  SOLR_TGZ="solr-${SOLR_VER}.tgz"
  fetch_pkg solr "$SOLR_TGZ" || curl -L "https://archive.apache.org/dist/lucene/solr/${SOLR_VER}/${SOLR_TGZ}" -o "$SOLR_TGZ"
  [[ -f "$SOLR_TGZ" ]] || { echo "Solr tgz missing"; exit 1; }
  tar -xvzf "$SOLR_TGZ" "solr-${SOLR_VER}/bin/install_solr_service.sh" --strip-components=2
  bash ./install_solr_service.sh "$SOLR_TGZ"
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
  systemctl daemon-reload; systemctl enable activemq --now
' || fail_note "activemq" "install/config failed"

#####################################
# PostgreSQL (Ubuntu path; soft-fail)
#####################################
run_step "postgresql" "configured" get_ver_pg '
  set -e
  if [[ "$PM" == "apt" ]]; then
    dpkg -s postgresql >/dev/null 2>&1 || bash -lc "$PKG_INSTALL postgresql"
    systemctl enable postgresql || true
    PG_VER=$(psql -V | awk "{print \$3}" | cut -d. -f1)
    PG_DIR="/etc/postgresql/${PG_VER}/main"
    sed -ri "s/^#?fsync\s*=.*/fsync = ${PG_PERF_FSYNC}/" "${PG_DIR}/postgresql.conf"
    sed -ri "s/^#?synchronous_commit\s*=.*/synchronous_commit = ${PG_PERF_SYNCCOMMIT}/" "${PG_DIR}/postgresql.conf"
    sed -ri "s/^#?full_page_writes\s*=.*/full_page_writes = ${PG_PERF_FULLPAGE}/" "${PG_DIR}/postgresql.conf"
    grep -q "listen_addresses" "${PG_DIR}/postgresql.conf" && \
      sed -ri "s/^#?listen_addresses\s*=.*/listen_addresses = '"'"'${PG_LISTEN_ADDR}'"'"'/" "${PG_DIR}/postgresql.conf" \
      || echo "listen_addresses = '"'"'${PG_LISTEN_ADDR}'"'"'" >> "${PG_DIR}/postgresql.conf"
    for n in ${ALLOW_NETS_CSV//,/ }; do
      grep -qE "^\s*host\s+all\s+all\s+${n}\s+md5" "${PG_DIR}/pg_hba.conf" || echo "host all all ${n} md5" >> "${PG_DIR}/pg_hba.conf"
    done
    systemctl restart postgresql || true
  fi
' || fail_note "postgresql" "install/config failed"

#####################################
# STIG prerequisites (OpenSCAP + SSG)
#####################################
if [[ "${MOD_STIG_EVAL_ENABLED:-0}" == "1" ]]; then
run_step "stig-prereqs" "installed" get_ver_stig '
  set -e
  if [[ "$PM" == "apt" ]]; then
    bash -lc "$PKG_INSTALL openscap-scanner unzip ssg-base ssg-debderived ssg-debian ssg-nondebian ssg-applications" || true
    bash -lc "apt-cache show scap-security-guide >/dev/null 2>&1 && $PKG_INSTALL scap-security-guide || true"
  else
    bash -lc "$PKG_INSTALL openscap-scanner unzip" || true
    bash -lc "$PKG_INSTALL scap-security-guide" || true
  fi
' || fail_note "stig" "could not install prerequisites"
fi

#####################################
# Splunk Universal Forwarder (DEB path; soft-fail)
#####################################
run_step "splunk-uf" "installed" get_ver_uf '
  set -e

  if [[ "$PM" != "apt" ]]; then
    echo "[!] Splunk UF step currently implements the Debian/Ubuntu path."
    exit 1
  fi

  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y || true
  apt-get install -y --no-install-recommends procps curl || true

  id splunkfwd >/dev/null 2>&1 || useradd --system --home-dir /opt/splunkforwarder --shell /usr/sbin/nologin splunkfwd || true

  # ---- locate UF package (env URL, /var/wade/pkg, or script dir) ----
  PKG=""
  if [[ -n "${SPLUNK_UF_DEB_URL:-}" ]]; then
    PKG="/tmp/$(basename "${SPLUNK_UF_DEB_URL}")"
    curl -L "${SPLUNK_UF_DEB_URL}" -o "$PKG"
  elif ls "${WADE_PKG_DIR:-/var/wade/pkg}"/splunkforwarder/*.deb >/dev/null 2>&1; then
    PKG="$(ls "${WADE_PKG_DIR:-/var/wade/pkg}"/splunkforwarder/*.deb | sort -V | tail -1)"
  elif ls "'"$SPLUNK_SRC_DIR"'"/*.deb >/dev/null 2>&1; then
    PKG="$(ls "'"$SPLUNK_SRC_DIR"'"/*.deb | sort -V | tail -1)"
  fi

  if [[ -z "$PKG" || ! -f "$PKG" ]]; then
    echo "[!] No UF .deb provided. Set SPLUNK_UF_DEB_URL or place a .deb under ${WADE_PKG_DIR:-/var/wade/pkg}/splunkforwarder/"
    exit 1
  fi

  dpkg -i "$PKG" || apt-get -f install -y
  /opt/splunkforwarder/bin/splunk enable boot-start -systemd-managed 1 -user splunkfwd --accept-license --answer-yes || true

  mkdir -p /opt/splunkforwarder/etc/system/local

  # ---- defaults from wade.conf (with sane fallbacks) ----
  local DEFAULT_HOSTS="${SPLUNK_UF_RCVR_HOSTS:-splunk.example.org:9997}"
  local DEFAULT_INDEX="${SPLUNK_UF_DEFAULT_INDEX:-${SPLUNK_DEFAULT_INDEX:-wade_custom}}"
  local COMPRESSED="${SPLUNK_UF_COMPRESSED:-true}"
  local USE_ACK="${SPLUNK_UF_USE_ACK:-true}"
  local SSL_VERIFY="${SPLUNK_UF_SSL_VERIFY:-false}"
  local SSL_CN="${SPLUNK_UF_SSL_COMMON_NAME:-*}"
  local DS_TARGET="${SPLUNK_UF_DEPLOYMENT_SERVER:-}"

  local SERVER_LINE=""

  if [[ "${NONINTERACTIVE:-0}" -eq 0 ]]; then
    echo
    echo ">> Splunk UF configuration"
    local IDXERS
    IDXERS="$(prompt_with_default "Indexer(s) host[:port], comma-separated" "${DEFAULT_HOSTS}")"
    local DEFAULT_PORT="$(echo "${DEFAULT_HOSTS##*:}" | awk '"'"'{print $1}'"'"')"
    local NORMALIZED=""
    IFS=',' read -r -a ARR <<< "$IDXERS"
    for h in "${ARR[@]}"; do
      h="$(echo "$h" | xargs)"
      [[ -z "$h" ]] && continue
      if [[ "$h" == *:* ]]; then NORMALIZED+="${h},"; else NORMALIZED+="${h}:${DEFAULT_PORT},"; fi
    done
    SERVER_LINE="${NORMALIZED%,}"

    DEFAULT_INDEX="$(prompt_with_default "Default index for WADE logs" "$DEFAULT_INDEX")"
    if yesno_with_default "Enable compression?" "Y"; then COMPRESSED="true"; else COMPRESSED="false"; fi
    if yesno_with_default "Enable indexer ACKs?" "Y"; then USE_ACK="true"; else USE_ACK="false"; fi
    if yesno_with_default "Configure a deployment server?" "N"; then
      DS_TARGET="$(prompt_with_default "Deployment server host:port" "${SPLUNK_UF_DEPLOYMENT_SERVER:-ds.example.org:8089}")"
    fi
    if yesno_with_default "Verify indexer SSL certs?" "N"; then
      SSL_VERIFY="true"
      SSL_CN="$(prompt_with_default "sslCommonNameToCheck" "${SPLUNK_UF_SSL_COMMON_NAME:-*}")"
    else
      SSL_VERIFY="false"
    fi
  else
    SERVER_LINE="${DEFAULT_HOSTS}"
  fi

  # ---- write outputs.conf ----
  SSL_BLOCK=""
  if [[ "$SSL_VERIFY" == "true" ]]; then
    SSL_BLOCK=$'"'"'sslVerifyServerCert = true
sslCommonNameToCheck = '"'"'"${SSL_CN}"'"'"''"'"'
  fi

  cat >/opt/splunkforwarder/etc/system/local/outputs.conf <<OUTCONF
[tcpout]
defaultGroup = default-autolb-group
indexAndForward = false

[tcpout:default-autolb-group]
server = ${SERVER_LINE}
autoLB = true
compressed = ${COMPRESSED}
useACK = ${USE_ACK}
${SSL_BLOCK}
OUTCONF

  # ---- write inputs.conf (basic WADE monitors) ----
  cat >/opt/splunkforwarder/etc/system/local/inputs.conf <<INCONF
[monitor:///var/wade/logs]
index = ${DEFAULT_INDEX}
sourcetype = wade:log

[monitor:///var/log/wade/piranha]
index = ${DEFAULT_INDEX}
sourcetype = wade:piranha

[monitor:///var/log/wade]
index = ${DEFAULT_INDEX}
sourcetype = wade:misc
INCONF

  # ---- deployment server (optional) ----
  if [[ -n "$DS_TARGET" ]]; then
    cat >/opt/splunkforwarder/etc/system/local/deploymentclient.conf <<DCONF
[deployment-client]
[target-broker:deploymentServer]
targetUri = ${DS_TARGET}
DCONF
  fi

  chown -R splunkfwd:splunkfwd /opt/splunkforwarder || true
  systemctl daemon-reload
  systemctl enable --now SplunkForwarder.service || systemctl restart SplunkForwarder.service || true
' || fail_note "splunk-uf" "install/config failed"

#####################################
# WADE: logrotate setup (multi-service)
#####################################

# Ensure logrotate is installed (best-effort for offline)
_wade_ensure_logrotate() {
  if command -v logrotate >/dev/null 2>&1; then return 0; fi
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y logrotate >/dev/null 2>&1 || true
  fi
}

# Derive default logdir from service name: wade-XYZ -> /var/wade/logs/XYZ
_wade_default_logdir_for_service() {
  local svc="$1"
  local base="${svc#wade-}"
  printf "/var/wade/logs/%s" "${base}"
}

# Configure logrotate + systemd override for a single service
# Args:
#   1: service name (e.g., wade-stage)  [required]
#   2: logdir (default: auto from svc)  [optional]
#   3: user  (default: autopsy)         [optional]
#   4: group (default: same as user)    [optional]
#   5: rotate count (default: 14)       [optional]
#   6: period: daily|weekly|monthly (default: daily) [optional]
#   7: method: signal:USR1|signal:HUP|copytruncate (default: signal:USR1) [optional]
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

  # Ensure log dir and ownership
  mkdir -p "${logdir}"
  if id -u "${user}" >/dev/null 2>&1 && getent group "${group}" >/dev/null 2>&1; then
    chown -R "${user}:${group}" "${logdir}" || true
  else
    echo "[wade] note: user/group ${user}:${group} not present; defaulting to root:root for ${logdir}"
    user="root"; group="root"
    chown -R root:root "${logdir}" || true
  fi
  chmod 0750 "${logdir}" || true

  # Per-service systemd override (only when signaling)
  if [[ "${method}" == signal:* ]]; then
    local sig="${method#signal:}"
    mkdir -p "/etc/systemd/system/${svc}.service.d"
    cat > "/etc/systemd/system/${svc}.service.d/logrotate-reload.conf" <<EOF
[Service]
ExecReload=
ExecReload=/bin/kill -s ${sig} \$MAINPID
EOF
    systemctl daemon-reload 2>/dev/null || true
  fi

  # Build postrotate script based on method
  local postrotate_cmd
  if [[ "${method}" == copytruncate ]]; then
    # No signal; rely on copytruncate directive
    postrotate_cmd=": # no signal; using copytruncate"
  else
    # Default or explicit signal:<SIG>
    local sig="${method#signal:}"
    postrotate_cmd="systemctl kill -s ${sig} ${svc}.service 2>/dev/null || true"
  fi

  # Per-service logrotate policy file
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

  echo "[wade] logrotate policy: ${policy}"
}

# Bulk helper:
# Accepts any number of tokens in the form:
#   "service[:logdir[:user[:group[:rotate[:period[:method]]]]]]"
# Example token: "wade-stage:/var/wade/logs/stage:autopsy:autopsy:14:daily:signal:USR1"
install_wade_logrotate_bulk() {
  local token svc logdir user group rotate period method
  for token in "$@"; do
    IFS=':' read -r svc logdir user group rotate period method <<<"${token}"
    install_wade_logrotate "${svc:?}" "${logdir:-}" "${user:-}" "${group:-}" "${rotate:-}" "${period:-}" "${method:-}"
  done
}

# Rotate JSONL under /var/wade/logs/malware weekly, keep 14 copies
install_wade_logrotate "wade-mw-extractor" "/var/wade/logs/malware" "${LWADEUSER:-autopsy}" "${LWADEUSER:-autopsy}" 14 "weekly" "copytruncate"

#####################################
# Persist facts & endpoints
#####################################
ENV_FILE="${WADE_ETC}/wade.env"
IPV4="$(hostname -I 2>/dev/null | awk '{print $1}')"

# — Derive Splunk UF settings if present (fall back to conf defaults) —
OUTCONF="/opt/splunkforwarder/etc/system/local/outputs.conf"
INCONF="/opt/splunkforwarder/etc/system/local/inputs.conf"
DCONF="/opt/splunkforwarder/etc/system/local/deploymentclient.conf"

UF_RCVR="$(awk -F= '/^\s*server\s*=/ {gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2; exit}' "$OUTCONF" 2>/dev/null)"
UF_COMP="$(awk -F= '/^\s*compressed\s*=/ {gsub(/^[ \t]+|[ \t]+$/,"", $2); print tolower($2); exit}' "$OUTCONF" 2>/dev/null)"
UF_ACKS="$(awk -F= '/^\s*useACK\s*=/ {gsub(/^[ \t]+|[ \t]+$/,"", $2); print tolower($2); exit}' "$OUTCONF" 2>/dev/null)"
UF_SSLV="$(awk -F= '/^\s*sslVerifyServerCert\s*=/ {gsub(/^[ \t]+|[ \t]+$/,"",$2); print tolower($2); exit}' "$OUTCONF" 2>/dev/null)"
UF_SSLN="$(awk -F= '/^\s*sslCommonNameToCheck\s*=/ {gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2; exit}' "$OUTCONF" 2>/dev/null)"
UF_DS="$(awk -F= '/^\s*targetUri\s*=/ {gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2; exit}' "$DCONF" 2>/dev/null)"
UF_IDX="$(awk -F= '/^\s*index\s*=/ {gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2; exit}' "$INCONF" 2>/dev/null)"

# fallbacks to defaults from wade.conf
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

# Reference ports (for dashboards / docs)
SPLUNK_WEB_PORT="${SPLUNK_WEB_PORT:-8000}"
SPLUNK_MGMT_PORT="${SPLUNK_MGMT_PORT:-8089}"
SPLUNK_HEC_PORT="${SPLUNK_HEC_PORT:-8088}"
SPLUNK_FORWARD_PORT="${SPLUNK_FORWARD_PORT:-9997}"

# Hayabusa locations
HAYABUSA_DEST="${HAYABUSA_DEST}"
HAYABUSA_RULES_DIR="${HAYABUSA_RULES_DIR}"
SIGMA_RULES_DIR="${SIGMA_RULES_DIR}"

# Offline flag
OFFLINE="${OFFLINE}"

# Queue 
WADE_QUEUE_DIR=_queue

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

WADE_SERVICE_PORTS_CSV="\${SSH_PORT},\${SMB_TCP_139},\${SMB_TCP_445},\${SMB_UDP_137},\${SMB_UDP_138},\${ZK_CLIENT_PORT},\${ZK_QUORUM_PORT},\${ZK_ELECTION_PORT},\${SOLR_PORT},\${ACTIVEMQ_OPENWIRE_PORT},\${ACTIVEMQ_WEB_CONSOLE_PORT},\${ACTIVEMQ_AMQP_PORT},\${ACTIVEMQ_STOMP_PORT},\${ACTIVEMQ_MQTT_PORT},\${ACTIVEMQ_WS_PORT},\${POSTGRES_PORT},\${PIRANHA_PORT},\${BARRACUDA_PORT},\${SPLUNK_WEB_PORT},\${SPLUNK_MGMT_PORT},\${SPLUNK_HEC_PORT},\${SPLUNK_FORWARD_PORT}"
ENV

 chown root:autopsy "$ENV_FILE"
 chmod 0640 "$ENV_FILE"


echo
echo "[+] WADE install attempted."
echo "    Shares: //${IPV4}/${WADE_DATADIR} //${IPV4}/${WADE_CASESDIR} //${IPV4}/${WADE_STAGINGDIR}"
echo "    Zookeeper : 127.0.0.1:${ZK_CLIENT_PORT:-2181}"
echo "    Solr (UI) : http://${IPV4}:${SOLR_PORT:-8983}/solr/#/~cloud"
echo "    ActiveMQ  : ${IPV4}:${ACTIVEMQ_OPENWIRE_PORT:-61616} (web console :${ACTIVEMQ_WEB_CONSOLE_PORT:-8161})"
echo "    Postgres  : ${IPV4}:${POSTGRES_PORT:-5432}"
echo "    Barracuda  : ${IPV4}:5000"
echo "    Tools     : vol3, dissect, bulk_extractor (+ piranha, barracuda, hayabusa)"
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
          if oscap xccdf eval --skip-valid ${SKIP_ARGS} \
               --profile "${CHOSEN_PROFILE}" \
               --results-arf "${REP_ARF}" \
               --report "${REP_HTML}" \
               "${DS_FILE}"; then
            echo "[+] STIG report: ${REP_HTML}"
            echo "[+] STIG ARF   : ${REP_ARF}"
            cp -f "${DS_FILE}" "${STIG_UBU_EXTRACT_DIR}/ds.xml" 2>/dev/null || true
            mark_done "stig-eval" "$(sha256_of "${STIG_UBU_EXTRACT_DIR}/ds.xml" 2>/dev/null || echo run-${TS})"
          else
            fail_note "stig-eval" "oscap eval failed"
          fi
        fi
      fi
      [[ -n "$TMP_EXTRACT" ]] && rm -rf "$TMP_EXTRACT"
    fi
  fi
fi

finish_summary
