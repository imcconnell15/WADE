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
# Absolute path to the directory of this script, even under sudo
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" >/dev/null 2>&1 && pwd -P)"
# Primary place we look for DISA STIG zips/XML packaged with the repo
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
get_mark_ver(){ local step="$1"; [[ -f "${STEPS_DIR}/${step}.ver" ]] && cat "${STEPS_DIR}/${step}.ver" || echo ""; }
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
get_ver_hayabusa(){ "${HAYABUSA_DEST:-/usr/local/bin/hayabusa}" --version 2>&1 | grep -Eo '[0-9]+(\.[0-9]+)*' | head -1 || true; }
get_ver_solr(){ /opt/solr/bin/solr -version 2>/dev/null | awk '{print $2}' || true; }
get_ver_zk(){ [[ -x /opt/zookeeper/bin/zkServer.sh ]] && ls /opt/zookeeper/lib/* 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo ""; }
get_ver_amq(){ /opt/activemq/bin/activemq --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9.]+' | head -1 || true; }
get_ver_pg(){ psql -V 2>/dev/null | awk '{print $3}' || true; }
get_ver_pipx_vol3(){ pipx list 2>/dev/null | awk '/package volatility3 /{print $3}' | tr -d '()' || true; }
get_ver_pipx_dissect(){ pipx list 2>/dev/null | awk '/package dissect /{print $3}' | tr -d '()' || true; }
get_ver_stig(){ [[ -f "${STIG_UBU_EXTRACT_DIR:-/var/wade/stigs/ubuntu2404}/ds.xml" ]] && sha256_of "${STIG_UBU_EXTRACT_DIR}/ds.xml" || echo ""; }
get_ver_qtgl(){ dpkg -s libegl1 >/dev/null 2>&1 && echo present || echo ""; }  # apt branch only

#####################################
# WADE Doctor (services, shares, Splunk UF)
#####################################
wade_doctor() {
  echo "=== WADE Doctor ==="
  # Samba service state
  if systemctl is-active --quiet smbd || systemctl is-active --quiet smb; then
    echo "[*] Samba: active"
  else
    echo "[!] Samba: inactive"
  fi
  # Validate expected shares exist in smb.conf and on disk
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
  # Splunk UF
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
    # Deployment server
    DC="/opt/splunkforwarder/etc/system/local/deploymentclient.conf"
    if [[ -f "$DC" ]]; then
      DS_TARGET="$(awk -F= '/^\s*targetUri\s*=/ {gsub(/^[ \t]+|[ \t]+$/,"",$2); print $2; exit}' "$DC" 2>/dev/null)"
      if [[ -n "$DS_TARGET" ]]; then
        echo "[+] UF deployment server: $DS_TARGET"
      fi
    fi
    /opt/splunkforwarder/bin/splunk status 2>/dev/null | sed -n '1,8p' || true
  else
    echo "[!] Splunk UF not installed"
  fi
  # Ports
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

# Splunk default index for new tools (adjust live later)
SPLUNK_DEFAULT_INDEX="wade_custom"

# Module toggles
MOD_VOL_SYMBOLS_ENABLED="1"
MOD_BULK_EXTRACTOR_ENABLED="1"
MOD_PIRANHA_ENABLED="1"
MOD_BARRACUDA_ENABLED="1"
MOD_HAYABUSA_ENABLED="1"

# Sigma disabled in this build
SIGMA_ENABLED="0"
SIGMA_AUTOUPDATE="0"

# Hayabusa locations
HAYABUSA_ARCH_AUTO="1"
HAYABUSA_ARCH_OVERRIDE=""
HAYABUSA_DEST="/usr/local/bin/hayabusa"
HAYABUSA_RULES_DIR="/etc/wade/hayabusa/rules"
SIGMA_RULES_DIR="/etc/wade/sigma"

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
  WANTED_PKGS_COMMON=(samba cifs-utils jq inotify-tools plocate libewf2 ewf-tools pipx zip unzip)
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

  SMB_CONF="/etc/samba/smb.conf"
  [[ -f "${SMB_CONF}.bak" ]] || cp "$SMB_CONF" "${SMB_CONF}.bak"

  # Ensure share directories exist
  DATADIR="/home/${LWADEUSER}/${WADE_DATADIR}"
  CASESDIR="/home/${LWADEUSER}/${WADE_CASESDIR}"
  STAGINGDIR="/home/${LWADEUSER}/${WADE_STAGINGDIR}"
  mkdir -p "$DATADIR" "$CASESDIR" "$STAGINGDIR"
  chown -R "${LWADEUSER}:${LWADEUSER}" "/home/${LWADEUSER}"
  chmod 755 "/home/${LWADEUSER}" "$DATADIR" "$CASESDIR" "$STAGINGDIR"

  # Assemble allow/deny
  HOSTS_DENY_LINE="   hosts deny = 0.0.0.0/0"
  HOSTS_ALLOW_BLOCK=""
  if [[ "${#ALLOW_NETS_ARR[@]}" -gt 0 ]]; then
    HOSTS_ALLOW_BLOCK="   hosts allow ="
    for n in "${ALLOW_NETS_ARR[@]}"; do HOSTS_ALLOW_BLOCK+=" ${n}"; done
  fi

  # Users allowed on shares
  VALID_USERS="$(echo "${SMB_USERS_CSV}" | sed "s/[[:space:]]//g")"

  # Remove any prior WADE block, then append a fresh one
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

  # Validate config; rollback on failure
  if ! testparm -s >/dev/null 2>&1; then
    echo "[!] testparm failed; restoring ${SMB_CONF}.bak"
    cp -f "${SMB_CONF}.bak" "$SMB_CONF"
    exit 1
  fi

  # Create Samba passwords for listed users (interactive only)
  if [[ "$NONINTERACTIVE" -eq 0 ]]; then
    for u in "${SMBUSERS[@]}"; do
      u="$(echo "$u" | xargs)"   # trim spaces
      [[ -z "$u" ]] && continue
      echo "[*] Set Samba password for $u"
      while :; do
        read -s -p "Password for $u: " sp1; echo
        read -s -p "Confirm: " sp2; echo
        [[ "$sp1" == "$sp2" && -n "$sp1" ]] && break
        echo "Mismatch/empty. Try again."
      done
      # -s = silent (read from stdin), avoids smbpasswd’s own prompt chatter
      ( printf "%s\n%s\n" "$sp1" "$sp1" ) | smbpasswd -s -a "$u" >/dev/null
    done
  fi

  # SELinux (RHEL-like only)
  if command -v getenforce >/dev/null 2>&1; then
    SEL=$(getenforce || echo Disabled)
    if [[ "$SEL" == "Enforcing" || "$SEL" == "Permissive" ]]; then
      setsebool -P samba_enable_home_dirs on || true
      semanage fcontext -a -t samba_share_t "/home/${LWADEUSER}(/.*)?" 2>/dev/null || true
      restorecon -Rv "/home/${LWADEUSER}" || true
    fi
  fi

  # Start/enable correct service name for the platform
  if systemctl list-unit-files | grep -q "^smbd\\.service"; then
    systemctl enable smbd --now
    systemctl list-unit-files | grep -q "^nmbd\\.service" && systemctl enable nmbd --now || true
  elif systemctl list-unit-files | grep -q "^smb\\.service"; then
    systemctl enable smb --now
    systemctl list-unit-files | grep -q "^nmb\\.service" && systemctl enable nmb --now || true
  else
    systemctl enable smbd --now 2>/dev/null || systemctl enable smb --now || true
    systemctl enable nmbd --now 2>/dev/null || systemctl enable nmb --now || true
  fi

  # Firewall open for Samba
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
# pipx tools: volatility3 + dissect
#####################################
run_step "pipx-vol3" "installed" get_ver_pipx_vol3 '
  set -e
  export PIPX_HOME=/opt/pipx; export PIPX_BIN_DIR=/usr/local/bin; mkdir -p "$PIPX_HOME"
  python3 -m pipx ensurepath || true
  pipx install volatility3
' || fail_note "pipx-vol3" "install failed"

run_step "pipx-dissect" "installed" get_ver_pipx_dissect '
  set -e
  export PIPX_HOME=/opt/pipx; export PIPX_BIN_DIR=/usr/local/bin; mkdir -p "$PIPX_HOME"
  python3 -m pipx ensurepath || true
  pipx install dissect --include-deps
' || fail_note "pipx-dissect" "install failed"

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
  mkdir -p /usr/local/bin/symbols
  VOL_SYM_DIR="$(find /opt/pipx/venvs/volatility3 -type d -path "*/site-packages/volatility3/symbols" | head -1 || true)"
  [[ -n "$VOL_SYM_DIR" ]] || VOL_SYM_DIR="/usr/local/bin/symbols"
  mkdir -p "$VOL_SYM_DIR"
  for z in windows.zip mac.zip linux.zip; do
    test -f "$VOL_SYM_DIR/$z" && continue
    fetch_pkg "volatility3/symbols" "$z" || curl -L "https://downloads.volatilityfoundation.org/volatility3/symbols/${z}" -o "$z"
    cp -f "$z" "$VOL_SYM_DIR/"
  done
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
    # Ubuntu/Debian build deps
    bash -lc "$PKG_INSTALL --no-install-recommends \
      git ca-certificates build-essential autoconf automake libtool pkg-config \
      flex bison libewf-dev libssl-dev zlib1g-dev libxml2-dev libexiv2-dev \
      libtre-dev libsqlite3-dev libpcap-dev libre2-dev libpcre3-dev libexpat1-dev" || true
  else
    # RHEL/Oracle/Fedora build deps (use groupinstall for toolchain)
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

  # Prepare per-user X and matplotlib dirs so GUIs can run without sudo -E
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
  # Runtime dirs + ownership
  install -d /opt/piranha /var/log/wade/piranha
  chown -R "${LWADEUSER}:${LWADEUSER}" /opt/piranha /var/log/wade/piranha

  # Ensure the path Piranha currently logs to exists and is writable
  install -d /opt/piranha/Documents/PiranhaLogs
  chown -R "${LWADEUSER}:${LWADEUSER}" /opt/piranha/Documents

  # Symlink APT_Report.log into central logs
  ln -sf /var/log/wade/piranha/APT_Report.log /opt/piranha/Documents/PiranhaLogs/APT_Report.log || true

  # Get sources (online/offline)
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

  # venv + deps
  python3 -m venv /opt/piranha/.venv || python3 -m virtualenv /opt/piranha/.venv
  /opt/piranha/.venv/bin/pip install --upgrade pip
  [[ -f /opt/piranha/requirements.txt ]] && /opt/piranha/.venv/bin/pip install -r /opt/piranha/requirements.txt || true

   FEIX="$(ls "$LOAD_PATCH_DIR"/*.py | sort -V | tail -1)"
   rm -rf /opt/piranha/backend/loader.py
   cp "$FEIX" /opt/piranha/backend/loader.py

  # GUI wrapper (runs as calling user, no sudo/-E needed)
 # cat >/usr/local/bin/piranha <<'"EOF"'
#!/usr/bin/env bash
#set -euo pipefail
# Prefer X11 rendering when DISPLAY is set; otherwise Qt picks a suitable backend.
#export QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-xcb}"
# Per-user Matplotlib cache to avoid /opt writes
#export MPLCONFIGDIR="${MPLCONFIGDIR:-$HOME/.config/matplotlib}"
#mkdir -p "$MPLCONFIGDIR"
#cd /opt/piranha
echo 'exec /opt/piranha/.venv/bin/python /opt/piranha/piranha.py "$@"' > /usr/local/bin/piranha
#EOF
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

  # venv + deps
  python3 -m venv /opt/barracuda/.venv || python3 -m virtualenv /opt/barracuda/.venv
  /opt/barracuda/.venv/bin/pip install --upgrade pip
  [[ -f /opt/barracuda/requirements.txt ]] && /opt/barracuda/.venv/bin/pip install -r /opt/barracuda/requirements.txt || true

  # Ensure MITRE JSON is present at the canonical location
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

  # **** Hard patch: change relative JSON to absolute path ****
  # techniques = load_techniques_enriched("enterprise-attack.json")
  # -> techniques = load_techniques_enriched("/opt/barracuda/enterprise-attack.json")
  sed -i -E \
    '\''s|load_techniques_enriched\("enterprise-attack\.json"\)|load_techniques_enriched("/opt/barracuda/enterprise-attack.json")|'\'' \
    /opt/barracuda/app.py || true

  install -d -o autopsy -g autopsy -m 0750 /opt/barracuda/uploads

  # Wrapper to enforce correct CWD + headless Qt
  cat >/usr/local/bin/barracuda <<'\''EOF'\''
#!/usr/bin/env bash
export QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-offscreen}"
cd /opt/barracuda
exec /opt/barracuda/.venv/bin/python /opt/barracuda/app.py "$@"
EOF
  chmod 0755 /usr/local/bin/barracuda

  # systemd unit (WorkingDirectory + env file)
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
# (App still uses its own defaults; env variables are documented in wade.env)
ExecStart=/opt/barracuda/.venv/bin/python /opt/barracuda/app.py
Restart=on-failure
RestartSec=5s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
#ProtectHome=true

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

  # Defensive: make sure HAY_ARCH is set before any use (nounset-safe)
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

  # Autopsy configset
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
    # Known-good on Ubuntu
    bash -lc "$PKG_INSTALL openscap-scanner unzip ssg-base ssg-debderived ssg-debian ssg-nondebian ssg-applications" || true
    # Only try scap-security-guide if it actually exists (avoid noisy E: lines)
    bash -lc "apt-cache show scap-security-guide >/dev/null 2>&1 && $PKG_INSTALL scap-security-guide || true"
  else
    bash -lc "$PKG_INSTALL openscap-scanner unzip" || true
    bash -lc "$PKG_INSTALL scap-security-guide" || true
  fi
' || fail_note "stig" "could not install prerequisites"
fi

#####################################
# Persist facts & endpoints
#####################################
ENV_FILE="${WADE_ETC}/wade.env"
IPV4="$(hostname -I 2>/dev/null | awk '{print $1}')"

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

# Splunk default index for new tools
SPLUNK_DEFAULT_INDEX="${SPLUNK_DEFAULT_INDEX:-wade_custom}"

# Hayabusa locations
HAYABUSA_DEST="${HAYABUSA_DEST}"
HAYABUSA_RULES_DIR="${HAYABUSA_RULES_DIR}"
SIGMA_RULES_DIR="${SIGMA_RULES_DIR}"

# Offline flag
OFFLINE="${OFFLINE}"

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
SPLUNK_WEB_PORT="8000"
SPLUNK_MGMT_PORT="8089"
SPLUNK_HEC_PORT="8088"
SPLUNK_FORWARD_PORT="9997"

# Barracuda runtime (Flask)
BARRACUDA_APP_DIR="/opt/barracuda"
BARRACUDA_HOST="0.0.0.0"
BARRACUDA_PORT="5000"
BARRACUDA_JSON_PATH="/opt/barracuda/enterprise-attack.json"
BARRACUDA_UPLOADS_DIR="/opt/barracuda/uploads"

WADE_SERVICE_PORTS_CSV="\${SSH_PORT},\${SMB_TCP_139},\${SMB_TCP_445},\${SMB_UDP_137},\${SMB_UDP_138},\${ZK_CLIENT_PORT},\${ZK_QUORUM_PORT},\${ZK_ELECTION_PORT},\${SOLR_PORT},\${ACTIVEMQ_OPENWIRE_PORT},\${ACTIVEMQ_WEB_CONSOLE_PORT},\${ACTIVEMQ_AMQP_PORT},\${ACTIVEMQ_STOMP_PORT},\${ACTIVEMQ_MQTT_PORT},\${ACTIVEMQ_WS_PORT},\${POSTGRES_PORT},\${PIRANHA_PORT},\${BARRACUDA_PORT},\${SPLUNK_WEB_PORT},\${SPLUNK_MGMT_PORT},\${SPLUNK_HEC_PORT},\${SPLUNK_FORWARD_PORT}"
ENV
chmod 600 "$ENV_FILE"

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
echo "    Log       : ${LOG_FILE}"
echo
echo "NOTE: New tools default to SPLUNK index: '${SPLUNK_DEFAULT_INDEX:-wade_custom}'."

#####################################
# Interactive STIG assessment (end; reads from ./stigs)
#####################################
stig_list_profiles() {
  # $1 = DS or Benchmark XML
  # Handles DISA “Profiles:” block (indented) with “Id: …” plus generic fallbacks.
  local info
  info="$(oscap info "$1" 2>/dev/null || true)"

  {
    # (1) “Profiles:” block → grab Id:
    printf '%s\n' "$info" | awk '
      BEGIN{inside=0}
      /^[[:space:]]*Profiles:/ {inside=1; next}
      inside && /^[[:space:]]*Id:[[:space:]]*/ {
        sub(/^[[:space:]]*Id:[[:space:]]*/,"")
        print $1
      }
    '
    # (2) Generic “Profile: <id>”
    printf '%s\n' "$info" | sed -nE 's/^[[:space:]]*Profile[[:space:]]*:[[:space:]]*([[:alnum:]_.:-]+).*/\1/p'
    # (3) Generic “… (<id>)”
    printf '%s\n' "$info" | sed -nE 's/^[[:space:]]*Profile.*\(([[:alnum:]_.:-]+)\).*/\1/p'
  } | awk 'NF' | sort -u
}

stig_pick_profile_interactive() {
  # All UI goes to stderr so command-substitution can capture only the chosen ID on stdout.
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
      # Pick latest zip or xml from ./stigs
      CAND_ZIP="$(ls -1 "${STIG_SRC_DIR}"/*.zip 2>/dev/null | sort -V | tail -1 || true)"
      CAND_XML="$(ls -1 "${STIG_SRC_DIR}"/*.xml "${STIG_SRC_DIR}"/*.XML 2>/dev/null | sort -V | tail -1 || true)"
      DS_FILE=""; TMP_EXTRACT=""

      if [[ -n "$CAND_ZIP" ]]; then
        echo "[*] Using ZIP: $(basename "$CAND_ZIP")"
        TMP_EXTRACT="$(mktemp -d)"
        unzip -oq "$CAND_ZIP" -d "$TMP_EXTRACT"
        # Prefer datastreams; then fall back to Benchmark XML
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
            # Save a stable copy for idempotent --check summaries
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

splunk_uf_install_and_config(){
  set -e
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y || true
    apt-get install -y --no-install-recommends procps curl
  fi

  id splunkfwd >/dev/null 2>&1 || useradd --system --home-dir /opt/splunkforwarder --shell /usr/sbin/nologin splunkfwd || true

  local PKG=""
  if [[ -n "${SPLUNK_UF_DEB_URL:-}" ]]; then
    PKG="/tmp/$(basename "${SPLUNK_UF_DEB_URL}")"
    curl -L "${SPLUNK_UF_DEB_URL}" -o "$PKG"
  elif ls "${WADE_PKG_DIR:-/var/wade/pkg}"/splunkforwarder/*.deb >/dev/null 2>&1; then
    PKG="$(ls "${WADE_PKG_DIR:-/var/wade/pkg}"/splunkforwarder/*.deb | sort -V | tail -1)"
  elif ls "$SPLUNK_SRC_DIR/*.deb >/dev/null 2>&1; then
    PKG="$(ls "$SPLUNK_SRC_DIR"/*.deb | sort -V | tail -1)"
  fi

  if [[ -n "$PKG" && -f "$PKG" ]]; then
    dpkg -i "$PKG" || apt-get -f install -y
  else
    echo "[!] No UF .deb provided. Set SPLUNK_UF_DEB_URL or place a .deb under ${WADE_PKG_DIR:-/var/wade/pkg}/splunkforwarder/"
    return 1
  fi

  /opt/splunkforwarder/bin/splunk enable boot-start -systemd-managed 1 -user splunkfwd --accept-license --answer-yes

  mkdir -p /opt/splunkforwarder/etc/system/local

  local SERVER_LINE=""
  local DEFAULT_INDEX="${SPLUNK_DEFAULT_INDEX:-wade_custom}"
  local COMPRESSED="true"
  local USE_ACK="true"
  local SSL_BLOCK=""
  local DS_TARGET=""

  if [[ "${NONINTERACTIVE:-0}" -eq 0 ]]; then
    echo
    echo ">> Splunk UF configuration"
    local IDXERS
    IDXERS="$(prompt_with_default "Indexer(s) host[:port], comma-separated" "${SPLUNK_UF_RCVR_HOST:-splunk.example.org}:${SPLUNK_UF_RCVR_PORT:-9997}")"
    local DEFAULT_PORT="${SPLUNK_UF_RCVR_PORT:-9997}"
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
    if yesno_with_default "Enable indexer ACKs (useACK)?" "Y"; then USE_ACK="true"; else USE_ACK="false"; fi
    if yesno_with_default "Configure a deployment server?" "N"; then
      DS_TARGET="$(prompt_with_default "Deployment server host:port" "ds.example.org:8089")"
    fi
    if yesno_with_default "Add SSL verify (sslVerifyServerCert=true)?" "N"; then
      SSL_BLOCK=$'sslVerifyServerCert = true\nsslCommonNameToCheck = *'
    fi
  else
    SERVER_LINE="${SPLUNK_UF_RCVR_HOST:-splunk.example.org}:${SPLUNK_UF_RCVR_PORT:-9997}"
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

  if [[ -n "$DS_TARGET" ]]; then
    cat >/opt/splunkforwarder/etc/system/local/deploymentclient.conf <<DCONF
[deployment-client]

[target-broker:deploymentServer]
targetUri = ${DS_TARGET}
DCONF
  fi

  chown -R splunkfwd:splunkfwd /opt/splunkforwarder
  systemctl daemon-reload
  systemctl enable --now SplunkForwarder.service || systemctl restart SplunkForwarder.service || true
}



# Execute Splunk UF step if requested via ONLY_LIST or menu
if [[ "${ONLY_LIST:-}" == "splunk-uf" ]] || [[ ",${ONLY_LIST:-all}," == *",splunk-uf,"* ]]; then
  splunk_uf_install_and_config || echo "[!] Splunk UF install/config failed"
fi

