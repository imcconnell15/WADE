#!/usr/bin/env bash
# WADE - Wide-Area Data Extraction :: Bootstrap Installer (soft-fail)
# Author: Ian McConnell
# Behavior:
# - Continues installing other components if one fails
# - Aggregates failures & prints a summary at the end (exit 2 if any failed)

set -Euo pipefail

#####################################
# Banner (ASCII)
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
# CLI flags & env
#####################################
NONINTERACTIVE=0
for arg in "${@:-}"; do
  case "$arg" in
    -y|--yes|--noninteractive) NONINTERACTIVE=1 ;;
  esac
done
NONINTERACTIVE=${WADE_NONINTERACTIVE:-$NONINTERACTIVE}
OFFLINE="${OFFLINE:-0}"

#####################################
# Logging & helpers
#####################################
LOG_DIR="/var/log/wade"; mkdir -p "$LOG_DIR"
LOG_FILE="${LOG_DIR}/install_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

require_root() { if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "[-] Run as root (sudo)."; exit 1; fi; }
confirm() { [[ "$NONINTERACTIVE" -eq 1 ]] && return 0; read -r -p "${1:-Proceed?} [y/N]: " a; [[ "$a" =~ ^[Yy]$ ]]; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }
validate_cidr() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$ ]]; }

# Hard-fatal (only for true preflight errors like unsupported OS)
die(){ echo "[-] $*"; exit 1; }

# --- Soft-fail aggregation ----------------------------------------------
FAILS=()
WARNS=()

fail_note() {  # record a module failure but keep going
  local mod="$1"; shift
  local msg="${*:-failed}"
  echo "[-] [$mod] $msg"
  FAILS+=("$mod — $msg")
}

warn_note() {  # record a non-fatal warning
  local mod="$1"; shift
  local msg="${*:-warning}"
  echo "[!] [$mod] $msg"
  WARNS+=("$mod — $msg")
}

finish_summary() {
  echo
  echo "================ WADE INSTALL SUMMARY ================"
  if ((${#FAILS[@]})); then
    echo "Failed components:"
    printf ' - %s\n' "${FAILS[@]}"
  else
    echo "No component failures recorded."
  fi
  if ((${#WARNS[@]})); then
    echo
    echo "Warnings:"
    printf ' - %s\n' "${WARNS[@]}"
  fi
  echo "======================================================"
  # exit non-zero if anything failed (useful for automation)
  ((${#FAILS[@]}==0)) || exit 2
}

find_offline_src() {
  for d in /media/*/wade-offline /run/media/*/wade-offline /mnt/wade-offline /wade-offline; do
    [[ -d "$d" ]] && { echo "$d"; return 0; }
  done
  local dev; dev=$(lsblk -o NAME,LABEL,MOUNTPOINT -nr | awk '/wade-offline/ {print "/dev/"$1; exit}')
  if [[ -n "$dev" ]]; then local mnt="/mnt/wade-repo"; mkdir -p "$mnt"; mount "$dev" "$mnt" && { echo "$mnt"; return 0; }; fi
  return 1
}

#####################################
# Pre-req checks
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
# WADE scaffolding & config precedence
#####################################
WADE_ETC="/etc/wade"
WADE_VAR="/var/wade"
mkdir -p "${WADE_ETC}/"{conf.d,modules,json_injection.d} \
         "${WADE_VAR}/"{logs,state,tmp,pkg,tools.d,pipelines.d}

# Seed default wade.conf (only if missing)
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

# Pinned versions (ship tarballs under /var/wade/pkg/*)
ZOOKEEPER_VER="3.5.7"
SOLR_VER="8.6.3"
ACTIVEMQ_VER="5.14.0"

# Java/Solr defaults (size to your box)
JAVA_PACKAGE_APT="default-jdk"
JAVA_PACKAGE_RPM="java-11-openjdk"
SOLR_HEAP="96G"
SOLR_JAVA_MEM='-Xms16G -Xmx96G'
SOLR_ZK_HOST="127.0.0.1"

# PostgreSQL lab settings (unsafe for prod)
PG_LISTEN_ADDR="0.0.0.0"
PG_PERF_FSYNC="off"
PG_PERF_SYNCCOMMIT="off"
PG_PERF_FULLPAGE="off"
PG_CREATE_AUTOPSY_USER="1"

# Splunk default index for new tools (adjust live as needed)
SPLUNK_DEFAULT_INDEX="wade_custom"

# Module toggles
MOD_VOL_SYMBOLS_ENABLED="1"
MOD_BULK_EXTRACTOR_ENABLED="1"
MOD_PIRANHA_ENABLED="1"
MOD_BARRACUDA_ENABLED="1"
MOD_HAYABUSA_ENABLED="1"

# Sigma (disabled / removed from installer) & Hayabusa
SIGMA_ENABLED="0"
SIGMA_AUTOUPDATE="0"
HAYABUSA_ARCH_AUTO="1"
HAYABUSA_ARCH_OVERRIDE=""
HAYABUSA_DEST="/usr/local/bin/hayabusa"
HAYABUSA_RULES_DIR="/etc/wade/hayabusa/rules"
SIGMA_RULES_DIR="/etc/wade/sigma"
CONF
  chmod 0644 "${WADE_ETC}/wade.conf"
fi

# Seed a universal jq if missing
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
# OFFLINE repo setup (USB) & pkg managers
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
    ubuntu:*|*:"debian"*) PKG_UPDATE="apt-get update -y"; PKG_INSTALL="apt-get install -y --no-install-recommends"; PKG_REFRESH="$PKG_INSTALL"; FIREWALL="ufw"; PM="apt" ;;
    ol:*|*:"rhel"*|*:"fedora"*) if have_cmd dnf; then PKG_UPDATE="dnf -y makecache"; PKG_INSTALL="dnf -y install"; PKG_REFRESH="$PKG_INSTALL"; PM="dnf"; else PKG_UPDATE="yum -y makecache"; PKG_INSTALL="yum -y install"; PKG_REFRESH="$PKG_INSTALL"; PM="yum"; fi; FIREWALL="firewalld" ;;
    *) die "Unsupported distro (ID=${OS_ID}, LIKE=${OS_LIKE})." ;;
  esac
fi

#####################################
# Fresh-install bootstrap
#####################################
bootstrap_fresh_install() {
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
# Prompts (honor noninteractive via wade.conf)
#####################################
DEFAULT_HOSTNAME="${WADE_HOSTNAME:-$(hostname)}"
DEFAULT_OWNER="${WADE_OWNER_USER:-autopsy}"
DEFAULT_SMB_USERS="${WADE_SMB_USERS:-${DEFAULT_OWNER},KAPE}"
DEFAULT_ALLOW_NETS="${WADE_ALLOW_NETS:-}"

if [[ "$NONINTERACTIVE" -eq 1 ]]; then
  LWADE="$DEFAULT_HOSTNAME"
  LWADEUSER="$DEFAULT_OWNER"
  SMB_USERS_CSV="$DEFAULT_SMB_USERS"
  ALLOW_NETS_CSV="$DEFAULT_ALLOW_NETS"
  echo "[*] Noninteractive: using wade.conf defaults."
else
  read -r -p "Hostname for this WADE server [${DEFAULT_HOSTNAME}]: " LWADE; LWADE="${LWADE:-$DEFAULT_HOSTNAME}"
  read -r -p "Primary Linux user to own shares [${DEFAULT_OWNER}]: " LWADEUSER; LWADEUSER="${LWADEUSER:-$DEFAULT_OWNER}"
  read -r -p "Samba users (comma-separated) [${DEFAULT_SMB_USERS}]: " SMB_USERS_CSV; SMB_USERS_CSV="${SMB_USERS_CSV:-$DEFAULT_SMB_USERS}"
  read -r -p "Allowed networks CSV (optional, ex. 10.10.10.0/24,20.20.0.0/16) [${DEFAULT_ALLOW_NETS}]: " ALLOW_NETS_CSV; ALLOW_NETS_CSV="${ALLOW_NETS_CSV:-$DEFAULT_ALLOW_NETS}"
fi
hostnamectl set-hostname "$LWADE" || true

IFS=',' read -ra ALLOW_NETS_ARR <<< "${ALLOW_NETS_CSV// /}"
for net in "${ALLOW_NETS_ARR[@]:-}"; do [[ -n "$net" ]] && ! validate_cidr "$net" && warn_note "precheck" "Invalid CIDR ignored: $net"; done
IFS=',' read -ra SMBUSERS <<< "${SMB_USERS_CSV}"

if ! id -u "$LWADEUSER" >/dev/null 2>&1; then
  echo "[*] Creating user ${LWADEUSER}…"
  useradd -m -s /bin/bash "$LWADEUSER" || fail_note "useradd" "could not create ${LWADEUSER}"
  if [[ "$NONINTERACTIVE" -eq 0 ]]; then
    while :; do read -s -p "Password for ${LWADEUSER}: " p1; echo; read -s -p "Confirm: " p2; echo; [[ "$p1" == "$p2" && -n "$p1" ]] && break; echo "Mismatch/empty. Try again."; done
    echo "${LWADEUSER}:${p1}" | chpasswd || warn_note "useradd" "could not set password for ${LWADEUSER}"
  fi
  usermod -aG sudo "$LWADEUSER" || true
fi
for u in "${SMBUSERS[@]}"; do
  u=$(echo "$u" | xargs)
  id -u "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u" || warn_note "useradd" "failed creating $u"
done

if [[ "$NONINTERACTIVE" -eq 0 ]]; then
  echo
  echo "===== Summary ====="
  echo " Hostname     : $LWADE"
  echo " Linux Owner  : $LWADEUSER"
  echo " SMB users    : ${SMB_USERS_CSV}"
  echo " Allow nets   : ${ALLOW_NETS_CSV:-<none>}"
  echo " Offline mode : ${OFFLINE}"
  confirm "Proceed with installation?" || exit 0
fi

#####################################
# Core packages
#####################################
( set -e
  WANTED_PKGS_COMMON=(samba cifs-utils jq inotify-tools plocate libewf2 ewf-tools pipx zip unzip)
  if [[ "$PM" == "apt" ]]; then
    JAVA_PKG="${JAVA_PACKAGE_APT:-default-jdk}"
    bash -lc "$PKG_UPDATE"
    bash -lc "$PKG_INSTALL ${WANTED_PKGS_COMMON[*]} ufw ${JAVA_PKG}"
  else
    JAVA_PKG="${JAVA_PACKAGE_RPM:-java-11-openjdk}"
    bash -lc "$PKG_UPDATE"
    EXTRA_RPM=(policycoreutils policycoreutils-python-utils setools-console "$JAVA_PKG")
    bash -lc "$PKG_INSTALL ${WANTED_PKGS_COMMON[*]} firewalld ${EXTRA_RPM[*]}" || true
    systemctl enable firewalld --now || true
  fi
) || fail_note "core_packages" "base packages failed"

#####################################
# Shares (DataSources, Cases, Staging)
#####################################
( set -e
  DATADIR="/home/${LWADEUSER}/${WADE_DATADIR}"
  CASESDIR="/home/${LWADEUSER}/${WADE_CASESDIR}"
  STAGINGDIR="/home/${LWADEUSER}/${WADE_STAGINGDIR}"
  mkdir -p "$DATADIR" "$CASESDIR" "$STAGINGDIR"
  chown -R "${LWADEUSER}:${LWADEUSER}" "/home/${LWADEUSER}"
  chmod 755 "/home/${LWADEUSER}" "$DATADIR" "$CASESDIR" "$STAGINGDIR"

  SMB_CONF="/etc/samba/smb.conf"; [[ -f "${SMB_CONF}.bak" ]] || cp "$SMB_CONF" "${SMB_CONF}.bak"
  HOSTS_DENY_LINE="   hosts deny = 0.0.0.0/0"
  HOSTS_ALLOW_BLOCK=""
  if [[ "${#ALLOW_NETS_ARR[@]}" -gt 0 ]]; then
    HOSTS_ALLOW_BLOCK="   hosts allow ="
    for n in "${ALLOW_NETS_ARR[@]}"; do HOSTS_ALLOW_BLOCK+=" ${n}"; done
  fi
  VALID_USERS="$(echo "${SMB_USERS_CSV}" | sed 's/ //g')"

  awk 'BEGIN{skip=0} /^\[WADE-BEGIN\]/{skip=1;next} /^\[WADE-END\]/{skip=0;next} skip==0{print}' "$SMB_CONF" > "${SMB_CONF}.tmp" && mv "${SMB_CONF}.tmp" "$SMB_CONF"
  cat <<EOF >> "$SMB_CONF"
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

  if [[ "$NONINTERACTIVE" -eq 0 ]]; then
    for u in "${SMBUSERS[@]}"; do
      u=$(echo "$u" | xargs)
      echo "[*] Set Samba password for $u"
      while :; do read -s -p "Password for $u: " sp1; echo; read -s -p "Confirm: " sp2; echo; [[ "$sp1" == "$sp2" && -n "$sp1" ]] && break; echo "Mismatch/empty. Try again."; done
      ( printf "%s\n%s\n" "$sp1" "$sp1" ) | smbpasswd -a "$u" >/dev/null
    done
  fi

  # SELinux (Oracle/RHEL)
  if have_cmd getenforce; then
    SEL=$(getenforce || echo Disabled)
    if [[ "$SEL" == "Enforcing" || "$SEL" == "Permissive" ]]; then
      setsebool -P samba_enable_home_dirs on || true
      semanage fcontext -a -t samba_share_t "/home/${LWADEUSER}(/.*)?" 2>/dev/null || true
      restorecon -Rv "/home/${LWADEUSER}" || true
    fi
  fi

  # Start Samba
  echo "[*] Enabling and starting Samba…"
  if systemctl list-unit-files | grep -q '^smbd\.service'; then systemctl enable smbd --now; systemctl list-unit-files | grep -q '^nmbd\.service' && systemctl enable nmbd --now || true
  elif systemctl list-unit-files | grep -q '^smb\.service'; then systemctl enable smb --now; systemctl list-unit-files | grep -q '^nmb\.service' && systemctl enable nmb --now || true
  else systemctl enable smbd --now 2>/dev/null || systemctl enable smb --now || true; systemctl enable nmbd --now 2>/dev/null || systemctl enable nmb --now || true; fi

  # Firewall
  echo "[*] Configuring firewall…"
  if [[ "$FIREWALL" == "ufw" ]]; then
    have_cmd ufw && { ufw allow Samba || true; }
  else
    systemctl enable firewalld --now || true
    if have_cmd firewall-cmd; then
      if [[ "${WADE_STRICT_FIREWALL:-0}" -eq 1 ]]; then
        firewall-cmd --permanent --remove-service=samba >/dev/null 2>&1 || true
        for n in "${ALLOW_NETS_ARR[@]}"; do
          firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='${n}' service name='samba' accept"
        done
      else
        firewall-cmd --permanent --add-service=samba || true
        for n in "${ALLOW_NETS_ARR[@]}"; do
          firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='${n}' service name='samba' accept"
        done
      fi
      firewall-cmd --reload || true
    fi
  fi
) || fail_note "samba_shares" "share setup failed"

#####################################
# Volatility3 & Dissect via pipx (soft-fail)
#####################################
( set -e
  export PIPX_HOME=/opt/pipx; export PIPX_BIN_DIR=/usr/local/bin; mkdir -p "$PIPX_HOME"
  python3 -m pipx ensurepath || true
  pipx install --force volatility3
  pipx install --force dissect --include-deps
) || fail_note "pipx_tools" "volatility3/dissect install failed"

#####################################
# Helpers
#####################################
# fetch_pkg: try to copy from /var/wade/pkg or $OFFLINE_SRC; NEVER die here.
fetch_pkg() {
  # $1 subdir (zookeeper|solr|activemq|autopsy|volatility3/symbols|bulk_extractor|piranha|barracuda|hayabusa), $2 filename
  local sub="$1" file="$2"
  local local_pkg="${WADE_PKG_DIR}/${sub}/${file}"
  if [[ -f "$local_pkg" ]]; then cp "$local_pkg" .; return 0; fi
  if [[ "$OFFLINE" == "1" ]]; then
    local off="${OFFLINE_SRC}/${sub}/${file}"
    [[ -f "$off" ]] && { cp "$off" .; return 0; }
  fi
  return 1
}

detect_hayabusa_arch() {
  local arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) echo "lin-x64-gnu" ;;
    aarch64|arm64) echo "lin-aarch64-gnu" ;;
    *) echo "lin-x64-gnu" ;;
  esac
}

#####################################
# Volatility3 symbol packs (+SHA256 verify if available, soft-fail)
#####################################
if [[ "${MOD_VOL_SYMBOLS_ENABLED:-1}" == "1" ]]; then
( set -e
  echo "[*] Installing Volatility3 symbol packs… (first use may build cache for a while)"
  mkdir -p /usr/local/bin/symbols
  VOL_SYM_DIR="$(find /opt/pipx/venvs/volatility3 -type d -path '*/site-packages/volatility3/symbols' | head -1 || true)"
  [[ -n "$VOL_SYM_DIR" ]] || VOL_SYM_DIR="/usr/local/bin/symbols"
  mkdir -p "$VOL_SYM_DIR"
  for z in windows.zip mac.zip linux.zip; do
    fetch_pkg "volatility3/symbols" "$z" || curl -L "https://downloads.volatilityfoundation.org/volatility3/symbols/${z}" -o "$z"
    [[ -f "$z" ]] || { echo "missing $z"; exit 1; }
    cp -f "$z" "$VOL_SYM_DIR/"
    cp -f "$z" /usr/local/bin/symbols/ || true
  done
  if curl -fsSL "https://downloads.volatilityfoundation.org/volatility3/symbols/SHA256SUMS" -o "SHA256SUMS"; then
    for z in windows.zip mac.zip linux.zip; do
      if grep -q " ${z}\$" SHA256SUMS; then
        echo "$(grep " ${z}\$" SHA256SUMS)" | sha256sum -c - || echo "[!] SHA256 check failed for ${z}"
      fi
    done
  else
    echo "[!] Could not obtain SHA256SUMS; skipping verification."
  fi
) || fail_note "volatility_symbols" "download/verify failed"
fi

#####################################
# bulk_extractor (always build from source; soft-fail)
#####################################
if [[ "${MOD_BULK_EXTRACTOR_ENABLED:-1}" == "1" ]]; then
( set -e
  echo "[*] Installing bulk_extractor from source…"

  BE_PREFIX="${WADE_TOOLS_DIR:-/opt/wade/tools.d}/bulk_extractor"
  mkdir -p "$BE_PREFIX" /var/tmp/wade/build
  BUILD_DIR="$(mktemp -d /var/tmp/wade/build/be.XXXXXX)"

  if [[ "$PM" == "apt" ]]; then
    bash -lc "$PKG_INSTALL -y --no-install-recommends \
      git ca-certificates build-essential autoconf automake libtool pkg-config \
      flex bison \
      libewf-dev libssl-dev zlib1g-dev libxml2-dev libexiv2-dev libtre-dev \
      libsqlite3-dev libpcap-dev libre2-dev libpcre3-dev libexpat1-dev || true"
  else
    bash -lc "$PKG_INSTALL -y @'Development Tools' || true"
    bash -lc "$PKG_INSTALL -y git ca-certificates libewf-devel openssl-devel \
      zlib-devel libxml2-devel exiv2-devel tre-devel sqlite-devel libpcap-devel \
      re2-devel pcre-devel expat-devel flex bison || true"
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
) || fail_note "bulk_extractor" "build/install failed (see ${LOG_FILE})"
fi

#####################################
# Piranha (venv + launcher) — soft-fail
#####################################
if [[ "${MOD_PIRANHA_ENABLED:-1}" == "1" ]]; then
( set -e
  echo "[*] Installing Piranha…"
  install -d /opt/piranha
  if [[ "$OFFLINE" == "1" ]]; then
    PKG_ARC="$(ls "${WADE_PKG_DIR}/piranha/"piranha*.tar.gz "${WADE_PKG_DIR}/piranha/"piranha*.zip 2>/dev/null | head -1 || true)"
    [[ -n "$PKG_ARC" ]] || { echo "offline Piranha archive missing"; exit 1; }
    cp "$PKG_ARC" /opt/piranha/
    pushd /opt/piranha >/dev/null
    [[ "$PKG_ARC" == *.zip ]] && unzip -o "$(basename "$PKG_ARC")" || tar -xzf "$(basename "$PKG_ARC")"
    popd >/dev/null
  else
    git clone https://github.com/williamjsmail/piranha /opt/piranha || true
  fi
  python3 -m venv /opt/piranha/.venv || python3 -m virtualenv /opt/piranha/.venv
  /opt/piranha/.venv/bin/pip install --upgrade pip
  [[ -f /opt/piranha/requirements.txt ]] && /opt/piranha/.venv/bin/pip install -r /opt/piranha/requirements.txt || true
  cat >/usr/local/bin/piranha <<'EOF'
#!/usr/bin/env bash
exec /opt/piranha/.venv/bin/python /opt/piranha/piranha.py "$@"
EOF
  chmod 0755 /usr/local/bin/piranha
) || fail_note "piranha" "setup failed"
fi

#####################################
# Barracuda (venv + launcher) — soft-fail
#####################################
if [[ "${MOD_BARRACUDA_ENABLED:-1}" == "1" ]]; then
( set -e
  echo "[*] Installing Barracuda…"
  install -d /opt/barracuda
  if [[ "$OFFLINE" == "1" ]]; then
    PKG_ARC="$(ls "${WADE_PKG_DIR}/barracuda/"barracuda*.tar.gz "${WADE_PKG_DIR}/barracuda/"barracuda*.zip 2>/dev/null | head -1 || true)"
    [[ -n "$PKG_ARC" ]] || { echo "offline Barracuda archive missing"; exit 1; }
    cp "$PKG_ARC" /opt/barracuda/
    pushd /opt/barracuda >/dev/null
    [[ "$PKG_ARC" == *.zip ]] && unzip -o "$(basename "$PKG_ARC")" || tar -xzf "$(basename "$PKG_ARC")"
    popd >/dev/null
  else
    git clone https://github.com/williamjsmail/Barracuda /opt/barracuda || true
  fi
  python3 -m venv /opt/barracuda/.venv || python3 -m virtualenv /opt/barracuda/.venv
  /opt/barracuda/.venv/bin/pip install --upgrade pip
  [[ -f /opt/barracuda/requirements.txt ]] && /opt/barracuda/.venv/bin/pip install -r /opt/barracuda/requirements.txt || true
  cat >/usr/local/bin/barracuda <<'EOF'
#!/usr/bin/env bash
exec /opt/barracuda/.venv/bin/python /opt/barracuda/app.py "$@"
EOF
  chmod 0755 /usr/local/bin/barracuda
) || fail_note "barracuda" "setup failed"
fi

#####################################
# Hayabusa (binary; robust extract) — soft-fail
#####################################
if [[ "${MOD_HAYABUSA_ENABLED:-1}" == "1" ]]; then
( set -e
  echo "[*] Installing Hayabusa…"
  install -d "$(dirname "${HAYABUSA_DEST}")"

  HAY_ARCH="$(detect_hayabusa_arch)"
  HAY_ZIP=""
  HAY_ZIP_LOCAL="$(ls "${WADE_PKG_DIR}/hayabusa/"hayabusa-*-${HAY_ARCH}.zip 2>/dev/null | sort -V | tail -1 || true)"
  if [[ -n "$HAY_ZIP_LOCAL" ]]; then
    cp "$HAY_ZIP_LOCAL" .
    HAY_ZIP="$(basename "$HAY_ZIP_LOCAL")"
  elif [[ "$OFFLINE" == "1" ]]; then
    HAY_ZIP_USB="$(ls "${OFFLINE_SRC}/hayabusa/"hayabusa-*-${HAY_ARCH}.zip 2>/dev/null | sort -V | tail -1 || true)"
    [[ -n "$HAY_ZIP_USB" ]] || { echo "Hayabusa zip for arch '${HAY_ARCH}' not found offline"; exit 1; }
    cp "$HAY_ZIP_USB" .
    HAY_ZIP="$(basename "$HAY_ZIP_USB")"
  else
    if have_cmd curl && have_cmd jq; then
      echo "[*] Downloading latest Hayabusa release for ${HAY_ARCH}…"
      DL_URL="$(curl -fsSL https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest \
        | jq -r --arg pat "$HAY_ARCH" '.assets[] | select(.name | test($pat)) | .browser_download_url' | head -1)"
      [[ -n "$DL_URL" ]] || { echo "Could not resolve latest Hayabusa asset for ${HAY_ARCH}"; exit 1; }
      HAY_ZIP="$(basename "$DL_URL")"
      curl -L "$DL_URL" -o "$HAY_ZIP"
    else
      echo "curl/jq required to auto-fetch Hayabusa online"; exit 1
    fi
  fi

  TMPDIR="$(mktemp -d)"; cleanup(){ rm -rf "$TMPDIR"; }; trap cleanup EXIT
  unzip -qo "$HAY_ZIP" -d "$TMPDIR"

  # Robust binary detection: don’t require exec perms; we’ll set them.
  HAY_BIN_PATH="$(find "$TMPDIR" -type f \( -name 'hayabusa' -o -name 'hayabusa-*' \) \
                  ! -path '*/rules/*' ! -path '*/config/*' | head -1 || true)"
  if [[ -z "$HAY_BIN_PATH" ]]; then
    echo "Hayabusa binary not found in ${HAY_ZIP}. Contents:"
    find "$TMPDIR" -maxdepth 3 -type f -printf '  %P\n'
    exit 1
  fi

  install -m 0755 "$HAY_BIN_PATH" "${HAYABUSA_DEST}"
  echo "[+] Installed Hayabusa to ${HAYABUSA_DEST}"

  # Optional content from the archive
  [[ -d "$TMPDIR/rules"  ]] && { cp -r "$TMPDIR/rules"  /usr/local/bin/; echo "[+] Copied Hayabusa rules/ to /usr/local/bin/rules"; }
  [[ -d "$TMPDIR/config" ]] && { cp -r "$TMPDIR/config" /usr/local/bin/; echo "[+] Copied Hayabusa config/ to /usr/local/bin/config"; }

  # Smoke test
  "${HAYABUSA_DEST}" --help >/dev/null 2>&1 || { echo "Hayabusa post-install test failed"; exit 1; }
) || fail_note "hayabusa" "binary/rules copy failed"
fi

#####################################
# Zookeeper (pinned) — soft-fail
#####################################
( set -e
  ZOOKEEPER_TGZ="apache-zookeeper-${ZOOKEEPER_VER}-bin.tar.gz"
  fetch_pkg zookeeper "$ZOOKEEPER_TGZ" || curl -L "https://archive.apache.org/dist/zookeeper/zookeeper-${ZOOKEEPER_VER}/${ZOOKEEPER_TGZ}" -o "$ZOOKEEPER_TGZ"
  [[ -f "$ZOOKEEPER_TGZ" ]] || { echo "ZooKeeper tarball missing"; exit 1; }
  id zookeeper >/dev/null 2>&1 || useradd --system -s /usr/sbin/nologin zookeeper
  mkdir -p /opt/zookeeper /var/lib/zookeeper
  tar -xzf "$ZOOKEEPER_TGZ" -C /opt/zookeeper --strip-components 1
  cat >/opt/zookeeper/conf/zoo.cfg <<'EOF'
ticktime=2000
dataDir=/var/lib/zookeeper
clientPort=2181
maxClientCnxns=60
4lw.commands.whitelist=mntr,conf,ruok
EOF
  chown -R zookeeper:zookeeper /opt/zookeeper /var/lib/zookeeper
  cat >/etc/systemd/system/zookeeper.service <<'EOF'
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
) || fail_note "zookeeper" "install/config failed"

#####################################
# Solr (pinned, cloud mode) — soft-fail
#####################################
( set -e
  SOLR_TGZ="solr-${SOLR_VER}.tgz"
  fetch_pkg solr "$SOLR_TGZ" || curl -L "https://archive.apache.org/dist/lucene/solr/${SOLR_VER}/${SOLR_TGZ}" -o "$SOLR_TGZ"
  [[ -f "$SOLR_TGZ" ]] || { echo "Solr tgz missing"; exit 1; }
  tar -xvzf "$SOLR_TGZ" "solr-${SOLR_VER}/bin/install_solr_service.sh" --strip-components=2
  bash ./install_solr_service.sh "$SOLR_TGZ"
  IPV4=$(hostname -I 2>/dev/null | awk '{print $1}')
  sed -i "s/^#\?SOLR_HEAP=.*/SOLR_HEAP=\"${SOLR_HEAP}\"/" /etc/default/solr.in.sh
  sed -i "s|^#\?SOLR_JAVA_MEM=.*|SOLR_JAVA_MEM=\"${SOLR_JAVA_MEM}\"|" /etc/default/solr.in.sh
  if grep -q '^#\?ZK_HOST=' /etc/default/solr.in.sh; then
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
) || fail_note "solr" "install/config failed"

#####################################
# ActiveMQ (pinned) — soft-fail
#####################################
( set -e
  ACTIVEMQ_TGZ="apache-activemq-${ACTIVEMQ_VER}-bin.tar.gz"
  fetch_pkg activemq "$ACTIVEMQ_TGZ" || curl -L "https://archive.apache.org/dist/activemq/${ACTIVEMQ_VER}/${ACTIVEMQ_TGZ}" -o "$ACTIVEMQ_TGZ"
  [[ -f "$ACTIVEMQ_TGZ" ]] || { echo "ActiveMQ tarball missing"; exit 1; }
  id activemq >/dev/null 2>&1 || useradd --system -s /usr/sbin/nologin activemq
  mkdir -p /opt/activemq; tar -xzf "$ACTIVEMQ_TGZ" -C /opt/activemq --strip-components 1
  chown -R activemq:activemq /opt/activemq
  cat >/etc/systemd/system/activemq.service <<'EOF'
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
) || fail_note "activemq" "install/config failed"

#####################################
# systemd units: Piranha & Barracuda (soft-fail-ish — only if present)
#####################################
( set -e
  if [[ -x /opt/piranha/.venv/bin/python && -f /opt/piranha/piranha.py ]]; then
    cat >/etc/systemd/system/piranha.service <<EOF
[Unit]
Description=WADE Piranha (DFIR helper)
After=network-online.target
Wants=network-online.target
ConditionPathExists=/opt/piranha/.venv/bin/python
ConditionPathExists=/opt/piranha/piranha.py

[Service]
Type=simple
User=${LWADEUSER}
Group=${LWADEUSER}
WorkingDirectory=/opt/piranha
EnvironmentFile=-/etc/wade/wade.env
Environment=PYTHONUNBUFFERED=1
ExecStart=/opt/piranha/.venv/bin/python /opt/piranha/piranha.py
Restart=on-failure
RestartSec=5s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=true
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now piranha.service || true
  fi

  if [[ -x /opt/barracuda/.venv/bin/python && -f /opt/barracuda/app.py ]]; then
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
ExecStart=/opt/barracuda/.venv/bin/python /opt/barracuda/app.py
Restart=on-failure
RestartSec=5s
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=true
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now barracuda.service || true
  fi
) || fail_note "systemd_helpers" "unit creation failed"

#####################################
# PostgreSQL (Ubuntu path) — soft-fail on install/config
#####################################
if [[ "$PM" == "apt" ]]; then
( set -e
  bash -lc "$PKG_INSTALL postgresql"
  systemctl enable postgresql
  PG_VER=$(psql -V | awk '{print $3}' | cut -d. -f1)
  PG_DIR="/etc/postgresql/${PG_VER}/main"
  sed -ri "s/^#?fsync\s*=.*/fsync = ${PG_PERF_FSYNC}/" "${PG_DIR}/postgresql.conf"
  sed -ri "s/^#?synchronous_commit\s*=.*/synchronous_commit = ${PG_PERF_SYNCCOMMIT}/" "${PG_DIR}/postgresql.conf"
  sed -ri "s/^#?full_page_writes\s*=.*/full_page_writes = ${PG_PERF_FULLPAGE}/" "${PG_DIR}/postgresql.conf"
  sed -ri "s/^#?listen_addresses\s*=.*/listen_addresses = '${PG_LISTEN_ADDR}'/" "${PG_DIR}/postgresql.conf"
  for n in "${ALLOW_NETS_ARR[@]}"; do echo "host all all ${n} md5" >> "${PG_DIR}/pg_hba.conf"; done
  systemctl restart postgresql
  if [[ "${PG_CREATE_AUTOPSY_USER:-1}" == "1" && "$NONINTERACTIVE" -eq 0 ]]; then
    echo "[*] Create Postgres role 'autopsy' (for Autopsy DB)…"
    read -s -p "Password for postgres role 'autopsy': " DBP1; echo; read -s -p "Confirm: " DBP2; echo
    [[ "$DBP1" == "$DBP2" && -n "$DBP1" ]] || { echo "DB password mismatch/empty"; exit 1; }
    sudo -u postgres psql -v ON_ERROR_STOP=1 -c "DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='autopsy') THEN CREATE USER autopsy WITH ENCRYPTED PASSWORD '${DBP1}'; END IF; END \$\$;"
    sudo -u postgres psql -c "ALTER USER autopsy CREATEDB;"
  fi
) || fail_note "postgresql" "install/config failed"
fi

#####################################
# Persist facts & finish
#####################################
ENV_FILE="${WADE_ETC}/wade.env"
cat > "$ENV_FILE" <<ENV
WADE_HOSTNAME="${LWADE}"
WADE_OWNER_USER="${LWADEUSER}"
WADE_SMB_USERS="${SMB_USERS_CSV}"
WADE_ALLOW_NETS="${ALLOW_NETS_CSV}"
WADE_DATADIR="${WADE_DATADIR}"
WADE_CASESDIR="${WADE_CASESDIR}"
WADE_STAGINGDIR="${WADE_STAGINGDIR}"
WADE_LOG_DIR="${WADE_LOG_DIR}"
WADE_PKG_DIR="${WADE_PKG_DIR}"
WADE_TOOLS_DIR="${WADE_TOOLS_DIR}"
WADE_PIPELINES_DIR="${WADE_PIPELINES_DIR}"
SPLUNK_DEFAULT_INDEX="${SPLUNK_DEFAULT_INDEX:-wade_custom}"
HAYABUSA_DEST="${HAYABUSA_DEST}"
HAYABUSA_RULES_DIR="${HAYABUSA_RULES_DIR}"
SIGMA_RULES_DIR="${SIGMA_RULES_DIR}"
OFFLINE="${OFFLINE}"
ENV
chmod 600 "$ENV_FILE"

IPV4=$(hostname -I 2>/dev/null | awk '{print $1}')
echo
echo "[+] WADE install attempted."
echo "    Shares: //${IPV4}/${WADE_DATADIR} //${IPV4}/${WADE_CASESDIR} //${IPV4}/${WADE_STAGINGDIR}"
echo "    Zookeeper : 127.0.0.1:2181"
echo "    Solr (UI) : http://${IPV4}:8983/solr/#/~cloud"
echo "    ActiveMQ  : ${IPV4}:61616"
echo "    Postgres  : ${IPV4}:5432"
echo "    Tools     : vol3, dissect, bulk_extractor (+ piranha, barracuda, hayabusa)"
echo "    Hayabusa  : binary at ${HAYABUSA_DEST}; rules/config copied if present"
echo "    Config    : ${WADE_ETC}/wade.conf (defaults), ${WADE_ETC}/wade.env (facts)"
echo "    Log       : ${LOG_FILE}"
echo
echo "NOTE: New tools default to SPLUNK index: '${SPLUNK_DEFAULT_INDEX:-wade_custom}'."

# Final summary + non-zero exit if anything failed
finish_summary
