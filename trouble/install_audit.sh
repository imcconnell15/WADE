#!/usr/bin/env bash
# WADE install audit + diagnostics bundle (v2.0)
# - Verifies install outcomes, services, versions, shares, ports
# - Collects logs/config/state into a support tarball for handoff
# - Auto-escalates to root, safe env sourcing under set -u

set -Eeuo pipefail
umask 022

# --- Auto-escalate to root ---
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

# -------- Options ----------
LINES=400        # journalctl lines per service
BUNDLE_TAG=""    # optional suffix for the bundle name

usage() {
  cat <<USAGE
Usage: $0 [--lines N] [--tag STR] [-h]

  --lines N   journal lines per service (default: $LINES)
  --tag STR   add a suffix to the bundle name (e.g., host or ticket)
  -h          show this help

Example:
  $0 --tag pre-symposium
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --lines)
      LINES="${2:-}"
      shift 2 || { echo "Missing value for --lines" >&2; exit 1; }
      ;;
    --tag)
      BUNDLE_TAG="${2:-}"
      shift 2 || { echo "Missing value for --tag" >&2; exit 1; }
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

log() { printf '[wade-audit] %s\n' "$*" >&2; }

# -------- Load WADE env --------
WADE_ENV="${WADE_ENV:-/etc/wade/wade.env}"
WADE_OWNER_USER="autopsy"
WADE_VAR_DEFAULT="/var/wade"
WADE_DATADIR_DEFAULT="/home/${WADE_OWNER_USER}/DataSources"
WADE_STAGINGDIR_DEFAULT="/home/${WADE_OWNER_USER}/Staging"
WADE_QUEUE_DIR_DEFAULT="${WADE_DATADIR_DEFAULT}/_queue"

if [[ -f "$WADE_ENV" ]]; then
  log "Sourcing env from $WADE_ENV"
  # shellcheck disable=SC1090
  set +u
  . "$WADE_ENV"
  set -u
else
  log "Env file $WADE_ENV not found; using defaults."
fi

WADE_OWNER_USER="${WADE_OWNER_USER:-autopsy}"
WADE_VAR="${WADE_VAR:-$WADE_VAR_DEFAULT}"
WADE_DATADIR="${WADE_DATADIR:-$WADE_DATADIR_DEFAULT}"
WADE_STAGINGDIR="${WADE_STAGINGDIR:-$WADE_STAGINGDIR_DEFAULT}"
WADE_QUEUE_DIR="${WADE_QUEUE_DIR:-$WADE_QUEUE_DIR_DEFAULT}"
if [[ "$WADE_QUEUE_DIR" == ~* ]]; then
  WADE_QUEUE_DIR="$(eval echo "$WADE_QUEUE_DIR")"
fi

STAGING_LOG_DIR="${STAGING_LOG_DIR:-${WADE_VAR}/logs/stage}"
WORKER_LOG_DIR="${WORKER_LOG_DIR:-${WADE_VAR}/logs/workers}"

SUPPORT_BASE="/home/${WADE_OWNER_USER}/WADE/_support"
RUN_ID="wade_install_audit_$(date +%Y%m%d_%H%M%S)"
if [[ -n "$BUNDLE_TAG" ]]; then
  RUN_ID="${RUN_ID}_${BUNDLE_TAG}"
fi

BUNDLE_ROOT="${SUPPORT_BASE}/${RUN_ID}"
mkdir -p "${BUNDLE_ROOT}"/{config,logs,services,system,splunk,samba,queue,wade,whiff} || true

STAGE_SERVICE="wade-staging.service"
QUEUE_SERVICE="wade-queue@${WADE_OWNER_USER}.service"
WHIFF_SERVICE="whiff-api.service"   # if present

# -------- Collectors --------

collect_sysinfo() {
  log "Collecting system info…"
  {
    echo "## uname -a"; uname -a
    echo
    echo "## /etc/os-release"; cat /etc/os-release 2>/dev/null || echo "no /etc/os-release"
    echo
    echo "## lsb_release"; command -v lsb_release && lsb_release -a || echo "lsb_release not installed"
    echo
    echo "## uptime"; uptime || true
    echo
    echo "## df -h"; df -h
    echo
    echo "## free -h"; free -h || true
    echo
    echo "## lsblk"; lsblk || true
    echo
    echo "## ip addr"; ip addr show || true
    echo
    echo "## listening ports (ss -plntu)"; ss -plntu || true
  } >"${BUNDLE_ROOT}/system/sysinfo.txt" 2>&1 || true
}

collect_wade_config() {
  log "Collecting WADE config…"
  {
    echo "## /etc/wade/wade.env"
    if [[ -f "$WADE_ENV" ]]; then
      # basic redaction of secrets
      sed -E 's/(PASS|PASSWORD|SECRET)=.*/\1=<redacted>/' "$WADE_ENV"
    else
      echo "no wade.env"
    fi
    echo
    echo "## /etc/wade/wade.conf"
    [[ -f /etc/wade/wade.conf ]] && cat /etc/wade/wade.conf || echo "no wade.conf"
    echo
    echo "## /etc/wade layout"
    ls -R /etc/wade 2>/dev/null || echo "no /etc/wade dir"
  } >"${BUNDLE_ROOT}/config/wade_config.txt" 2>&1 || true
}

collect_services() {
  log "Collecting service status + journals…"

  local svc
  for svc in "$STAGE_SERVICE" "$QUEUE_SERVICE" "$WHIFF_SERVICE"; do
    if systemctl list-unit-files "$svc" >/dev/null 2>&1 || systemctl status "$svc" >/dev/null 2>&1; then
      systemctl status "$svc" >"${BUNDLE_ROOT}/services/${svc}.status.txt" 2>&1 || true
      journalctl -u "$svc" -n "$LINES" --no-pager >"${BUNDLE_ROOT}/services/${svc}.journal.txt" 2>&1 || true
    fi
  done

  systemctl list-unit-files 'wade-*' >"${BUNDLE_ROOT}/services/wade_units.list.txt" 2>&1 || true
  systemctl list-units 'wade-*' --no-pager >"${BUNDLE_ROOT}/services/wade_units.active.txt" 2>&1 || true
}

collect_logs() {
  log "Collecting WADE logs…"
  if [[ -d "$STAGING_LOG_DIR" ]]; then
    mkdir -p "${BUNDLE_ROOT}/logs/stage"
    cp -p "$STAGING_LOG_DIR"/* "${BUNDLE_ROOT}/logs/stage/" 2>/dev/null || true
  fi
  if [[ -d "$WORKER_LOG_DIR" ]]; then
    mkdir -p "${BUNDLE_ROOT}/logs/workers"
    cp -p "$WORKER_LOG_DIR"/* "${BUNDLE_ROOT}/logs/workers/" 2>/dev/null || true
  fi
  if [[ -d "${WADE_VAR}/logs" ]]; then
    mkdir -p "${BUNDLE_ROOT}/logs/var_wade"
    cp -p "${WADE_VAR}/logs"/* "${BUNDLE_ROOT}/logs/var_wade/" 2>/dev/null || true
  fi
}

collect_queue() {
  log "Collecting queue layout…"
  if [[ -d "$WADE_QUEUE_DIR" ]]; then
    {
      echo "## WADE_QUEUE_DIR=$WADE_QUEUE_DIR"
      echo
      echo "## counts by subdir:"
      find "$WADE_QUEUE_DIR" -maxdepth 3 -type f -name '*.json' \
        | sed "s|.*/_queue/||" \
        | sort | uniq -c
    } >"${BUNDLE_ROOT}/queue/queue_counts.txt" 2>&1 || true

    # dead vs live
    {
      echo "## live tickets:"
      find "$WADE_QUEUE_DIR" -type f -name '*.json' ! -name '*.dead.json' -printf '%P\n' | sort
      echo
      echo "## dead tickets:"
      find "$WADE_QUEUE_DIR" -type f -name '*.dead.json' -printf '%P\n' | sort
    } >"${BUNDLE_ROOT}/queue/queue_live_dead.txt" 2>&1 || true

    find "$WADE_QUEUE_DIR" -type f -name '*.json' | head -n 5 \
      | xargs -r -I{} sh -c 'echo "### {}"; head -c 2000 "{}"; echo; echo' \
      >"${BUNDLE_ROOT}/queue/sample_tickets.txt" 2>/dev/null || true
  else
    echo "No WADE_QUEUE_DIR at $WADE_QUEUE_DIR" >"${BUNDLE_ROOT}/queue/queue_counts.txt"
  fi
}

collect_samba() {
  log "Collecting Samba info…"
  {
    echo "## testparm -s"; testparm -s 2>&1 || echo "testparm failed"
    echo
    echo "## smb.conf"; cat /etc/samba/smb.conf 2>/dev/null || echo "no smb.conf"
    echo
    echo "## pdbedit -L (user list)"; pdbedit -L 2>/dev/null || echo "pdbedit failed"
    echo
    echo "## smbstatus"; smbstatus 2>/dev/null || echo "smbstatus failed"
  } >"${BUNDLE_ROOT}/samba/samba_status.txt" 2>&1 || true
}

collect_splunk() {
  log "Collecting Splunk info (if present)…"
  {
    echo "## splunkforwarder service"
    systemctl status splunkforwarder 2>&1 || echo "no splunkforwarder service"
    echo
    echo "## splunkd service"
    systemctl status splunk 2>&1 || echo "no splunk service"
  } >"${BUNDLE_ROOT}/splunk/splunk_status.txt" 2>&1 || true

  if [[ -d /opt/splunkforwarder/etc ]]; then
    tar -czf "${BUNDLE_ROOT}/splunk/splunkforwarder_etc.tgz" -C /opt splunkforwarder/etc 2>/dev/null || true
  fi
}

collect_whiff() {
  log "Collecting WHIFF info (if installed)…"
  {
    echo "## /etc/whiff/install.conf"
    [[ -f /etc/whiff/install.conf ]] && cat /etc/whiff/install.conf || echo "no /etc/whiff/install.conf"
    echo
    echo "## /etc/whiff/whiff.env"
    [[ -f /etc/whiff/whiff.env ]] && sed -E 's/(PASS|PASSWORD|SECRET)=.*/\1=<redacted>/' /etc/whiff/whiff.env || echo "no /etc/whiff/whiff.env"
  } >"${BUNDLE_ROOT}/whiff/whiff_config.txt" 2>&1 || true

  if [[ -d /opt/whiff ]]; then
    find /opt/whiff -maxdepth 3 -type d >"${BUNDLE_ROOT}/whiff/whiff_tree.txt" 2>&1 || true
  fi
}

collect_wade_layout() {
  log "Collecting WADE layout snapshots…"
  {
    echo "## /opt/wade"
    [[ -d /opt/wade ]] && find /opt/wade -maxdepth 3 -mindepth 1 -type d || echo "no /opt/wade"
  } >"${BUNDLE_ROOT}/wade/opt_wade_tree.txt" 2>&1 || true

  {
    echo "## /var/wade"
    [[ -d "$WADE_VAR" ]] && find "$WADE_VAR" -maxdepth 3 -mindepth 1 -type d || echo "no $WADE_VAR"
  } >"${BUNDLE_ROOT}/wade/var_wade_tree.txt" 2>&1 || true

  {
    echo "## DataSources root"
    echo "WADE_DATADIR=$WADE_DATADIR"
    [[ -d "$WADE_DATADIR" ]] && find "$WADE_DATADIR" -maxdepth 3 -mindepth 1 -type d || echo "no $WADE_DATADIR"
  } >"${BUNDLE_ROOT}/wade/datasources_tree.txt" 2>&1 || true

  {
    echo "## Staging root"
    echo "WADE_STAGINGDIR=$WADE_STAGINGDIR"
    [[ -d "$WADE_STAGINGDIR" ]] && find "$WADE_STAGINGDIR" -maxdepth 2 -mindepth 1 -type d || echo "no $WADE_STAGINGDIR"
  } >"${BUNDLE_ROOT}/wade/staging_tree.txt" 2>&1 || true
}

write_summary() {
  log "Writing summary…"
  {
    echo "WADE install audit summary"
    echo "=========================="
    echo "Date: $(date -Iseconds)"
    echo "Host: $(hostname -f 2>/dev/null || hostname)"
    echo
    echo "WADE_OWNER_USER=${WADE_OWNER_USER}"
    echo "WADE_VAR=${WADE_VAR}"
    echo "WADE_DATADIR=${WADE_DATADIR}"
    echo "WADE_STAGINGDIR=${WADE_STAGINGDIR}"
    echo "WADE_QUEUE_DIR=${WADE_QUEUE_DIR}"
    echo
    echo "Stage service status:"
    systemctl is-active "$STAGE_SERVICE" 2>/dev/null || echo "unknown"
    echo
    echo "Queue service status:"
    systemctl is-active "$QUEUE_SERVICE" 2>/dev/null || echo "unknown"
    echo
    echo "Bundle root: ${BUNDLE_ROOT}"
  } >"${BUNDLE_ROOT}/SUMMARY.txt" 2>&1 || true
}

# -------- Main --------

collect_sysinfo
collect_wade_config
collect_services
collect_logs
collect_queue
collect_samba
collect_splunk
collect_whiff
collect_wade_layout
write_summary

# Tar the whole thing
mkdir -p "$SUPPORT_BASE"
BUNDLE_TAR="${SUPPORT_BASE}/${RUN_ID}.tar.gz"
tar -czf "$BUNDLE_TAR" -C "$SUPPORT_BASE" "$RUN_ID"
echo "$BUNDLE_TAR" >"${BUNDLE_ROOT}/BUNDLE_PATH.txt"
chown -R "${WADE_OWNER_USER}:${WADE_OWNER_USER}" "$SUPPORT_BASE" 2>/dev/null || true

log "Install audit bundle created at: $BUNDLE_TAR"
echo "$BUNDLE_TAR"
