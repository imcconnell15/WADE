#!/usr/bin/env bash
# WADE reset + diagnostics + code audit helper (v3.0)
# - Soft/Hard reset of staging + queue
# - Optional service restart
# - Builds a diagnostics bundle for handoff
# - Optional code audit/sync against GitHub (stage_daemon, wade_workers, etc.)

set -Eeuo pipefail
umask 022

# --- Auto-escalate to root ---
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

# -------- Defaults --------
SERVICE_STAGE="wade-staging.service"
WADE_ENV="${WADE_ENV:-/etc/wade/wade.env}"

SOFT=1           # default: soft reset
HARD=0
RESTART=1
TAIL=1
ASSUME_YES=0
BUNDLE_ONLY=0

CODE_AUDIT=0     # default: no code audit
CODE_SYNC=0      # default: no code sync

LINES=400        # journal lines per service

# --- Git / code audit defaults ---
WADE_REPO_URL="${WADE_REPO_URL:-https://github.com/imcconnell15/WADE.git}"
WADE_REPO_BRANCH="${WADE_REPO_BRANCH:-main}"

# Each entry: kind|label|local_path|repo_rel_path
# - kind: "file" or "dir"
# - label: friendly name used in logs/report
# - local_path: where WADE-installed script(s) live
# - repo_rel_path: path inside the cloned repo
#
# *** TUNE THESE TO MATCH YOUR LAYOUT ***
CODE_TARGETS=(
  # Single file example: staging daemon
  "file|stage_daemon|/opt/wade/stage_daemon.py|stage_daemon.py"

  # Directory example: all wade_workers under /opt/wade/wade_workers
  "dir|wade_workers|/opt/wade/wade_workers|wade_workers"
)

# Populated during audit; list of "local|repo" pairs to sync
CODE_DIFFS=()

usage() {
  cat <<USAGE
Usage: $0 [--soft|--hard] [--no-restart] [--no-tail] [--yes] [--bundle-only]
          [--code-audit] [--code-sync]

  --soft         Soft reset (default): clear queue + optionally staging state
  --hard         Hard reset: soft reset + purge staging dedupe DB
  --no-restart   Do not restart services after reset
  --no-tail      Do not tail logs on completion
  --yes          Assume yes to any destructive prompts
  --bundle-only  Do not reset anything; just build a diagnostics bundle

  --code-audit   Clone WADE repo and audit tracked scripts (no changes)
  --code-sync    Audit + sync: replace local scripts with repo versions if different

Examples:
  $0                         # soft reset, restart services, tail logs
  $0 --hard --yes            # hard reset with no prompts, restart, tail
  $0 --bundle-only           # collect diags only, no changes
  $0 --code-audit            # only build bundle + code audit (no reset)
  $0 --code-sync --yes       # bundle + code audit + auto-sync updated scripts
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --soft)        SOFT=1 HARD=0 ;;
    --hard)        SOFT=0 HARD=1 ;;
    --no-restart)  RESTART=0 ;;
    --no-tail)     TAIL=0 ;;
    --yes|-y)      ASSUME_YES=1 ;;
    --bundle-only) BUNDLE_ONLY=1 SOFT=0 HARD=0 RESTART=0 ;;

    --code-audit)  CODE_AUDIT=1 ;;
    --code-sync)   CODE_AUDIT=1 CODE_SYNC=1 ;;
    -h|--help)     usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

log() { printf '[wade-reset] %s\n' "$*" >&2; }

# -------- Load WADE env safely --------
WADE_OWNER_USER="autopsy"
WADE_DATADIR_DEFAULT="/home/${WADE_OWNER_USER}/DataSources"
WADE_QUEUE_DIR_DEFAULT="${WADE_DATADIR_DEFAULT}/_queue"
WADE_VAR_DEFAULT="/var/wade"

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
WADE_QUEUE_DIR="${WADE_QUEUE_DIR:-$WADE_QUEUE_DIR_DEFAULT}"

# Normalize ~ in WADE_QUEUE_DIR if present
if [[ "$WADE_QUEUE_DIR" == ~* ]]; then
  WADE_QUEUE_DIR="$(eval echo "$WADE_QUEUE_DIR")"
fi

STAGING_STATE_DIR="${STAGING_STATE_DIR:-${WADE_VAR}/state}"
STAGING_DB="${STAGING_DB:-${STAGING_STATE_DIR}/staging_index.sqlite3}"
STAGING_LOG_DIR="${STAGING_LOG_DIR:-${WADE_VAR}/logs/stage}"
WORKER_LOG_DIR="${WORKER_LOG_DIR:-${WADE_VAR}/logs/workers}"

SUPPORT_BASE="/home/${WADE_OWNER_USER}/WADE/_support"
RUN_ID="wade_reset_$(date +%Y%m%d_%H%M%S)"
BUNDLE_ROOT="${SUPPORT_BASE}/${RUN_ID}"
mkdir -p "${BUNDLE_ROOT}"/{config,logs,services,queue,system} || true

QUEUE_USER="${WADE_OWNER_USER}"
QUEUE_SERVICE="wade-queue@${QUEUE_USER}.service"

# -------- Helpers --------
confirm() {
  local msg="$1"
  if [[ "$ASSUME_YES" -eq 1 ]]; then
    return 0
  fi
  read -r -p "$msg [y/N]: " ans
  [[ "$ans" =~ ^[Yy]$ ]]
}

stop_services() {
  log "Stopping ${SERVICE_STAGE} and ${QUEUE_SERVICE} (if running)…"
  systemctl stop "${SERVICE_STAGE}" 2>/dev/null || true
  systemctl stop "${QUEUE_SERVICE}" 2>/dev/null || true
}

start_services() {
  log "Starting ${SERVICE_STAGE} and ${QUEUE_SERVICE}…"
  systemctl daemon-reload || true
  systemctl start "${SERVICE_STAGE}" 2>/dev/null || true
  systemctl start "${QUEUE_SERVICE}" 2>/dev/null || true
}

soft_reset() {
  log "Performing SOFT reset…"
  stop_services

  if [[ -d "$WADE_QUEUE_DIR" ]]; then
    if confirm "Clear JSON work orders under ${WADE_QUEUE_DIR}?"; then
      find "$WADE_QUEUE_DIR" -type f -name '*.json' -print -delete \
        | sed 's/^/[wade-reset] deleted /' >&2 || true
    else
      log "Queue cleanup skipped."
    fi
  else
    log "Queue dir ${WADE_QUEUE_DIR} not found; skipping queue cleanup."
  fi
}

hard_reset() {
  log "Performing HARD reset…"
  soft_reset

  if [[ -f "$STAGING_DB" || -d "$STAGING_STATE_DIR" ]]; then
    if confirm "Purge staging dedupe DB/state under ${STAGING_STATE_DIR}?"; then
      rm -f "$STAGING_DB" 2>/dev/null || true
      # optional: wipe entire state dir
      # rm -rf "$STAGING_STATE_DIR" 2>/dev/null || true
      log "Staging state reset."
    else
      log "Staging state purge skipped."
    fi
  else
    log "No staging state found at ${STAGING_STATE_DIR}."
  fi
}

collect_diags() {
  log "Collecting diagnostics into ${BUNDLE_ROOT}…"

  # --- Basic system info ---
  {
    echo "# uname -a"; uname -a
    echo
    echo "# lsb_release / os-release"
    if command -v lsb_release >/dev/null 2>&1; then
      lsb_release -a || true
    fi
    cat /etc/os-release 2>/dev/null || true
    echo
    echo "# df -h"; df -h
    echo
    echo "# free -h"; free -h || true
  } >"${BUNDLE_ROOT}/system/sysinfo.txt" 2>&1 || true

  # --- WADE config ---
  {
    echo "# wade.env"
    [[ -f "$WADE_ENV" ]] && sed 's/^\(.*PASS.*=\).*/\1<redacted>/' "$WADE_ENV" || echo "no wade.env"
    echo
    echo "# /etc/wade/wade.conf"
    [[ -f /etc/wade/wade.conf ]] && cat /etc/wade/wade.conf || echo "no wade.conf"
  } >"${BUNDLE_ROOT}/config/wade_config.txt" 2>&1 || true

  # --- Services status & journal ---
  systemctl status "${SERVICE_STAGE}" >"${BUNDLE_ROOT}/services/${SERVICE_STAGE}.status.txt" 2>&1 || true
  journalctl -u "${SERVICE_STAGE}" -n "$LINES" --no-pager >"${BUNDLE_ROOT}/services/${SERVICE_STAGE}.journal.txt" 2>&1 || true

  systemctl status "${QUEUE_SERVICE}" >"${BUNDLE_ROOT}/services/${QUEUE_SERVICE}.status.txt" 2>&1 || true
  journalctl -u "${QUEUE_SERVICE}" -n "$LINES" --no-pager >"${BUNDLE_ROOT}/services/${QUEUE_SERVICE}.journal.txt" 2>&1 || true

  systemctl list-unit-files 'wade-*' >"${BUNDLE_ROOT}/services/wade_units.list.txt" 2>&1 || true
  systemctl list-units 'wade-*' --no-pager >"${BUNDLE_ROOT}/services/wade_units.active.txt" 2>&1 || true

  # --- Logs ---
  if [[ -d "$STAGING_LOG_DIR" ]]; then
    mkdir -p "${BUNDLE_ROOT}/logs/stage"
    cp -p "$STAGING_LOG_DIR"/* "${BUNDLE_ROOT}/logs/stage/" 2>/dev/null || true
  fi

  if [[ -d "$WORKER_LOG_DIR" ]]; then
    mkdir -p "${BUNDLE_ROOT}/logs/workers"
    cp -p "$WORKER_LOG_DIR"/* "${BUNDLE_ROOT}/logs/workers/" 2>/dev/null || true
  fi

  # --- Queue layout ---
  if [[ -d "$WADE_QUEUE_DIR" ]]; then
    {
      echo "# Queue counts by subdir:"
      find "$WADE_QUEUE_DIR" -maxdepth 3 -type f -name '*.json' \
        | sed "s|.*/_queue/||" \
        | sort | uniq -c
    } >"${BUNDLE_ROOT}/queue/queue_counts.txt" 2>&1 || true

    # sample ticket
    find "$WADE_QUEUE_DIR" -type f -name '*.json' | head -n 5 \
      | xargs -r -I{} sh -c 'echo "### {}"; head -c 2000 "{}"; echo; echo' \
      >"${BUNDLE_ROOT}/queue/sample_tickets.txt" 2>/dev/null || true
  fi

  # --- Staging state ---
  if [[ -d "$STAGING_STATE_DIR" ]]; then
    ls -l "$STAGING_STATE_DIR" >"${BUNDLE_ROOT}/system/staging_state.ls.txt" 2>&1 || true
  fi

  # --- DataSources layout snapshot ---
  if [[ -d "$WADE_DATADIR" ]]; then
    find "$WADE_DATADIR" -maxdepth 3 -mindepth 1 -type d \
      >"${BUNDLE_ROOT}/system/datasources_dirs.txt" 2>&1 || true
  fi

  # --- Tar it up ---
  mkdir -p "$SUPPORT_BASE"
  BUNDLE_TAR="${SUPPORT_BASE}/${RUN_ID}.tar.gz"
  tar -czf "$BUNDLE_TAR" -C "$SUPPORT_BASE" "$RUN_ID"
  echo "$BUNDLE_TAR" >"${BUNDLE_ROOT}/BUNDLE_PATH.txt"
  chown -R "${WADE_OWNER_USER}:${WADE_OWNER_USER}" "$SUPPORT_BASE" 2>/dev/null || true

  log "Diagnostics bundle created at: $BUNDLE_TAR"
}

tail_logs() {
  log "Tailing ${SERVICE_STAGE} and ${QUEUE_SERVICE} (Ctrl+C to stop)…"
  journalctl -u "${SERVICE_STAGE}" -u "${QUEUE_SERVICE}" -f --no-pager
}

# -------- Code audit helpers --------

GIT_CLONE_DIR=""

code_clone_repo() {
  if ! command -v git >/dev/null 2>&1; then
    log "git not found in PATH; skipping code audit."
    return 1
  fi

  local tmp_base="${WADE_VAR}/git_audit"
  mkdir -p "$tmp_base"
  local stamp
  stamp="$(date +%Y%m%d_%H%M%S)"
  GIT_CLONE_DIR="${tmp_base}/WADE_${stamp}"

  log "Cloning ${WADE_REPO_URL} (branch: ${WADE_REPO_BRANCH}) into ${GIT_CLONE_DIR}…"
  if ! git clone --depth 1 --branch "${WADE_REPO_BRANCH}" "${WADE_REPO_URL}" "${GIT_CLONE_DIR}" \
       >"${BUNDLE_ROOT}/system/git_clone.log" 2>&1; then
    log "git clone failed; see ${BUNDLE_ROOT}/system/git_clone.log"
    return 1
  fi

  return 0
}

code_audit() {
  CODE_DIFFS=()  # reset

  if ! code_clone_repo; then
    return 1
  fi

  local report="${BUNDLE_ROOT}/system/code_audit.txt"
  {
    echo "# WADE code audit - $(date -Iseconds)"
    echo "# Repo:   ${WADE_REPO_URL} (branch ${WADE_REPO_BRANCH})"
    echo "# Clone:  ${GIT_CLONE_DIR}"
    echo
  } >"$report"

  log "Auditing tracked scripts against repo…"

  for spec in "${CODE_TARGETS[@]}"; do
    IFS='|' read -r kind label local_path repo_rel <<<"$spec"

    echo "## Target: ${label}" >>"$report"
    echo "# kind=${kind} local=${local_path} repo_rel=${repo_rel}" >>"$report"

    if [[ "$kind" == "file" ]]; then
      local repo_file="${GIT_CLONE_DIR}/${repo_rel}"
      if [[ ! -f "$repo_file" ]]; then
        echo "  [WARN] Repo file missing: ${repo_file}" >>"$report"
        continue
      fi

      if [[ ! -f "$local_path" ]]; then
        echo "  [MISSING] Local file missing: ${local_path}" >>"$report"
        CODE_DIFFS+=("${local_path}|${repo_file}")
        continue
      fi

      local_hash="$(sha256sum "$local_path" 2>/dev/null | awk '{print $1}')"
      repo_hash="$(sha256sum "$repo_file" 2>/dev/null | awk '{print $1}')"

      if [[ "$local_hash" == "$repo_hash" ]]; then
        echo "  [OK] ${local_path}" >>"$report"
      else
        echo "  [DIFF] ${local_path}" >>"$report"
        echo "    local: ${local_hash}" >>"$report"
        echo "    repo : ${repo_hash}" >>"$report"
        CODE_DIFFS+=("${local_path}|${repo_file}")
      fi

    elif [[ "$kind" == "dir" ]]; then
      local repo_dir="${GIT_CLONE_DIR}/${repo_rel}"
      local local_dir="${local_path}"

      if [[ ! -d "$repo_dir" ]]; then
        echo "  [WARN] Repo dir missing: ${repo_dir}" >>"$report"
        continue
      fi

      if [[ ! -d "$local_dir" ]]; then
        echo "  [MISSING_DIR] Local dir missing: ${local_dir}" >>"$report"
        # We still audit to show what's expected
      fi

      while IFS= read -r rf; do
        rel="${rf#${repo_dir}/}"
        lf="${local_dir}/${rel}"

        if [[ ! -f "$lf" ]]; then
          echo "  [MISSING] ${lf}" >>"$report"
          CODE_DIFFS+=("${lf}|${rf}")
          continue
        fi

        local_hash="$(sha256sum "$lf" 2>/dev/null | awk '{print $1}')"
        repo_hash="$(sha256sum "$rf" 2>/dev/null | awk '{print $1}')"

        if [[ "$local_hash" == "$repo_hash" ]]; then
          echo "  [OK] ${lf}" >>"$report"
        else
          echo "  [DIFF] ${lf}" >>"$report"
          echo "    local: ${local_hash}" >>"$report"
          echo "    repo : ${repo_hash}" >>"$report"
          CODE_DIFFS+=("${lf}|${rf}")
        fi
      done < <(find "$repo_dir" -type f ! -path '*/.git/*' | sort)

    else
      echo "  [WARN] Unknown CODE_TARGET kind: ${kind}" >>"$report"
    fi

    echo >>"$report"
  done

  local diff_count="${#CODE_DIFFS[@]}"
  if [[ "$diff_count" -eq 0 ]]; then
    log "Code audit complete: no differences found."
    echo "# Summary: no differences found." >>"$report"
  else
    log "Code audit complete: ${diff_count} file(s) differ or are missing."
    echo "# Summary: ${diff_count} file(s) differ or are missing." >>"$report"
  fi

  return 0
}

code_sync() {
  local diff_count="${#CODE_DIFFS[@]}"
  if [[ "$diff_count" -eq 0 ]]; then
    log "No code differences to sync."
    return 0
  fi

  log "Preparing to sync ${diff_count} file(s) from repo to local…"
  if ! confirm "Replace local files with versions from ${WADE_REPO_URL}?"; then
    log "Code sync aborted by user."
    return 1
  fi

  for pair in "${CODE_DIFFS[@]}"; do
    IFS='|' read -r lf rf <<<"$pair"
    mkdir -p "$(dirname "$lf")"
    cp -p "$rf" "$lf"
    log "Updated ${lf} from repo."
  done

  return 0
}

# -------- Main flow --------

if [[ "$BUNDLE_ONLY" -eq 0 ]]; then
  if [[ "$HARD" -eq 1 ]]; then
    hard_reset
  elif [[ "$SOFT" -eq 1 ]]; then
    soft_reset
  fi
fi

collect_diags

# Optional code audit / sync
if [[ "$CODE_AUDIT" -eq 1 ]]; then
  code_audit || log "Code audit encountered errors (see bundle)."
  if [[ "$CODE_SYNC" -eq 1 ]]; then
    code_sync || log "Code sync encountered errors."
  fi
fi

if [[ "$RESTART" -eq 1 && "$BUNDLE_ONLY" -eq 0 ]]; then
  start_services
fi

if [[ "$RESTART" -eq 1 && "$TAIL" -eq 1 && "$BUNDLE_ONLY" -eq 0 ]]; then
  tail_logs
else
  log "Done. Bundle at: $(cat "${BUNDLE_ROOT}/BUNDLE_PATH.txt" 2>/dev/null || echo "<unknown>")."
fi
