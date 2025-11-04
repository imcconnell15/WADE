#!/usr/bin/env bash
set -euo pipefail
TARBALL="$1"
DEST="/opt/whiff"
DB="${WHIFF_DB_DSN:-postgresql://whiff:whiff@127.0.0.1:5432/whiff}"

tmp="$(mktemp -d)"
tar -C "$tmp" -xzf "$TARBALL"

# Ensure schema exists
psql "$DB" -f "$DEST/sql/00_bootstrap.sql" >/dev/null 2>&1 || true

# Restore docs table
pg_restore -d "$DB" --data-only -t sage_docs "$tmp/db/sage_docs.dump"

# Drop in models if present
if [[ -f "$tmp/models/whiff-7b-q4.gguf" ]]; then
  install -D -m 0644 "$tmp/models/whiff-7b-q4.gguf" "$DEST/models/whiff-7b-q4.gguf"
fi
if [[ -d "$tmp/models/emb/e5-small-v2" ]]; then
  mkdir -p "$DEST/models/emb"
  rsync -a "$tmp/models/emb/e5-small-v2" "$DEST/models/emb/"
fi

echo "Imported KB into $DB and copied any bundled models."
