#!/usr/bin/env bash
set -euo pipefail
OUT="${1:-/tmp/whiff_kb_$(date +%Y%m%d).tgz}"
DB="${WHIFF_DB_DSN:-postgresql://whiff:whiff@127.0.0.1:5432/whiff}"

work="$(mktemp -d)"
mkdir -p "$work/db" "$work/ingest" "$work/models"

# Export only the docs table data in Postgres custom format (data-only)
pg_dump "$DB" -t sage_docs -a -Fc -f "$work/db/sage_docs.dump"

# Include sites.yaml for provenance + potential re-crawls
if [[ -f /opt/whiff/ingest/sites.yaml ]]; then
  cp /opt/whiff/ingest/sites.yaml "$work/ingest/sites.yaml"
fi

# (Optional) include models if you want a single self-contained tarball.
# WARNING: big files. Comment out if you prefer to copy models separately.
if [[ -f /opt/whiff/models/whiff-7b-q4.gguf ]]; then
  cp /opt/whiff/models/whiff-7b-q4.gguf "$work/models/"
fi
if [[ -d /opt/whiff/models/emb/e5-small-v2 ]]; then
  rsync -a /opt/whiff/models/emb/e5-small-v2 "$work/models/emb/"
fi

tar -C "$work" -czf "$OUT" .
echo "Wrote $OUT"
