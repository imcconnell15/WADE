-- Assumes: CREATE DATABASE whiff; and a whiff user with connect rights.
CREATE EXTENSION IF NOT EXISTS vector;

-- Main doc store for RAG
CREATE TABLE IF NOT EXISTS sage_docs (
  id UUID PRIMARY KEY,
  title TEXT,
  source_url TEXT,
  tool TEXT,
  version TEXT,
  license TEXT,
  chunk TEXT NOT NULL,
  chunk_hash TEXT NOT NULL,
  meta JSONB,
  embedding VECTOR(768) -- match your embedding model dimension
);

CREATE INDEX IF NOT EXISTS ix_docs_vec ON sage_docs
USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

CREATE INDEX IF NOT EXISTS ix_docs_tool_ver ON sage_docs(tool, version);
CREATE INDEX IF NOT EXISTS ix_docs_chunkhash ON sage_docs(chunk_hash);

-- Annotation cache (prevents regenerating help{} for same event)
CREATE TABLE IF NOT EXISTS annotation_cache (
  event_hash TEXT PRIMARY KEY,
  help JSONB NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);
