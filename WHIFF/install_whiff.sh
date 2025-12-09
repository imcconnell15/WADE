#!/usr/bin/env bash
# Whiff - DFIR RAG Companion :: Idempotent Installer (online/offline)
# Author: You + GPT
# Tested on: Ubuntu 22.04/24.04 (root required)
set -Eeuo pipefail

#####################################
# Banner
#####################################
cat <<'BANNER'

  _      __  ___ ___ ._________________________
/  \    /  \/   |   \|   \_   _____/\_   _____/ Whiff - DFIR RAG Companion
\   \/\/   /    ~    \   ||    __)   |    __)   Offline-first. CPU-friendly. Idempotent.
 \        /\    Y    /   ||     \    |     \    Llama 3.1 8B Instruct + Snowflake Arctic Embed
  \__/\  /  \___|_  /|___|\___  /    \___  /    
       \/         \/          \/         \/ 
BANNER

#####################################
# Helpers
#####################################
die(){ echo "ERROR: $*" >&2; exit 1; }
req(){ command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }
prompt() { local q="$1" d="$2" a; read -r -p "$q [$d]: " a; echo "${a:-$d}"; }
yn() { local q="$1" d="${2:-Y}" a; read -r -p "$q [${d}/$( [[ "$d" =~ ^[Yy]$ ]] && echo n || echo y )]: " a; a="${a:-$d}"; [[ "$a" =~ ^[Yy]$ ]] && echo "1" || echo "0"; }
prompt_secret_confirm() {
  local q="$1" p1 p2
  while true; do
    read -rs -p "$q: " p1; echo
    read -rs -p "Confirm $q: " p2; echo
    if [[ "$p1" == "$p2" ]]; then
      printf '%s' "$p1"
      return 0
    fi
    echo "Passwords don't match. Try again." >&2
  done
}

# ---- Resilient model download helpers (resumable + fallback) ----
: "${HF_HOME:=/opt/whiff/cache}"
: "${TRANSFORMERS_CACHE:=/opt/whiff/cache}"
export HF_HOME TRANSFORMERS_CACHE
export HF_HUB_ENABLE_HF_TRANSFER=0

# Default repos/paths (override via env before running if desired)
WHIFF_LLM_REPO="${WHIFF_LLM_REPO:-bartowski/Meta-Llama-3.1-8B-Instruct-GGUF}"
WHIFF_LLM_FILE="${WHIFF_LLM_FILE:-Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf}"
WHIFF_LLM_DIR="${WHIFF_LLM_DIR:-/opt/whiff/models}"
WHIFF_LLM_PATH_DEFAULT="${WHIFF_LLM_PATH_DEFAULT:-/opt/whiff/models/whiff-llm.gguf}"

WHIFF_EMBED_REPO="${WHIFF_EMBED_REPO:-Snowflake/snowflake-arctic-embed-m-v2.0}"
# Minimal files for SentenceTransformers CPU path (skip big ONNX files)
WHIFF_EMBED_ALLOW="${WHIFF_EMBED_ALLOW:-model.safetensors,*.json,modules.json,1_Pooling/*,configuration_hf_alibaba_nlp_gte.py,modeling_hf_alibaba_nlp_gte.py}"
WHIFF_EMBED_DIR_DEFAULT="${WHIFF_EMBED_DIR_DEFAULT:-/opt/whiff/models/emb/snowflake-m-v2}"

# Small fallback embedder (~90MB)
WHIFF_EMBED_FALLBACK_REPO="${WHIFF_EMBED_FALLBACK_REPO:-sentence-transformers/all-MiniLM-L6-v2}"
WHIFF_EMBED_FALLBACK_DIR="${WHIFF_EMBED_FALLBACK_DIR:-/opt/whiff/models/emb/all-MiniLM-L6-v2}"

# Minimum free space guard (GB) for Snowflake
WHIFF_MIN_FREE_GB="${WHIFF_MIN_FREE_GB:-6}"

check_free_gb() {  # usage: check_free_gb /opt 6
  local path="$1" min="$2"
  local kb_free; kb_free=$(df -Pk "$path" | awk 'NR==2{print $4}')
  local gb_free=$(( kb_free / 1024 / 1024 ))
  [[ $gb_free -ge $min ]]
}

# Build --allow-patterns args for huggingface-cli from a CSV string
build_allow_args() {
  local csv="$1"
  local out=()
  IFS=',' read -ra parts <<< "$csv"
  for p in "${parts[@]}"; do
    # trim whitespace
    p="${p//[[:space:]]/}"
    [[ -n "$p" ]] && out+=( "--allow-patterns" "$p" )
  done
  printf '%s\n' "${out[@]}"
}

# Minimal HF download helper using huggingface-cli (with retries)
hf_download() {  # repo pattern_or_empty dest_dir [extra_args...]
  local repo="$1" pattern="$2" dest="$3"
  shift 3
  local extra_args=("$@")

  mkdir -p "$dest"

  local attempt
  for attempt in 1 2 3; do
    if [[ -n "$pattern" ]]; then
      /opt/whiff/.venv/bin/huggingface-cli download \
        "$repo" "$pattern" \
        --local-dir "$dest" \
        --local-dir-use-symlinks False \
        "${extra_args[@]}" && return 0
    else
      /opt/whiff/.venv/bin/huggingface-cli download \
        "$repo" \
        --local-dir "$dest" \
        --local-dir-use-symlinks False \
        "${extra_args[@]}" && return 0
    fi
    sleep $((attempt*2))
  done

  return 1
}

# ---- Non-interactive plumbing (args, config, getters) ----
usage(){ cat <<EOF
Usage: $0 [--non-interactive|--ni] [--config FILE]
You can also set env vars to bypass prompts, e.g.:
  WHIFF_NONINTERACTIVE=1 INSTALL_PG_LOCAL=1 DB_HOST=127.0.0.1 DB_NAME=whiff DB_USER=whiff DB_PASS=secret \ 
  ONLINE_MODE=1 DL_MODELS_NOW=1 SEED_BASELINE_DOCS=1 RUN_INITIAL_CRAWL=0 ./install_whiff.sh
EOF
}

CONFIG_FILE=""
WHIFF_NONINTERACTIVE="${WHIFF_NONINTERACTIVE:-0}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --non-interactive|--ni) WHIFF_NONINTERACTIVE=1; shift ;;
    --config) CONFIG_FILE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 1 ;;
  esac
done

# Load simple key=value config if provided
if [[ -n "${CONFIG_FILE}" ]]; then
  # shellcheck disable=SC1090
  source "${CONFIG_FILE}"
fi

getv(){ local name="$1" default="$2"; local val="${!name:-}"; [[ -z "$val" ]] && echo "$default" || echo "$val"; }
getyn(){ local name="$1" default="$2"; local val="${!name:-}"; [[ -z "$val" ]] && val="$default"; [[ "$val" =~ ^(1|y|Y|yes|true)$ ]] && echo 1 || echo 0; }
getsecret(){
  local name="$1"; local val="${!name:-}"
  if [[ -n "$val" ]]; then echo "$val"; return; fi
  [[ "$WHIFF_NONINTERACTIVE" == "1" ]] && die "Missing required secret: $name"
  prompt_secret_confirm "$name"
}

# ----------------------------------------------------------------

#####################################
# Preflight
#####################################
[[ "$EUID" -eq 0 ]] || exec sudo -E bash "$0" "$@"
req apt-get; req systemctl; req sed; req awk; req curl; req jq; req git
command -v psql >/dev/null 2>&1 || true
[[ -n "$HF_TOKEN" ]] && export HUGGING_FACE_HUB_TOKEN="$HF_TOKEN"

#####################################
# Config (prompts OR env; supports --non-interactive)
#####################################
if [[ "$WHIFF_NONINTERACTIVE" == "1" ]]; then
  INSTALL_PG_LOCAL="$(getyn INSTALL_PG_LOCAL Y)"
  DB_HOST="$(getv DB_HOST 127.0.0.1)"
  DB_PORT="$(getv DB_PORT 5432)"
  DB_NAME="$(getv DB_NAME whiff)"
  DB_USER="$(getv DB_USER whiff)"
  DB_PASS="$(getsecret DB_PASS)"

  WHIFF_BIND="$(getv WHIFF_BIND 127.0.0.1)"
  WHIFF_PORT="$(getv WHIFF_PORT 8088)"
  WHIFF_THREADS="$(getv WHIFF_THREADS 8)"
  WHIFF_CTX="$(getv WHIFF_CTX 4096)"

  ONLINE_MODE="$(getyn ONLINE_MODE N)"
  DL_MODELS_NOW="$(getyn DL_MODELS_NOW N)"
  LLM_PATH="$(getv LLM_PATH /opt/whiff/models/whiff-llm.gguf)"
  EMBED_DIR="$(getv EMBED_DIR /opt/whiff/models/emb/snowflake-m-v2)"

  RUN_INITIAL_CRAWL="$(getyn RUN_INITIAL_CRAWL N)"
  SEED_BASELINE_DOCS="$(getyn SEED_BASELINE_DOCS N)"
  HF_TOKEN="$(getv HF_TOKEN "")"

  ENABLE_NIGHTLY_BACKFILL="$(getyn ENABLE_NIGHTLY_BACKFILL Y)"
  PATCH_WADE_ENV="$(getyn PATCH_WADE_ENV Y)"
  PACKAGE_SPLUNK_ADDON="$(getyn PACKAGE_SPLUNK_ADDON Y)"
else
  INSTALL_PG_LOCAL="$(yn "Install & configure local PostgreSQL + pgvector?" Y)"
  DB_HOST="$(prompt "Postgres host" "127.0.0.1")"
  DB_PORT="$(prompt "Postgres port" "5432")"
  DB_NAME="$(prompt "Database name" "whiff")"
  DB_USER="$(prompt "Database user" "whiff")"
  DB_PASS="$(prompt_secret_confirm "Database password")"

  WHIFF_BIND="$(prompt "Whiff bind address" "127.0.0.1")"
  WHIFF_PORT="$(prompt "Whiff port" "8088")"
  WHIFF_THREADS="$(prompt "Model CPU threads" "8")"
  WHIFF_CTX="$(prompt "Model context tokens" "4096")"

  ONLINE_MODE="$(yn "Online mode (allow model downloads + crawling now)?" N)"
  DL_MODELS_NOW="0"; [[ "$ONLINE_MODE" == "1" ]] && DL_MODELS_NOW="$(yn "Download models now via HF CLI (resumable)?" Y)"
  LLM_PATH="$(prompt "Path to LLM .gguf (if already on disk)" "/opt/whiff/models/whiff-llm.gguf")"
  EMBED_DIR="$(prompt "Path to embeddings model dir" "/opt/whiff/models/emb/snowflake-m-v2")"
  RUN_INITIAL_CRAWL="0"; [[ "$ONLINE_MODE" == "1" ]] && RUN_INITIAL_CRAWL="$(yn "Run initial crawl of tuned sites.yaml after install?" Y)"
  SEED_BASELINE_DOCS="0"; [[ "$ONLINE_MODE" == "1" ]] && SEED_BASELINE_DOCS="$(yn "Seed baseline docs now?" Y)"
  HF_TOKEN="$(prompt "Hugging Face token (press Enter to skip)" "")"

  ENABLE_NIGHTLY_BACKFILL="$(yn "Install (disabled) nightly backfill service+timer?" Y)"
  PATCH_WADE_ENV="$(yn "Add WHIFF_* toggles to /etc/wade/wade.env if present?" Y)"
  PACKAGE_SPLUNK_ADDON="$(yn "Package Splunk custom command tarball?" Y)"
fi

#####################################
# OS packages
#####################################
echo "[*] Installing OS packages…"
apt-get update -y
apt-get install -y python3-venv build-essential cmake ninja-build libopenblas-dev \
  postgresql-client jq rsync git
if [[ "$INSTALL_PG_LOCAL" == "1" ]]; then
  apt-get install -y postgresql postgresql-contrib \
    || true
  # try to get pgvector for the installed PG major (best-effort)
  apt-get install -y postgresql-16-pgvector || \
  apt-get install -y postgresql-15-pgvector || \
  apt-get install -y postgresql-14-pgvector || true
fi

#####################################
# Users & directories
#####################################
echo "[*] Creating whiff user and directories…"
id -u whiff >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin whiff
mkdir -p /opt/whiff/{scripts,ingest,sql,packaging,splunk/SA-WADE-Search/bin,splunk/SA-WADE-Search/default,models/emb,docs_ingest} \
         /etc/whiff /var/log/whiff /opt/whiff/cache
chown -R whiff:whiff /opt/whiff /var/log/whiff

#####################################
# requirements.txt
#####################################
cat > /opt/whiff/requirements.txt <<'REQ'
fastapi==0.115.0
uvicorn[standard]==0.30.6
pydantic==2.9.2
psycopg2-binary==2.9.9
numpy==2.1.1
beautifulsoup4==4.12.3
lxml==5.3.0
pypdf==5.0.0
orjson==3.10.7
requests==2.32.3
PyYAML==6.0.2
llama-cpp-python==0.2.90
sentence-transformers==3.0.1
docutils==0.20.1
python-docx==1.1.2
chardet==5.2.0
huggingface_hub[cli]==0.23.2
hf_transfer==0.1.6
REQ

#####################################
# Core Python (utils, models, API, indexer, crawler)
#####################################
cat > /opt/whiff/whiff_utils.py <<'PY'
import hashlib, json, re
VOLATILE_FIELDS = {"_time","_raw","_indextime","linecount"}
def stable_event_hash(ev: dict) -> str:
    cleaned = {k: v for k, v in ev.items() if k not in VOLATILE_FIELDS}
    s = json.dumps(cleaned, sort_keys=True, separators=(",",":"), ensure_ascii=False)
    return hashlib.sha1(s.encode("utf-8")).hexdigest()
def simple_chunks(text: str, max_words=400):
    buf, count = [], 0
    for para in re.split(r"\n\s*\n", text):
        words = para.split()
        if not words: continue
        if count + len(words) > max_words and buf:
            yield "\n\n".join(buf); buf, count = [], 0
        buf.append(para); count += len(words)
    if buf: yield "\n\n".join(buf)
PY

cat > /opt/whiff/whiff_models.py <<'PY'
import os
import numpy as np
from typing import List
from llama_cpp import Llama
_EMBED_MODEL = None
_LLM = None
def init_models():
    global _EMBED_MODEL, _LLM
    from sentence_transformers import SentenceTransformer
    embed_path = os.environ.get("WHIFF_EMBED_PATH", "/opt/whiff/models/emb/snowflake-m-v2")
    _EMBED_MODEL = SentenceTransformer(embed_path)
    llm_path = os.environ.get("WHIFF_LLM_MODEL", "/opt/whiff/models/whiff-llm.gguf")
    n_threads = int(os.environ.get("WHIFF_THREADS", "8"))
    ctx = int(os.environ.get("WHIFF_CTX", "4096"))
    _LLM = Llama(model_path=llm_path, n_threads=n_threads, n_ctx=ctx, verbose=False)
def embed_texts(texts: List[str]) -> np.ndarray:
    if _EMBED_MODEL is None: init_models()
    return _EMBED_MODEL.encode(texts, normalize_embeddings=True, convert_to_numpy=True)
def generate(prompt: str, max_tokens=400, temperature=0.2) -> str:
    if _LLM is None: init_models()
    sysmsg = "You are Whiff, a DFIR assistant. Be concise. Cite sources if given."
    out = _LLM.create_chat_completion(
        messages=[{"role":"system","content":sysmsg},{"role":"user","content":prompt}],
        temperature=temperature, max_tokens=max_tokens
    )
    return out["choices"][0]["message"]["content"].strip()
PY

cat > /opt/whiff/whiff_api.py <<'PY'
import os, json
import psycopg2, numpy as np, orjson
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
from whiff_models import embed_texts, generate
from whiff_utils import stable_event_hash
DB_DSN = os.environ.get("WHIFF_DB_DSN","host=127.0.0.1 port=5432 dbname=whiff user=whiff password=whiff")
TOP_K = int(os.environ.get("WHIFF_TOPK","6"))
app = FastAPI(title="Whiff API", version="0.1.0")
def db(): return psycopg2.connect(DB_DSN)
class AskBody(BaseModel):
    query: str; k: int = TOP_K; tool_hint: Optional[str]=None; version_hint: Optional[str]=None
class AnnotateBody(BaseModel):
    event: dict
def search_docs(q_emb: np.ndarray, k=6, tool=None, version=None):
    conn=db(); cur=conn.cursor()
    where, params = [], []
    if tool: where.append("tool = %s"); params.append(tool)
    if version: where.append("version = %s"); params.append(version)
    where_sql=("WHERE " + " AND ".join(where)) if where else ""
    sql=f"""
      SELECT title, chunk, source_url, tool, version, (embedding <#> %s::vector) AS score
      FROM sage_docs
      {where_sql}
      ORDER BY embedding <#> %s::vector
      LIMIT %s
    """
    params.extend([q_emb.tolist(), q_emb.tolist(), k])
    cur.execute(sql, params); rows=cur.fetchall(); cur.close(); conn.close()
    return [{"title":r[0],"chunk":r[1],"url":r[2],"tool":r[3],"version":r[4],"distance":float(r[5])} for r in rows]
@app.get("/health")
def health(): return {"ok": True}
@app.post("/ask")
def ask(body: AskBody):
    q_emb=embed_texts([body.query])[0]
    hits=search_docs(q_emb,k=body.k,tool=body.tool_hint,version=body.version_hint)
    context="\n\n---\n\n".join(h["chunk"] for h in hits)
    prompt=f"""Answer the user's DFIR question using ONLY the context below.
If info is missing, say you don't know. Provide: short answer, 2-4 bullet next steps, and ATT&CK IDs if clearly supported.
Include a line 'Sources:' listing titles you used.

Question:
{body.query}

Context (verbatim):
{context}
"""
    answer=generate(prompt,max_tokens=500)
    return {"answer":answer,"sources":hits}
@app.post("/annotate")
def annotate(body: AnnotateBody):
    ev=body.event; ev_hash=stable_event_hash(ev)
    conn=db(); cur=conn.cursor()
    cur.execute("SELECT help FROM annotation_cache WHERE event_hash=%s",(ev_hash,))
    row=cur.fetchone()
    if row:
        cur.close(); conn.close()
        return {"help": row[0], "cached": True}
    tool=ev.get("sourcetype") or ev.get("source") or ev.get("tool")
    version=ev.get("tool_version") or ev.get("version")
    query=f"Explain this event and suggest next steps. Event JSON:\n{json.dumps(ev,ensure_ascii=False)}"
    q_emb=embed_texts([query])[0]
    hits=search_docs(q_emb,k=6,tool=tool,version=version)
    context="\n\n---\n\n".join(h["chunk"] for h in hits)
    prompt=f"""You are Whiff. Produce STRICT JSON with keys:
summary, significance, mitre, next_steps, spl_suggestions, refs, confidence, sources_used.
- 'mitre' is a list of objects: {{tactic, technique, confidence}}. Only include ATT&CK techniques that appear in context.
- 'refs' is a list of {{title, url}}
- confidence is 0..1

Context:
{context}

Event:
{json.dumps(ev, ensure_ascii=False)}

Return ONLY JSON.
"""
    raw=generate(prompt,max_tokens=400)
    js,je=raw.find("{"), raw.rfind("}")
    if js==-1 or je==-1:
        help_obj={"summary":"Insufficient context.","significance":"","mitre":[],"next_steps":[],"spl_suggestions":[],"refs":[],"confidence":0.0,"sources_used":[]}
    else:
        try: import orjson as _oj; help_obj=_oj.loads(raw[js:je+1])
        except Exception: help_obj={"summary":"Parse error.","significance":"","mitre":[],"next_steps":[],"spl_suggestions":[],"refs":[],"confidence":0.0,"sources_used":[]}
    cur.execute("INSERT INTO annotation_cache(event_hash,help) VALUES (%s,%s) ON CONFLICT (event_hash) DO NOTHING",
                (ev_hash, orjson.dumps(help_obj).decode()))
    conn.commit(); cur.close(); conn.close()
    return {"help": help_obj, "cached": False}
PY

cat > /opt/whiff/whiff_index.py <<'PY'
import os, uuid, glob, json, csv
from pathlib import Path
import psycopg2
from bs4 import BeautifulSoup
from pypdf import PdfReader
from docx import Document as DocxDoc
from whiff_models import embed_texts
from whiff_utils import simple_chunks
import chardet

DB_DSN=os.environ.get("WHIFF_DB_DSN","host=127.0.0.1 port=5432 dbname=whiff user=whiff password=whiff")

def read_text_guess(p:Path)->str:
    raw = p.read_bytes()
    enc = chardet.detect(raw).get("encoding") or "utf-8"
    try:
        return raw.decode(enc, errors="ignore")
    except Exception:
        return raw.decode("utf-8", errors="ignore")

def load_text(p:Path)->str:
    sfx=p.suffix.lower()
    if sfx in {".md",".txt",".rst",".log",".ini",".cfg"}:
        return read_text_guess(p)
    if sfx in {".html",".htm"}:
        return BeautifulSoup(read_text_guess(p),"lxml").get_text("\n")
    if sfx == ".pdf":
        out=[]
        with open(p,"rb") as f:
            pdf=PdfReader(f)
            for pg in pdf.pages: out.append(pg.extract_text() or "")
        return "\n".join(out)
    if sfx == ".docx":
        try:
            d = DocxDoc(p)
            return "\n".join(par.text for par in d.paragraphs)
        except Exception:
            return ""
    if sfx == ".csv":
        try:
            with open(p, newline="", encoding="utf-8", errors="ignore") as f:
                reader = csv.reader(f)
                rows = ["\t".join(r) for r in reader]
            return "\n".join(rows)
        except Exception:
            return ""
    if sfx == ".json":
        try:
            obj = json.loads(read_text_guess(p))
            return json.dumps(obj, indent=2, ensure_ascii=False)
        except Exception:
            return ""
    return ""

def insert_docs(conn,rows):
    cur=conn.cursor()
    cur.executemany("""
      INSERT INTO sage_docs (id,title,source_url,tool,version,license,chunk,chunk_hash,meta,embedding)
      VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING
    """, rows)
    conn.commit(); cur.close()

def infer_meta(p:Path):
    parts = Path(p).parts
    tool="misc"; version="unknown"; license_="unknown"
    if len(parts) >= 4:
        tool = parts[-4]
        version = parts[-3]
        license_ = parts[-2]
    return tool, version, license_

def main(root="docs_ingest"):
    conn=psycopg2.connect(DB_DSN)
    for f in glob.glob(f"{root}/**/*", recursive=True):
        p=Path(f)
        if not p.is_file(): continue
        text=load_text(p).replace("\\x00","").strip()
        if not text or len(text) < 200:
            continue
        tool, version, license_ = infer_meta(p)
        meta={"filename":p.name,"source_path":str(p)}
        chunks=list(simple_chunks(text, max_words=400))
        if not chunks: continue
        embs=embed_texts(chunks)
        rows=[(str(uuid.uuid4()), p.stem[:512], None, tool, version, license_, c, str(hash(c)), json.dumps(meta), e.tolist())
              for c,e in zip(chunks, embs)]
        insert_docs(conn, rows)
    conn.close()

if __name__=="__main__":
    import sys
    main(sys.argv[1] if len(sys.argv)>1 else "docs_ingest")
PY

cat > /opt/whiff/whiff_crawl.py <<'PY'
#!/usr/bin/env python3
import os, time, re, json, urllib.parse, queue
import requests, psycopg2, yaml
from bs4 import BeautifulSoup
from pypdf import PdfReader
from whiff_models import embed_texts
from whiff_utils import simple_chunks

DB_DSN=os.getenv("WHIFF_DB_DSN","host=127.0.0.1 port=5432 dbname=whiff user=whiff password=whiff")
UA="WhiffCrawler/0.1 (+local DFIR KB builder)"

def allowed(url, allow, deny):
    ok = any(re.search(p,url) for p in allow) if allow else True
    bad = any(re.search(p,url) for p in deny) if deny else False
    return ok and not bad

def text_from_html(html):
    soup=BeautifulSoup(html,"lxml")
    for bad in soup(["script","style","nav","aside","footer","header"]): bad.decompose()
    return soup.get_text("\n", strip=True), soup

def text_from_pdf(data):
    from io import BytesIO
    r=PdfReader(BytesIO(data))
    return "\n".join((p.extract_text() or "") for p in r.pages)

def fetch(s,u):
    r=s.get(u,headers={"User-Agent":UA},timeout=15,allow_redirects=True)
    r.raise_for_status(); return r.headers.get("content-type","").lower(), r.content, r.url

def index_chunks(conn,title,url,tool,version,license_,chunks,embs):
    rows=[]
    import uuid, json as _json
    for c,e in zip(chunks,embs):
        rows.append((str(uuid.uuid4()), title[:512], url, tool, version, license_, c, str(hash(c)), _json.dumps({"source_url":url}), e.tolist()))
    cur=conn.cursor()
    cur.executemany("""
      INSERT INTO sage_docs (id,title,source_url,tool,version,license,chunk,chunk_hash,meta,embedding)
      VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
      ON CONFLICT DO NOTHING
    """, rows)
    conn.commit(); cur.close()

def crawl_site(site):
    base=site["base"].rstrip("/")
    allow=site.get("allow",[]); deny=site.get("deny",[])
    max_pages=int(site.get("max_pages",500))
    rate=float(site.get("rate_per_sec",0.5))
    tool=site.get("tool","misc"); version=site.get("version","unknown"); license_=site.get("license","unknown")
    seen=set(); q=queue.Queue(); q.put(base)
    conn=psycopg2.connect(DB_DSN); s=requests.Session()
    last=0.0; pages=0
    while not q.empty() and pages<max_pages:
        url=q.get()
        if url in seen: continue
        seen.add(url)
        if not allowed(url, allow, deny): continue
        sleep=max(0.0,(1.0/rate)-(time.time()-last))
        if sleep>0: time.sleep(sleep)
        last=time.time()
        try: ctype,data,final=fetch(s,url)
        except Exception: continue
        title=url; text=""
        if "text/html" in ctype:
            html=data.decode("utf-8","ignore")
            text,soup=text_from_html(html)
            if soup.title and soup.title.string: title=soup.title.string.strip()[:256]
            for a in soup.find_all("a", href=True):
                href=urllib.parse.urljoin(final, a["href"])
                if href.startswith(base) and allowed(href, allow, deny): q.put(href)
        elif "application/pdf" in ctype:
            text=text_from_pdf(data)
        else:
            continue
        text=text.strip()
        if not text or len(text)<200: continue
        chunks=list(simple_chunks(text, max_words=400))
        if not chunks: continue
        embs=embed_texts(chunks)
        index_chunks(conn, title, final, tool, version, license_, chunks, embs)
        pages+=1
    conn.close()

def main(cfg_path="./ingest/sites.yaml"):
    with open(cfg_path,"r",encoding="utf-8") as f: cfg=yaml.safe_load(f)
    for site in cfg.get("sites",[]): crawl_site(site)

if __name__=="__main__":
    import sys
    main(sys.argv[1] if len(sys.argv)>1 else "./ingest/sites.yaml")
PY
chmod +x /opt/whiff/whiff_crawl.py

#####################################
# SQL bootstrap
#####################################
cat > /opt/whiff/sql/00_bootstrap.sql <<'SQL'
SET search_path = whiff, public;
CREATE EXTENSION IF NOT EXISTS vector;
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
  embedding VECTOR(384)
);
CREATE INDEX IF NOT EXISTS ix_docs_vec ON sage_docs
USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
CREATE INDEX IF NOT EXISTS ix_docs_tool_ver ON sage_docs(tool, version);
CREATE INDEX IF NOT EXISTS ix_docs_chunkhash ON sage_docs(chunk_hash);
CREATE TABLE IF NOT EXISTS annotation_cache (
  event_hash TEXT PRIMARY KEY,
  help JSONB NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);
SQL

#####################################
# Ingest config (sites)
#####################################
mkdir -p /opt/whiff/ingest
cat > /opt/whiff/ingest/sites.yaml <<'YAML'
sites:
  - name: mitre-attack
    base: "https://attack.mitre.org"
    allow: ["^https://attack\\.mitre\\.org/(techniques|tactics|mitigations|datasources)/.*$"]
    deny: []
    rate_per_sec: 1.0
    max_pages: 3000
    license: "CC BY 4.0"
    tool: "mitre-attack"
    version: "v14x"

  - name: volatility3-docs
    base: "https://volatility3.readthedocs.io"
    allow: ["^https://volatility3\\.readthedocs\\.io/en/(latest|stable)/.*$"]
    deny: ["\\.(zip|tar|gz|jpg|png|gif|svg|ico)$"]
    rate_per_sec: 1.0
    max_pages: 1200
    license: "See Volatility docs license"
    tool: "volatility3"
    version: "docs-snapshot"

  - name: hayabusa-wiki
    base: "https://github.com/Yamato-Security/hayabusa/wiki"
    allow: ["^https://github\\.com/Yamato-Security/hayabusa/wiki/.*$"]
    deny: []
    rate_per_sec: 0.5
    max_pages: 600
    license: "Repo MIT; GitHub Wiki TOS (verify)"
    tool: "hayabusa"
    version: "wiki"

  - name: capa-docs
    base: "https://mandiant.github.io/capa"
    allow: ["^https://mandiant\\.github\\.io/capa/.*$"]
    deny: []
    rate_per_sec: 0.5
    max_pages: 400
    license: "Apache-2.0 (docs)"
    tool: "capa"
    version: "doc"

  - name: yara-docs
    base: "https://yara.readthedocs.io"
    allow: ["^https://yara\\.readthedocs\\.io/.*$"]
    deny: []
    rate_per_sec: 0.8
    max_pages: 600
    license: "See YARA docs license"
    tool: "yara"
    version: "docs-snapshot"

  - name: arkime-docs
    base: "https://arkime.com"
    allow: ["^https://arkime\\.com/(learn|faq|apiv3|settings).*"]
    deny: []
    rate_per_sec: 0.6
    max_pages: 400
    license: "Arkime site TOS"
    tool: "arkime"
    version: "site"

  - name: zeek-docs
    base: "https://docs.zeek.org"
    allow: ["^https://docs\\.zeek\\.org/.+"]
    deny: []
    rate_per_sec: 0.8
    max_pages: 1200
    license: "Zeek docs site"
    tool: "zeek"
    version: "docs-snapshot"

  - name: forensic-artifacts-kb
    base: "https://artifacts.readthedocs.io"
    allow: ["^https://artifacts\\.readthedocs\\.io/.*$"]
    deny: []
    rate_per_sec: 0.8
    max_pages: 800
    license: "Apache-2.0 (repo); docs site"
    tool: "forensic-artifacts"
    version: "kb"
YAML

#####################################
# Splunk custom command (package locally)
#####################################
cat > /opt/whiff/splunk/SA-WADE-Search/bin/whiff.py <<'PY'
import sys, json, requests
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option
@Configuration()
class WhiffCommand(StreamingCommand):
    max_refs = Option(require=False, default=5)
    api = Option(require=False, default="http://127.0.0.1:8088/annotate")
    def stream(self, records):
        for r in records:
            ev = dict(r)
            try:
                j = requests.post(self.api, json={"event":ev}, timeout=5).json()
                h = j.get("help", {})
                r["whiff_summary"]    = h.get("summary")
                r["whiff_next_steps"] = "; ".join(h.get("next_steps", [])[:3])
                r["whiff_mitre"]      = "; ".join(m.get("technique","") for m in h.get("mitre", []))
                r["whiff_conf"]       = h.get("confidence")
                r["whiff_refs"]       = "; ".join((x.get("title") or x.get("url","")) for x in h.get("refs", [])[:int(self.max_refs)])
            except Exception as e:
                r["whiff_error"] = str(e)
            yield r
dispatch(WhiffCommand, sys.argv, sys.stdin, sys.stdout, __name__)
PY

cat > /opt/whiff/splunk/SA-WADE-Search/default/commands.conf <<'CONF'
[whiff]
filename = whiff.py
chunked = true
passauth = true
enableheader = true
CONF

#####################################
# Scripts: helper/packer/importer/seeder
#####################################
cat > /opt/whiff/scripts/whiff-help <<'SH'
#!/usr/bin/env bash
set -euo pipefail
API="${WHIFF_API:-http://127.0.0.1:8088/annotate}"
IN="${1:-/var/wade/logs/stage/today.jsonl}"
OUT="${2:-/var/wade/logs/stage/today.with_help.jsonl}"
TMP="$(mktemp)"
jq -c 'def ann:
  . as $ev
  | (curl -s -X POST "'"$API"'" -H "Content-Type: application/json" -d ({"event":$ev}|tojson))
  | .help;
  . + {help:(ann)}' "$IN" > "$TMP"
mv "$TMP" "$OUT"
echo "Wrote $OUT"
SH
chmod +x /opt/whiff/scripts/whiff-help

cat > /opt/whiff/scripts/whiff-pack-kb.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail
OUT="${1:-/tmp/whiff_kb_$(date +%Y%m%d).tgz}"
DB="${WHIFF_DB_DSN:-host=127.0.0.1 port=5432 dbname=whiff user=whiff password=whiff}"
work="$(mktemp -d)"
mkdir -p "$work/db" "$work/ingest" "$work/models"
pg_dump "$DB" -t sage_docs -a -Fc -f "$work/db/sage_docs.dump"
[[ -f /opt/whiff/ingest/sites.yaml ]] && cp /opt/whiff/ingest/sites.yaml "$work/ingest/sites.yaml"
if [[ -f /opt/whiff/models/whiff-llm.gguf ]]; then cp /opt/whiff/models/whiff-llm.gguf "$work/models/"; fi
if [[ -d /opt/whiff/models/emb/snowflake-m-v2 ]]; then mkdir -p "$work/models/emb"; rsync -a /opt/whiff/models/emb/snowflake-m-v2 "$work/models/emb/"; fi
tar -C "$work" -czf "$OUT" .
echo "Wrote $OUT"
SH
chmod +x /opt/whiff/scripts/whiff-pack-kb.sh

cat > /opt/whiff/scripts/whiff-import-kb.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail
TARBALL="$1"
DEST="/opt/whiff"
DB="${WHIFF_DB_DSN:-host=127.0.0.1 port=5432 dbname=whiff user=whiff password=whiff}"
tmp="$(mktemp -d)"
tar -C "$tmp" -xzf "$TARBALL"
psql "$DB" -f "$DEST/sql/00_bootstrap.sql" >/dev/null 2>&1 || true
pg_restore -d "$DB" --data-only -t sage_docs "$tmp/db/sage_docs.dump"
if [[ -f "$tmp/models/whiff-llm.gguf" ]]; then install -D -m 0644 "$tmp/models/whiff-llm.gguf" "$DEST/models/whiff-llm.gguf"; fi
if [[ -d "$tmp/models/emb/snowflake-m-v2" ]]; then mkdir -p "$DEST/models/emb"; rsync -a "$tmp/models/emb/snowflake-m-v2" "$DEST/models/emb/"; fi
echo "Imported KB into $DB and copied any bundled models."
SH
chmod +x /opt/whiff/scripts/whiff-import-kb.sh

cat > /opt/whiff/scripts/whiff-seed-docs.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail
DEST="/opt/whiff/docs_ingest"
work="$(mktemp -d)"
echo "[*] Working in $work"
git clone --depth=1 https://github.com/mitre-attack/attack-stix-data "$work/attack-stix-data" >/dev/null 2>&1 || true
mkdir -p "$DEST/mitre_attack/v14.1/CC-BY-4.0"
python3 - "$work/attack-stix-data" "$DEST/mitre_attack/v14.1/CC-BY-4.0" <<'PY'
import sys, json, glob, os
root, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
for f in glob.glob(os.path.join(root,"enterprise-attack/attack-pattern/*.json")):
    with open(f,"r",encoding="utf-8") as fh:
        j=json.load(fh)
    for obj in j.get("objects",[]):
        if obj.get("type")!="attack-pattern": continue
        tid = next((x["external_id"] for x in obj.get("external_references",[]) if x.get("source_name")=="mitre-attack"), None)
        name = obj.get("name","")
        desc = obj.get("description","")
        if not tid: continue
        fn = os.path.join(out, f"{tid}-{name}.md".replace("/","_"))
        with open(fn,"w",encoding="utf-8") as w:
            w.write(f"# {tid} — {name}\n\n{desc}\n")
PY
git clone --depth=1 https://github.com/volatilityfoundation/volatility3 "$work/vol3" >/dev/null 2>&1 || true
mkdir -p "$DEST/volatility3/2.7/Apache-2.0"
rsync -a "$work/vol3/doc/" "$DEST/volatility3/2.7/Apache-2.0/" --exclude .git >/dev/null 2>&1 || true
git clone --depth=1 https://github.com/Yamato-Security/hayabusa.wiki.git "$work/hayabusa-wiki" >/dev/null 2>&1 || true
mkdir -p "$DEST/hayabusa/2.18/MIT"
rsync -a "$work/hayabusa-wiki/" "$DEST/hayabusa/2.18/MIT/" --exclude .git >/dev/null 2>&1 || true
git clone --depth=1 https://github.com/mandiant/capa "$work/capa" >/dev/null 2>&1 || true
mkdir -p "$DEST/capa/7.1/Apache-2.0"
rsync -a "$work/capa/doc/" "$DEST/capa/7.1/Apache-2.0/" --exclude .git >/dev/null 2>&1 || true
git clone --depth=1 https://github.com/VirusTotal/yara "$work/yara" >/dev/null 2>&1 || true
mkdir -p "$DEST/yara/4.5/Apache-2.0"
rsync -a "$work/yara/docs/" "$DEST/yara/4.5/Apache-2.0/" --exclude .git >/dev/null 2>&1 || true
git clone --depth=1 https://github.com/arkime/arkime "$work/arkime" >/dev/null 2>&1 || true
mkdir -p "$DEST/arkime/3.9/AGPL-2.0"
rsync -a "$work/arkime/docs/" "$DEST/arkime/3.9/AGPL-2.0/" --exclude .git >/dev/null 2>&1 || true
echo "[+] Seed complete -> $DEST"
SH
chmod +x /opt/whiff/scripts/whiff-seed-docs.sh

#####################################
# Python venv & deps
#####################################
echo "[*] Creating venv and installing Python deps…"
cd /opt/whiff
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

#####################################
# (Optional) Download models (simple helper + patterns + fallback)
#####################################
if [[ "$DL_MODELS_NOW" == "1" ]]; then
  echo "[*] Downloading LLM (${WHIFF_LLM_FILE}) …"
  mkdir -p "$WHIFF_LLM_DIR"

  # Only download if not already present
  if [[ ! -f "${WHIFF_LLM_DIR}/${WHIFF_LLM_FILE}" ]]; then
    if hf_download "$WHIFF_LLM_REPO" "$WHIFF_LLM_FILE" "$WHIFF_LLM_DIR"; then
      echo "[+] LLM downloaded."
    else
      echo "[!] LLM download failed; place a GGUF later at $LLM_PATH"
    fi
  else
    echo "[*] LLM already present; skipping download."
  fi

  # Wire default symlink if file is there
  if [[ -f "${WHIFF_LLM_DIR}/${WHIFF_LLM_FILE}" ]]; then
    ln -sf "${WHIFF_LLM_DIR}/${WHIFF_LLM_FILE}" "$WHIFF_LLM_PATH_DEFAULT"
    LLM_PATH="$WHIFF_LLM_PATH_DEFAULT"
    echo "[+] LLM ready at $LLM_PATH"
  else
    echo "[!] LLM file missing after download: ${WHIFF_LLM_DIR}/${WHIFF_LLM_FILE}"
  fi

  echo "[*] Downloading embeddings (Snowflake Arctic-Embed-M-v2.0, minimal set) …"
  EMBED_DIR="$WHIFF_EMBED_DIR_DEFAULT"

  if ! check_free_gb /opt "$WHIFF_MIN_FREE_GB"; then
    echo "[!] Less than ${WHIFF_MIN_FREE_GB} GB free under /opt; using fallback embedder."
    if hf_download "$WHIFF_EMBED_FALLBACK_REPO" "" "$WHIFF_EMBED_FALLBACK_DIR"; then
      EMBED_DIR="$WHIFF_EMBED_FALLBACK_DIR"
      echo "[+] Fallback embedder ready at $EMBED_DIR"
    else
      echo "[!] Fallback embedder failed to download; proceed without embeddings."
    fi
  else
    # Primary Snowflake with allow-patterns for minimal download
    mapfile -t allow_args < <(build_allow_args "$WHIFF_EMBED_ALLOW")
    if hf_download "$WHIFF_EMBED_REPO" "" "$WHIFF_EMBED_DIR_DEFAULT" "${allow_args[@]}"; then
      EMBED_DIR="$WHIFF_EMBED_DIR_DEFAULT"
      echo "[+] Snowflake embedder ready at $EMBED_DIR"
    else
      echo "[!] Snowflake download failed; attempting fallback embedder."
      if hf_download "$WHIFF_EMBED_FALLBACK_REPO" "" "$WHIFF_EMBED_FALLBACK_DIR"; then
        EMBED_DIR="$WHIFF_EMBED_FALLBACK_DIR"
        echo "[+] Fallback embedder ready at $EMBED_DIR"
      else
        echo "[!] Could not fetch any embedding model; API will start but semantic search will be limited."
      fi
    fi
  fi
else
  echo "[*] Online model pulls skipped. Ensure on disk:"
  echo "    - LLM:   $LLM_PATH"
  echo "    - Embed: $EMBED_DIR"
fi

#####################################
# Postgres bootstrap (DB, user, extension, pg_hba)
#####################################
DB_DSN="host=$DB_HOST port=$DB_PORT dbname=$DB_NAME user=$DB_USER password=$DB_PASS"
DB_PASS_SQL="$(printf "%s" "$DB_PASS" | sed "s/'/''/g")"  # SQL-safe single quotes

# If DB_HOST is not resolvable and we’re installing local Postgres, fall back.
if ! getent ahosts "$DB_HOST" >/dev/null 2>&1; then
  echo "[!] DB host '$DB_HOST' not resolvable."
  if [[ "$INSTALL_PG_LOCAL" == "1" ]]; then
    echo "[*] Falling back to 127.0.0.1 for DB host."
    DB_HOST="127.0.0.1"
    DB_DSN="host=$DB_HOST port=$DB_PORT dbname=$DB_NAME user=$DB_USER password=$DB_PASS"
  fi
fi

echo "[*] Bootstrapping database schema…"
if [[ "$INSTALL_PG_LOCAL" == "1" ]]; then
  sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'" | grep -q 1 || \
    sudo -u postgres createdb "$DB_NAME"
  sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname = '$DB_USER'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER \"$DB_USER\";" >/dev/null
  sudo -u postgres psql -c "ALTER USER \"$DB_USER\" WITH PASSWORD '$DB_PASS_SQL';" >/dev/null
  sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE \"$DB_NAME\" TO \"$DB_USER\";" >/dev/null || true
  sudo -u postgres psql -d "$DB_NAME" -c "CREATE EXTENSION IF NOT EXISTS vector;" >/dev/null || true
  sudo -u postgres psql -d "$DB_NAME" -v ON_ERROR_STOP=1 -c "CREATE SCHEMA IF NOT EXISTS whiff AUTHORIZATION \"$DB_USER\";"
  sudo -u postgres psql -d "$DB_NAME" -v ON_ERROR_STOP=1 -c "ALTER ROLE \"$DB_USER\" IN DATABASE \"$DB_NAME\" SET search_path = whiff, public;"
  PG_HBA="$(ls /etc/postgresql/*/main/pg_hba.conf 2>/dev/null | head -n1 || true)"
  if [[ -n "$PG_HBA" ]]; then
    if ! grep -qE '^host\s+all\s+all\s+127\.0\.0\.1/32\s+(scram-sha-256|md5)\s*$' "$PG_HBA"; then
      echo "host all all 127.0.0.1/32 scram-sha-256" >> "$PG_HBA"
      systemctl restart postgresql
    fi
  fi
fi

if psql "$DB_DSN" -Atqc "SELECT 1" >/dev/null 2>&1; then
  (echo 'SET search_path = whiff, public;'; cat /opt/whiff/sql/00_bootstrap.sql) | psql "$DB_DSN" >/dev/null || \
    echo "[!] Schema applied with warnings; ensure pgvector exists."
else
  echo "[!] Could not connect to ${DB_HOST}:${DB_PORT}/${DB_NAME} as ${DB_USER}. Re-run schema later with:"
  echo "    psql \"host=${DB_HOST} port=${DB_PORT} dbname=${DB_NAME} user=${DB_USER} password=********\" -f /opt/whiff/sql/00_bootstrap.sql"
fi

#####################################
# Env + systemd
#####################################
cat > /etc/whiff/whiff.env <<ENV
WHIFF_DB_DSN="$DB_DSN"
WHIFF_TOPK=6
WHIFF_LLM_MODEL=${LLM_PATH}
WHIFF_EMBED_PATH=${EMBED_DIR}
WHIFF_THREADS=${WHIFF_THREADS}
WHIFF_CTX=${WHIFF_CTX}
ENV
chown root:whiff /etc/whiff/whiff.env
chmod 640 /etc/whiff/whiff.env

cat > /opt/whiff/packaging/whiff-api.service <<SERVICE
[Unit]
Description=Whiff RAG API
After=network-online.target
Wants=network-online.target

[Service]
User=whiff
Group=whiff
WorkingDirectory=/opt/whiff
EnvironmentFile=/etc/whiff/whiff.env
ExecStart=/opt/whiff/.venv/bin/uvicorn whiff_api:app --host ${WHIFF_BIND} --port ${WHIFF_PORT} --workers 2
Restart=on-failure
Nice=10
CPUQuota=120%
Environment=OMP_NUM_THREADS=${WHIFF_THREADS}
Environment=TOKENIZERS_PARALLELISM=false

[Install]
WantedBy=multi-user.target
SERVICE

cp /opt/whiff/packaging/whiff-api.service /etc/systemd/system/whiff-api.service
systemctl daemon-reload
systemctl enable --now whiff-api

echo "[*] Waiting for whiff-api to answer /health …"
healthy=0
for i in {1..30}; do
  if curl -sf "http://${WHIFF_BIND}:${WHIFF_PORT}/health" >/dev/null; then
    echo "[+] whiff-api healthy"
    healthy=1
    break
  fi
  sleep 1
done
[[ "$healthy" -eq 1 ]] || echo "[!] whiff-api did not become healthy in time."

#####################################
# Optional: Nightly backfill
#####################################
if [[ "$ENABLE_NIGHTLY_BACKFILL" == "1" ]]; then
  cat > /etc/systemd/system/whiff-nightly.service <<'SVC'
[Unit]
Description=Whiff nightly annotation backfill
[Service]
Type=oneshot
Environment=WHIFF_API=http://${WHIFF_BIND}:${WHIFF_PORT}/annotate
ExecStart=/opt/whiff/scripts/whiff-help /var/wade/logs/stage/today.jsonl /var/wade/logs/stage/today.with_help.jsonl
SVC
  cat > /etc/systemd/system/whiff-nightly.timer <<'TMR'
[Unit]
Description=Run Whiff backfill nightly
[Timer]
OnCalendar=02:10
Persistent=true
[Install]
WantedBy=timers.target
TMR
  systemctl daemon-reload
  systemctl enable --now whiff-nightly.timer || true
fi

#####################################
# Optional: Patch WADE env toggles
#####################################
if [[ "$PATCH_WADE_ENV" == "1" && -f /etc/wade/wade.env ]]; then
  echo "[*] Adding WHIFF_* toggles to /etc/wade/wade.env"
  {
    grep -q '^WHIFF_ENABLE=' /etc/wade/wade.env || echo 'WHIFF_ENABLE=1'
    echo "WHIFF_URL=http://${WHIFF_BIND}:${WHIFF_PORT}/annotate"
  } >> /etc/wade/wade.env.tmp
  sort -u /etc/wade/wade.env.tmp > /etc/wade/wade.env
  rm -f /etc/wade/wade.env.tmp
fi

#####################################
# Optional: Package Splunk add-on tarball
#####################################
if [[ "$PACKAGE_SPLUNK_ADDON" == "1" ]]; then
  echo "[*] Packaging Splunk custom command for deployment…"
  tar -C /opt/whiff/splunk -czf /opt/whiff/whiff_splunk_addon.tgz SA-WADE-Search
  echo " -> /opt/whiff/whiff_splunk_addon.tgz (copy to your Search Head)"
fi

#####################################
# Optional: Seed baseline docs
#####################################
if [[ "$SEED_BASELINE_DOCS" == "1" ]]; then
  /opt/whiff/scripts/whiff-seed-docs.sh || echo "[!] Seed encountered errors; continuing."
  WHIFF_DB_DSN="${DB_DSN}" /opt/whiff/.venv/bin/python /opt/whiff/whiff_index.py /opt/whiff/docs_ingest
fi

#####################################
# Optional: Initial crawl
#####################################
if [[ "$RUN_INITIAL_CRAWL" == "1" ]]; then
  if psql "$DB_DSN" -Atqc "SELECT 1" >/dev/null 2>&1 && \
     psql "$DB_DSN" -Atqc "SELECT to_regclass('whiff.sage_docs') IS NOT NULL;" | grep -q 't'; then
    echo "[*] Running initial crawl (this can take a while)…"
    export WHIFF_DB_DSN="$DB_DSN"
    /opt/whiff/.venv/bin/python /opt/whiff/whiff_crawl.py /opt/whiff/ingest/sites.yaml || echo "[!] Crawl encountered errors; continue."
  else
    echo "[!] Skipping initial crawl (DB not ready or schema missing)."
  fi
fi

#####################################
# Final info (masked DSN)
#####################################
SAFE_DSN="host=${DB_HOST} port=${DB_PORT} dbname=${DB_NAME} user=${DB_USER} password=********"
cat <<EOF

Whiff install complete.

Service:
  systemctl status whiff-api
  Health: curl -s http://${WHIFF_BIND}:${WHIFF_PORT}/health

Models:
  LLM:    ${LLM_PATH}
  Embed:  ${EMBED_DIR}

DB (masked DSN):
  DSN: ${SAFE_DSN}
  Schema file: /opt/whiff/sql/00_bootstrap.sql

Indexer:
  WHIFF_DB_DSN="${SAFE_DSN}" /opt/whiff/.venv/bin/python /opt/whiff/whiff_index.py /opt/whiff/docs_ingest

Crawler:
  WHIFF_DB_DSN="${SAFE_DSN}" /opt/whiff/.venv/bin/python /opt/whiff/whiff_crawl.py /opt/whiff/ingest/sites.yaml

Packer/Importer:
  /opt/whiff/scripts/whiff-pack-kb.sh  /tmp/whiff_kb.tgz
  /opt/whiff/scripts/whiff-import-kb.sh /tmp/whiff_kb.tgz

Splunk:
  Tarball: /opt/whiff/whiff_splunk_addon.tgz

Semper,
Whiff is up.
EOF
