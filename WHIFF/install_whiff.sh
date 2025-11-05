#!/usr/bin/env bash
# Whiff - DFIR RAG Companion :: Idempotent Installer (online/offline)
# Author: You + GPT (Meta Llama 3.1 + Snowflake Arctic Embed)
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
# Prompt helpers
#####################################
prompt() { local q="$1" d="$2" a; read -r -p "$q [$d]: " a; echo "${a:-$d}"; }
yn() { local q="$1" d="${2:-Y}" a; read -r -p "$q [${d}/$( [[ "$d" =~ ^[Yy]$ ]] && echo n || echo y )]: " a; a="${a:-$d}"; [[ "$a" =~ ^[Yy]$ ]] && echo "1" || echo "0"; }
die(){ echo "ERROR: $*" >&2; exit 1; }
req(){ command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"; }

#####################################
# Prompts (all configuration here)
#####################################
INSTALL_PG_LOCAL="$(yn "Install & configure local PostgreSQL + pgvector?" Y)"
DB_HOST="$(prompt "Postgres host" "127.0.0.1")"
DB_PORT="$(prompt "Postgres port" "5432")"
DB_NAME="$(prompt "Database name" "whiff")"
DB_USER="$(prompt "Database user" "whiff")"
DB_PASS="$(prompt "Database password" "whiff")"

WHIFF_BIND="$(prompt "Whiff bind address" "127.0.0.1")"
WHIFF_PORT="$(prompt "Whiff port" "8088")"
WHIFF_THREADS="$(prompt "Model CPU threads" "8")"
WHIFF_CTX="$(prompt "Model context tokens" "4096")"

ONLINE_MODE="$(yn "Online mode (allow model downloads + crawling now)?" N)"
DL_MODELS_NOW="0"
if [[ "$ONLINE_MODE" == "1" ]]; then
  DL_MODELS_NOW="$(yn "Download models now via huggingface-cli?" Y)"
fi
LLM_PATH="$(prompt "Path to LLM .gguf (if already on disk)" "/opt/whiff/models/whiff-llm.gguf")"
EMBED_DIR="$(prompt "Path to embeddings model dir" "/opt/whiff/models/emb/snowflake-m-v2")"

RUN_INITIAL_CRAWL="0"
if [[ "$ONLINE_MODE" == "1" ]]; then
  RUN_INITIAL_CRAWL="$(yn "Run initial crawl of tuned sites.yaml after install?" Y)"
fi

# Seed docs (no export to git)
SEED_DOCS_NOW="$(yn "Seed baseline docs (ATT&CK, Vol3, Hayabusa, capa, YARA, Arkime, JA3/JA4 links) into /opt/whiff/docs_ingest now?" Y)"
if [[ "$SEED_DOCS_NOW" == "1" && "$ONLINE_MODE" != "1" ]]; then
  echo "[!] Seeding needs network access. Set Online mode = Y or run /opt/whiff/scripts/whiff-seed-docs.sh later."
fi

ENABLE_NIGHTLY_BACKFILL="$(yn "Install (disabled) nightly backfill service+timer?" Y)"
PATCH_WADE_ENV="$(yn "Add WHIFF_* toggles to /etc/wade/wade.env if present?" Y)"
PACKAGE_SPLUNK_ADDON="$(yn "Package Splunk custom command tarball for your Search Head?" Y)"

#####################################
# Preflight
#####################################
[[ "$EUID" -eq 0 ]] || exec sudo -E bash "$0" "$@"
req apt-get
req systemctl
req sed
req awk
req curl
req psql || true  # we'll install if needed

#####################################
# OS packages
#####################################
echo "[*] Installing OS packages…"
apt-get update -y
apt-get install -y python3-venv build-essential libopenblas-dev \
  postgresql-client jq rsync git

if [[ "$INSTALL_PG_LOCAL" == "1" ]]; then
  apt-get install -y postgresql postgresql-contrib
fi

#####################################
# Users & directories
#####################################
echo "[*] Creating whiff user and directories…"
id -u whiff >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin whiff
mkdir -p /opt/whiff/{scripts,ingest,sql,packaging,splunk/SA-WADE-Search/bin,splunk/SA-WADE-Search/default,models/emb,docs_ingest} \
         /etc/whiff /var/log/whiff
chown -R whiff:whiff /opt/whiff /var/log/whiff

#####################################
# requirements.txt  (added: docutils, python-docx, chardet)
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
REQ

#####################################
# Core Python files
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
DB_DSN = os.environ.get("WHIFF_DB_DSN","postgresql://whiff:whiff@127.0.0.1:5432/whiff")
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
        try: help_obj=orjson.loads(raw[js:je+1])
        except Exception: help_obj={"summary":"Parse error.","significance":"","mitre":[],"next_steps":[],"spl_suggestions":[],"refs":[],"confidence":0.0,"sources_used":[]}
    cur.execute("INSERT INTO annotation_cache(event_hash,help) VALUES (%s,%s) ON CONFLICT (event_hash) DO NOTHING",
                (ev_hash, orjson.dumps(help_obj).decode()))
    conn.commit(); cur.close(); conn.close()
    return {"help": help_obj, "cached": False}
PY

# --------- Enhanced indexer: supports PDF/HTML/MD/RST/TXT/LOG/INI/CFG/DOCX/CSV/JSON ---------
cat > /opt/whiff/whiff_index.py <<'PY'
import os, uuid, glob, json, csv
from pathlib import Path
import psycopg2
import chardet
from bs4 import BeautifulSoup
from pypdf import PdfReader
from docutils.core import publish_parts
from docx import Document
from whiff_models import embed_texts
from whiff_utils import simple_chunks

DB_DSN=os.environ.get("WHIFF_DB_DSN","postgresql://whiff:whiff@127.0.0.1:5432/whiff")
MAX_BYTES=int(os.environ.get("WHIFF_INDEX_MAX_BYTES","5242880"))  # 5 MiB per file
CSV_MAX_ROWS=int(os.environ.get("WHIFF_INDEX_CSV_MAX_ROWS","500"))

def sniff_file_text(p: Path) -> str:
    data = p.read_bytes()
    if not data: return ""
    enc = chardet.detect(data).get("encoding") or "utf-8"
    try:
        return data.decode(enc, errors="ignore")
    except Exception:
        return data.decode("utf-8", errors="ignore")

def load_text(p:Path)->str:
    if p.stat().st_size > MAX_BYTES: return ""
    sfx=p.suffix.lower()
    if sfx in {".md",".txt",".log",".ini",".cfg"}:
        return sniff_file_text(p)

    if sfx in {".html",".htm"}:
        html = sniff_file_text(p)
        soup=BeautifulSoup(html,"lxml")
        for bad in soup(["script","style","nav","aside","footer","header"]): bad.decompose()
        return soup.get_text("\n", strip=True)

    if sfx == ".rst":
        rst = sniff_file_text(p)
        try:
            parts = publish_parts(source=rst, writer_name="plaintext")
            return parts.get("whole","").strip()
        except Exception:
            return rst

    if sfx == ".pdf":
        out=[]
        with open(p,"rb") as f:
            pdf=PdfReader(f)
            for pg in pdf.pages:
                try:
                    out.append(pg.extract_text() or "")
                except Exception:
                    out.append("")
        return "\n".join(out)

    if sfx == ".docx":
        try:
            doc=Document(p)
            chunks=[]
            for para in doc.paragraphs:
                if para.text.strip(): chunks.append(para.text)
            for table in doc.tables:
                for row in table.rows:
                    chunks.append("\t".join(cell.text.strip() for cell in row.cells))
            return "\n".join(chunks)
        except Exception:
            return ""

    if sfx == ".csv":
        try:
            text = sniff_file_text(p)
            lines = text.splitlines()
            reader = csv.reader(lines)
            rows = []
            for i, row in enumerate(reader):
                rows.append("\t".join(row))
                if i >= CSV_MAX_ROWS: break
            return "\n".join(rows)
        except Exception:
            return ""

    if sfx == ".json":
        try:
            obj=json.loads(sniff_file_text(p))
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

def main(root="docs_ingest"):
    conn=psycopg2.connect(DB_DSN)
    for f in glob.glob(f"{root}/**/*", recursive=True):
        p=Path(f)
        if not p.is_file(): continue
        text=load_text(p).strip()
        if not text: continue
        parts=p.parts
        tool=parts[-4] if len(parts)>=4 else "misc"
        version=parts[-3] if len(parts)>=3 else "unknown"
        license_=parts[-2] if len(parts)>=2 else "unknown"
        meta={"filename":p.name,"source_path":str(p)}
        chunks=list(simple_chunks(text, max_words=400))
        if not chunks: continue
        embs=embed_texts(chunks)
        rows=[(str(uuid.uuid4()), p.stem, None, tool, version, license_, c, str(hash(c)), json.dumps(meta), e.tolist())
              for c,e in zip(chunks, embs)]
        insert_docs(conn, rows)
    conn.close()

if __name__=="__main__":
    import sys
    main(sys.argv[1] if len(sys.argv)>1 else "docs_ingest")
PY

# --------- Crawler: use uuid in Python; HTML/PDF supported ---------
cat > /opt/whiff/whiff_crawl.py <<'PY'
#!/usr/bin/env python3
import os, time, re, json, urllib.parse, queue, uuid
import requests, psycopg2, yaml
from bs4 import BeautifulSoup
from pypdf import PdfReader
from whiff_models import embed_texts
from whiff_utils import simple_chunks
DB_DSN=os.getenv("WHIFF_DB_DSN","postgresql://whiff:whiff@127.0.0.1:5432/whiff")
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
    for c,e in zip(chunks,embs):
        rows.append((str(uuid.uuid4()), title[:512], url, tool, version, license_, c, str(hash(c)), json.dumps({"source_url":url}), e.tolist()))
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
        if "text/html" in ctype or "application/xhtml" in ctype:
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
# SQL bootstrap (768-dim for Snowflake Arctic Embed)
#####################################
cat > /opt/whiff/sql/00_bootstrap.sql <<'SQL'
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
  embedding VECTOR(768)
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
# Ingest config (pre-tuned sites.yaml)
#####################################
mkdir -p /opt/whiff/ingest
cat > /opt/whiff/ingest/sites.yaml <<'YAML'
sites:
  - name: mitre-attack
    base: "https://attack.mitre.org"
    allow:
      - "^https://attack\\.mitre\\.org/(techniques|tactics|mitigations|datasources)/.*$"
    deny: []
    rate_per_sec: 1.0
    max_pages: 3000
    license: "CC BY 4.0"
    tool: "mitre-attack"
    version: "v14x"

  - name: volatility3-docs
    base: "https://volatility3.readthedocs.io"
    allow:
      - "^https://volatility3\\.readthedocs\\.io/en/(latest|stable)/.*$"
    deny:
      - "\\.(zip|tar|gz|jpg|png|gif|svg|ico)$"
    rate_per_sec: 1.0
    max_pages: 1200
    license: "See Volatility docs license"
    tool: "volatility3"
    version: "docs-snapshot"

  - name: hayabusa-wiki
    base: "https://github.com/Yamato-Security/hayabusa/wiki"
    allow:
      - "^https://github\\.com/Yamato-Security/hayabusa/wiki/.*$"
    deny: []
    rate_per_sec: 0.5
    max_pages: 600
    license: "Repo MIT; GitHub Wiki TOS (verify)"
    tool: "hayabusa"
    version: "wiki"

  - name: capa-docs
    base: "https://mandiant.github.io/capa"
    allow:
      - "^https://mandiant\\.github\\.io/capa/.*$"
    deny: []
    rate_per_sec: 0.5
    max_pages: 400
    license: "Apache-2.0 (docs)"
    tool: "capa"
    version: "doc"

  - name: yara-docs
    base: "https://yara.readthedocs.io"
    allow:
      - "^https://yara\\.readthedocs\\.io/.*$"
    deny: []
    rate_per_sec: 0.8
    max_pages: 600
    license: "See YARA docs license"
    tool: "yara"
    version: "docs-snapshot"

  - name: arkime-docs
    base: "https://arkime.com"
    allow:
      - "^https://arkime\\.com/(learn|faq|apiv3|settings).*"
    deny: []
    rate_per_sec: 0.6
    max_pages: 400
    license: "Arkime site TOS"
    tool: "arkime"
    version: "site"

  - name: zeek-docs
    base: "https://docs.zeek.org"
    allow:
      - "^https://docs\\.zeek\\.org/.+"
    deny: []
    rate_per_sec: 0.8
    max_pages: 1200
    license: "Zeek docs site"
    tool: "zeek"
    version: "docs-snapshot"

  - name: forensic-artifacts-kb
    base: "https://artifacts.readthedocs.io"
    allow:
      - "^https://artifacts\\.readthedocs\\.io/.*$"
    deny: []
    rate_per_sec: 0.8
    max_pages: 800
    license: "Apache-2.0 (repo); docs site"
    tool: "forensic-artifacts"
    version: "kb"

  - name: sysmon-learn
    base: "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"
    allow:
      - "^https://learn\\.microsoft\\.com/en-us/sysinternals/downloads/sysmon.*$"
    deny: []
    rate_per_sec: 0.4
    max_pages: 50
    license: "Microsoft Learn terms"
    tool: "sysmon"
    version: "learn"
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
# Scripts: whiff-help, packer, importer
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
DB="${WHIFF_DB_DSN:-postgresql://whiff:whiff@127.0.0.1:5432/whiff}"
work="$(mktemp -d)"
mkdir -p "$work/db" "$work/ingest" "$work/models"
pg_dump "$DB" -t sage_docs -a -Fc -f "$work/db/sage_docs.dump"
[[ -f /opt/whiff/ingest/sites.yaml ]] && cp /opt/whiff/ingest/sites.yaml "$work/ingest/sites.yaml"
if [[ -f /opt/whiff/models/whiff-llm.gguf" ]]; then cp /opt/whiff/models/whiff-llm.gguf "$work/models/"; fi
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
DB="${WHIFF_DB_DSN:-postgresql://whiff:whiff@127.0.0.1:5432/whiff}"
tmp="$(mktemp -d)"
tar -C "$tmp" -xzf "$TARBALL"
psql "$DB" -f "$DEST/sql/00_bootstrap.sql" >/dev/null 2>&1 || true
pg_restore -d "$DB" --data-only -t sage_docs "$tmp/db/sage_docs.dump"
if [[ -f "$tmp/models/whiff-llm.gguf" ]]; then install -D -m 0644 "$tmp/models/whiff-llm.gguf" "$DEST/models/whiff-llm.gguf"; fi
if [[ -d "$tmp/models/emb/snowflake-m-v2" ]]; then mkdir -p "$DEST/models/emb"; rsync -a "$tmp/models/emb/snowflake-m-v2" "$DEST/models/emb/"; fi
echo "Imported KB into $DB and copied any bundled models."
SH
chmod +x /opt/whiff/scripts/whiff-import-kb.sh

#####################################
# NEW: MITRE STIX → Markdown converter
#####################################
cat > /opt/whiff/scripts/mitre_to_md.py <<'PY'
#!/usr/bin/env python3
# Usage: mitre_to_md.py /path/to/attack-stix-data /opt/whiff/docs_ingest/mitre_attack v14.1
import json, sys, re, os, pathlib
src, out_root, ver = sys.argv[1], sys.argv[2], sys.argv[3]
out_dir = os.path.join(out_root, ver, "CC-BY-4.0")
os.makedirs(out_dir, exist_ok=True)
def safe(name): return re.sub(r'[^A-Za-z0-9_.-]+','_', name).strip('_')
domain_dir = os.path.join(src, "enterprise-attack")
bundles = [p for p in pathlib.Path(domain_dir).glob("*.json")]
if not bundles: raise SystemExit("No enterprise-attack bundles found.")
def get_tid(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name","").lower() in ("mitre-attack","attack") and ref.get("external_id"):
            return ref["external_id"]
    return None
def get_url(obj):
    for ref in obj.get("external_references", []):
        u = ref.get("url")
        if u and "attack.mitre.org" in u:
            return u
    return ""
for p in bundles:
    with open(p, "r", encoding="utf-8") as f:
        data = json.load(f)
    for obj in data.get("objects", []):
        if obj.get("type")!="attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = get_tid(obj)
        if not tid: continue
        name = obj.get("name","")
        desc = (obj.get("description","") or "").strip()
        det  = (obj.get("x_mitre_detection","") or "").strip()
        url = get_url(obj)
        fn = f"{tid}_{safe(name)}.md"
        with open(os.path.join(out_dir, fn), "w", encoding="utf-8") as w:
            w.write(f"---\n")
            w.write(f"title: {tid} {name}\n")
            w.write(f"mitre_id: {tid}\n")
            w.write(f"source_url: {url}\n")
            w.write(f"license: CC BY 4.0\n")
            w.write(f"attribution: MITRE ATT&CK®\n")
            w.write(f"---\n\n")
            w.write(f"# {tid} — {name}\n\n")
            if desc: w.write(desc + "\n\n")
            if det:
                w.write("## Detection Guidance\n\n")
                w.write(det + "\n\n")
            w.write("> Source: MITRE ATT&CK (STIX 2.1). CC BY 4.0.\n")
PY
chmod +x /opt/whiff/scripts/mitre_to_md.py

#####################################
# NEW: Docs seeder (clones + copies + ATTRIBUTION)
#####################################
cat > /opt/whiff/scripts/whiff-seed-docs.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail
TARGET_ROOT="${1:-/opt/whiff/docs_ingest}"

# Version pins for folder names
ATTACK_VER="${ATTACK_VER:-v14.1}"
VOL3_VER="${VOL3_VER:-2.7}"
HAYABUSA_VER="${HAYABUSA_VER:-2.18}"
CAPA_VER="${CAPA_VER:-7.1}"
YARA_VER="${YARA_VER:-4.5}"
ARKIME_VER="${ARKIME_VER:-3.9}"
JA_VER="${JA_VER:-2024}"
WADE_SOP_DATE="${WADE_SOP_DATE:-$(date +%F)}"

LIC_CC_BY="CC-BY-4.0"
LIC_APACHE="Apache-2.0"
LIC_MIT="MIT"
LIC_AGPL="AGPL-2.0"
LIC_PROP="Proprietary"
LIC_VARIOUS="Various"

WORK="$(mktemp -d)"
mkdir -p "$TARGET_ROOT"
echo "[*] Working in $WORK"

# MITRE ATT&CK (STIX → MD)
git clone --depth 1 https://github.com/mitre-attack/attack-stix-data.git "$WORK/attack-stix-data"
mkdir -p "$TARGET_ROOT/mitre_attack/${ATTACK_VER}/${LIC_CC_BY}"
/opt/whiff/scripts/mitre_to_md.py "$WORK/attack-stix-data" "$TARGET_ROOT/mitre_attack" "$ATTACK_VER"
echo "[+] ATT&CK rendered."

# Volatility3
git clone --depth 1 https://github.com/volatilityfoundation/volatility3.git "$WORK/vol3"
mkdir -p "$TARGET_ROOT/volatility3/${VOL3_VER}/docs/${LIC_APACHE}"
if [[ -d "$WORK/vol3/docs" ]]; then
  rsync -a --include="*/" --include="*.md" --include="*.rst" --exclude="*" \
    "$WORK/vol3/docs/" "$TARGET_ROOT/volatility3/${VOL3_VER}/docs/${LIC_APACHE}/"
fi

# Hayabusa (GitHub wiki)
git clone --depth 1 https://github.com/Yamato-Security/hayabusa.wiki.git "$WORK/hayabusa-wiki"
mkdir -p "$TARGET_ROOT/hayabusa/${HAYABUSA_VER}/docs/${LIC_MIT}"
rsync -a --include="*/" --include="*.md" --exclude="*" \
  "$WORK/hayabusa-wiki/" "$TARGET_ROOT/hayabusa/${HAYABUSA_VER}/docs/${LIC_MIT}/"

# capa
git clone --depth 1 https://github.com/mandiant/capa.git "$WORK/capa"
mkdir -p "$TARGET_ROOT/capa/${CAPA_VER}/docs/${LIC_APACHE}"
if [[ -d "$WORK/capa/docs" ]]; then
  rsync -a --include="*/" --include="*.md" --exclude="*" \
    "$WORK/capa/docs/" "$TARGET_ROOT/capa/${CAPA_VER}/docs/${LIC_APACHE}/"
elif [[ -d "$WORK/capa/doc" ]]; then
  rsync -a --include="*/" --include="*.md" --exclude="*" \
    "$WORK/capa/doc/" "$TARGET_ROOT/capa/${CAPA_VER}/docs/${LIC_APACHE}/"
fi

# YARA
git clone --depth 1 https://github.com/VirusTotal/yara.git "$WORK/yara"
mkdir -p "$TARGET_ROOT/yara/${YARA_VER}/docs/${LIC_APACHE}"
if [[ -d "$WORK/yara/docs" ]]; then
  rsync -a --include="*/" --include="*.md" --include="*.rst" --exclude="*" \
    "$WORK/yara/docs/" "$TARGET_ROOT/yara/${YARA_VER}/docs/${LIC_APACHE}/"
fi

# Arkime
git clone --depth 1 https://github.com/arkime/arkime.git "$WORK/arkime"
mkdir -p "$TARGET_ROOT/arkime/${ARKIME_VER}/docs/${LIC_APACHE}"
if [[ -d "$WORK/arkime/docs" ]]; then
  rsync -a --include="*/" --include="*.md" --exclude="*" \
    "$WORK/arkime/docs/" "$TARGET_ROOT/arkime/${ARKIME_VER}/docs/${LIC_APACHE}/"
fi

# JA3/JA4 (links only)
mkdir -p "$TARGET_ROOT/ja3_ja4/${JA_VER}/docs/${LIC_VARIOUS}"
cat > "$TARGET_ROOT/ja3_ja4/${JA_VER}/docs/${LIC_VARIOUS}/README.md" <<'EOF'
# JA3 / JA4 Reading List (links only)
- JA4+ official repo: https://github.com/FoxIO-LLC/ja4
- JA3 original repo/blog (Salesforce): https://github.com/salesforce/ja3
- Cloudflare docs on JA3/JA4: https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/
EOF

# Your SOP placeholder
mkdir -p "$TARGET_ROOT/wade_sop/${WADE_SOP_DATE}/${LIC_PROP}"
touch "$TARGET_ROOT/wade_sop/${WADE_SOP_DATE}/${LIC_PROP}/.gitkeep"

# Attribution
cat > "$TARGET_ROOT/ATTRIBUTION.md" <<EOF
# Whiff Docs Ingest — Attribution & Licenses

- MITRE ATT&CK content generated from STIX 2.1 datasets: CC BY 4.0.
- Volatility3 docs from volatilityfoundation/volatility3 (repo license).
- Hayabusa wiki from Yamato-Security/hayabusa.wiki (MIT).
- capa docs from mandiant/capa (Apache-2.0).
- YARA docs from VirusTotal/yara (Apache-2.0).
- Arkime docs from arkime/arkime (Apache-2.0).
- JA3/JA4: links only to original sources (Various).
- WADE SOP: proprietary documents authored by you.

Each folder includes a license segment (e.g., CC-BY-4.0, Apache-2.0). Preserve headers where present.
EOF

echo "[+] Seed complete -> $TARGET_ROOT"
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
# (Optional) Download models (Meta Llama 3.1 + Snowflake Arctic Embed)
#####################################
if [[ "$DL_MODELS_NOW" == "1" ]]; then
  echo "[*] Downloading models (huggingface-cli)…"
  pip install -q 'huggingface_hub[cli]'
  mkdir -p /opt/whiff/models/emb
  # Meta Llama 3.1 8B Instruct (GGUF Q4_K_M) -> whiff-llm.gguf
  huggingface-cli download bartowski/Meta-Llama-3.1-8B-Instruct-GGUF \
    --include "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf" \
    --local-dir /opt/whiff/models --local-dir-use-symlinks False || true
  [[ -f /opt/whiff/models/Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf ]] && \
    mv /opt/whiff/models/Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf /opt/whiff/models/whiff-llm.gguf || true

  # Snowflake Arctic-Embed-M-v2.0 (768-dim)
  huggingface-cli download Snowflake/snowflake-arctic-embed-m-v2.0 \
    --local-dir /opt/whiff/models/emb/snowflake-m-v2 \
    --local-dir-use-symlinks False || true
fi

#####################################
# Postgres bootstrap (DB, user, extension)
#####################################
DB_DSN="postgresql://$DB_USER:$DB_PASS@$DB_HOST:$DB_PORT/$DB_NAME"
echo "[*] Bootstrapping database schema…"
if [[ "$INSTALL_PG_LOCAL" == "1" ]]; then
  sudo -u postgres psql >/dev/null <<SQL || true
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_database WHERE datname = '$DB_NAME') THEN
    PERFORM dblink_exec('dbname=' || current_database(), 'CREATE DATABASE $DB_NAME');
  END IF;
END\$\$;
SQL
  sudo -u postgres psql -d "$DB_NAME" -c "CREATE EXTENSION IF NOT EXISTS vector;" >/dev/null || true
  sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname = '$DB_USER'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';" >/dev/null
  sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;" >/dev/null || true
fi

# Run schema file using provided DSN (works for local or remote, if perms allow)
WHIFF_DB_DSN="$DB_DSN" psql "$DB_DSN" -f /opt/whiff/sql/00_bootstrap.sql >/dev/null || \
  echo "[!] Schema bootstrap skipped (insufficient privs?). Ensure 'vector' ext + tables exist."

#####################################
# Env + systemd
#####################################
cat > /etc/whiff/whiff.env <<ENV
WHIFF_DB_DSN=$DB_DSN
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
After=network-online.target postgresql.service
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
sleep 1
curl -s "http://${WHIFF_BIND}:${WHIFF_PORT}/health" || echo "[!] Health check failed (service may still be starting)."

#####################################
# Optional: Nightly backfill
#####################################
if [[ "$ENABLE_NIGHTLY_BACKFILL" == "1" ]]; then
  cat > /etc/systemd/system/whiff-nightly.service <<'SVC'
[Unit]
Description=Whiff nightly annotation backfill
[Service]
Type=oneshot
Environment=WHIFF_API=http://127.0.0.1:8088/annotate
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
# Run docs seeding (no export)
#####################################
if [[ "$SEED_DOCS_NOW" == "1" && "$ONLINE_MODE" == "1" ]]; then
  echo "[*] Seeding docs into /opt/whiff/docs_ingest …"
  /opt/whiff/scripts/whiff-seed-docs.sh /opt/whiff/docs_ingest || echo "[!] Seeding encountered issues; continuing."
fi

#####################################
# Optional: Patch WADE env toggles
#####################################
if [[ "$PATCH_WADE_ENV" == "1" && -f /etc/wade/wade.env ]]; then
  echo "[*] Adding WHIFF_* toggles to /etc/wade/wade.env"
  awk 'BEGIN{added=0} /WHIFF_ENABLE=/{found=1} END{if(!found)print "WHIFF_ENABLE=1"}' /etc/wade/wade.env >> /etc/wade/wade.env.tmp || true
  echo "WHIFF_URL=http://${WHIFF_BIND}:${WHIFF_PORT}/annotate" >> /etc/wade/wade.env.tmp
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
# Optional: Initial crawl
#####################################
if [[ "$RUN_INITIAL_CRAWL" == "1" ]]; then
  echo "[*] Running initial crawl (this can take a while)…"
  export WHIFF_DB_DSN="$DB_DSN"
  /opt/whiff/.venv/bin/python /opt/whiff/whiff_crawl.py /opt/whiff/ingest/sites.yaml || echo "[!] Crawl encountered errors; continue."
fi

#####################################
# Final info
#####################################
cat <<EOF

Whiff install complete (Meta Llama 3.1 8B Instruct + Snowflake Arctic Embed).

Service:
  systemctl status whiff-api
  Health: curl -s http://${WHIFF_BIND}:${WHIFF_PORT}/health

Models:
  LLM:    ${LLM_PATH}
  Embed:  ${EMBED_DIR}
  (If missing and you chose offline, copy them into place and restart: systemctl restart whiff-api)

DB:
  DSN: ${DB_DSN}
  Schema file: /opt/whiff/sql/00_bootstrap.sql

Crawler:
  Config: /opt/whiff/ingest/sites.yaml
  Run:    WHIFF_DB_DSN="${DB_DSN}" /opt/whiff/.venv/bin/python /opt/whiff/whiff_crawl.py /opt/whiff/ingest/sites.yaml

Index local docs (PDF, HTML, MD, RST, TXT/LOG/INI/CFG, DOCX, CSV, JSON):
  WHIFF_DB_DSN="${DB_DSN}" /opt/whiff/.venv/bin/python /opt/whiff/whiff_index.py /opt/whiff/docs_ingest

Seed baseline docs (can run anytime):
  /opt/whiff/scripts/whiff-seed-docs.sh /opt/whiff/docs_ingest

Packer/Importer:
  /opt/whiff/scripts/whiff-pack-kb.sh  /tmp/whiff_kb.tgz
  /opt/whiff/scripts/whiff-import-kb.sh /tmp/whiff_kb.tgz

Splunk:
  Tarball for Search Head: /opt/whiff/whiff_splunk_addon.tgz
  Usage after deploy:
    index=wade_volatility sourcetype=wade_volatility
    | head 20
    | whiff max_refs=3
    | table _time host whiff_summary whiff_mitre whiff_next_steps whiff_conf

Quick API test:
  curl -s http://${WHIFF_BIND}:${WHIFF_PORT}/ask \
    -H 'Content-Type: application/json' \
    -d '{"query":"What does Volatility pslist output represent?"}'

Semper,
Whiff is up.
EOF
