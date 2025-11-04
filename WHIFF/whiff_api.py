import os, json
import psycopg2, numpy as np, orjson
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional, List
from whiff_models import embed_texts, generate
from whiff_utils import stable_event_hash

DB_DSN = os.environ.get("WHIFF_DB_DSN","postgresql://whiff:whiff@127.0.0.1:5432/whiff")
TOP_K = int(os.environ.get("WHIFF_TOPK","6"))

app = FastAPI(title="Whiff API", version="0.1.0")

def db():
    return psycopg2.connect(DB_DSN)

class AskBody(BaseModel):
    query: str
    k: int = TOP_K
    tool_hint: Optional[str] = None
    version_hint: Optional[str] = None

class AnnotateBody(BaseModel):
    event: dict

def search_docs(q_emb: np.ndarray, k=6, tool=None, version=None):
    conn = db(); cur = conn.cursor()
    where, params = [], []
    if tool:    where.append("tool = %s"); params.append(tool)
    if version: where.append("version = %s"); params.append(version)
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    sql = f"""
      SELECT title, chunk, source_url, tool, version, (embedding <#> %s::vector) AS score
      FROM sage_docs
      {where_sql}
      ORDER BY embedding <#> %s::vector
      LIMIT %s
    """
    params.extend([q_emb.tolist(), q_emb.tolist(), k])
    cur.execute(sql, params)
    rows = cur.fetchall()
    cur.close(); conn.close()
    return [
      {"title": r[0], "chunk": r[1], "url": r[2], "tool": r[3], "version": r[4], "distance": float(r[5])}
      for r in rows
    ]

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/ask")
def ask(body: AskBody):
    q_emb = embed_texts([body.query])[0]
    hits = search_docs(q_emb, k=body.k, tool=body.tool_hint, version=body.version_hint)
    context = "\n\n---\n\n".join(h["chunk"] for h in hits)
    prompt = f"""Answer the user's DFIR question using ONLY the context below.
If info is missing, say you don't know. Provide: short answer, 2-4 bullet next steps, and ATT&CK IDs if clearly supported.
Include a line 'Sources:' listing titles you used.

Question:
{body.query}

Context (verbatim):
{context}
"""
    answer = generate(prompt, max_tokens=500)
    return {"answer": answer, "sources": hits}

@app.post("/annotate")
def annotate(body: AnnotateBody):
    ev = body.event
    # Cache check
    ev_hash = stable_event_hash(ev)
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT help FROM annotation_cache WHERE event_hash=%s", (ev_hash,))
    hit = cur.fetchone()
    if hit:
        help_obj = hit[0]
        cur.close(); conn.close()
        return {"help": help_obj, "cached": True}

    tool = ev.get("sourcetype") or ev.get("source") or ev.get("tool")
    version = ev.get("tool_version") or ev.get("version")
    query = f"Explain this event and suggest next steps. Event JSON:\n{json.dumps(ev, ensure_ascii=False)}"

    q_emb = embed_texts([query])[0]
    hits = search_docs(q_emb, k=6, tool=tool, version=version)
    context = "\n\n---\n\n".join(h["chunk"] for h in hits)

    prompt = f"""You are Whiff. Produce STRICT JSON with keys:
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
    raw = generate(prompt, max_tokens=400)
    # Be forgiving if model surrounds JSON with prose
    json_start = raw.find("{"); json_end = raw.rfind("}")
    if json_start == -1 or json_end == -1:
        help_obj = {"summary":"Insufficient context.","significance":"","mitre":[],"next_steps":[],"spl_suggestions":[],"refs":[],"confidence":0.0,"sources_used":[]}
    else:
        try:
            help_obj = orjson.loads(raw[json_start:json_end+1])
        except Exception:
            help_obj = {"summary":"Parse error.","significance":"","mitre":[],"next_steps":[],"spl_suggestions":[],"refs":[],"confidence":0.0,"sources_used":[]}

    # Cache store
    cur.execute("INSERT INTO annotation_cache(event_hash, help) VALUES (%s,%s) ON CONFLICT (event_hash) DO NOTHING",
                (ev_hash, orjson.dumps(help_obj).decode()))
    conn.commit(); cur.close(); conn.close()
    return {"help": help_obj, "cached": False}
