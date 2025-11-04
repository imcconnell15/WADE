import os, uuid, glob, json
from pathlib import Path
import psycopg2
from bs4 import BeautifulSoup
from pypdf import PdfReader
from whiff_models import embed_texts
from whiff_utils import simple_chunks

DB_DSN = os.environ.get("WHIFF_DB_DSN","postgresql://whiff:whiff@127.0.0.1:5432/whiff")

def load_text(path: Path) -> str:
    sfx = path.suffix.lower()
    if sfx in {".md",".txt"}:
        return path.read_text(errors="ignore")
    if sfx in {".html",".htm"}:
        return BeautifulSoup(path.read_text(errors="ignore"), "lxml").get_text("\n")
    if sfx == ".pdf":
        txt=[]; 
        with open(path,"rb") as f:
            pdf=PdfReader(f)
            for p in pdf.pages:
                txt.append(p.extract_text() or "")
        return "\n".join(txt)
    return ""

def insert_docs(conn, rows):
    cur = conn.cursor()
    cur.executemany("""
        INSERT INTO sage_docs (id,title,source_url,tool,version,license,chunk,chunk_hash,meta,embedding)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING
    """, rows)
    conn.commit(); cur.close()

def main(root="docs_ingest"):
    conn = psycopg2.connect(DB_DSN)
    for f in glob.glob(f"{root}/**/*", recursive=True):
        p = Path(f)
        if not p.is_file(): continue
        text = load_text(p).strip()
        if not text: continue

        # Expect layout like docs_ingest/<tool>/<version>/<license>/file.ext
        parts = p.parts
        tool    = parts[-4] if len(parts)>=4 else "misc"
        version = parts[-3] if len(parts)>=3 else "unknown"
        license = parts[-2] if len(parts)>=2 else "unknown"
        meta = {"filename": p.name, "source_path": str(p)}

        rows=[]
        chunks=list(simple_chunks(text, max_words=400))
        if not chunks: continue
        embs = embed_texts(chunks)
        for chunk, emb in zip(chunks, embs):
            rows.append((
                str(uuid.uuid4()),
                p.stem, None, tool, version, license,
                chunk, str(hash(chunk)),
                json.dumps(meta), emb.tolist()
            ))
        insert_docs(conn, rows)
    conn.close()

if __name__=="__main__":
    import sys
    main(sys.argv[1] if len(sys.argv)>1 else "docs_ingest")
