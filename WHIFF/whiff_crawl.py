#!/usr/bin/env python3
import os, time, re, json, hashlib, urllib.parse, queue
import requests
from bs4 import BeautifulSoup
from pypdf import PdfReader
import psycopg2
from whiff_models import embed_texts
from whiff_utils import simple_chunks

DB_DSN = os.getenv("WHIFF_DB_DSN","postgresql://whiff:whiff@127.0.0.1:5432/whiff")
UA = "WhiffCrawler/0.1 (+local DFIR KB builder)"

def load_yaml(path):
    import yaml
    with open(path,"r",encoding="utf-8") as f:
        return yaml.safe_load(f)

def allowed(url, allow, deny):
    ok = any(re.search(p, url) for p in allow) if allow else True
    bad = any(re.search(p, url) for p in deny) if deny else False
    return ok and not bad

def text_from_html(html):
    soup = BeautifulSoup(html, "lxml")
    # drop nav/aside/script/style
    for bad in soup(["script","style","nav","aside","footer","header"]):
        bad.decompose()
    return soup.get_text("\n", strip=True)

def text_from_pdf(bytes_):
    from io import BytesIO
    buf = BytesIO(bytes_)
    reader = PdfReader(buf)
    out=[]
    for p in reader.pages:
        out.append(p.extract_text() or "")
    return "\n".join(out)

def hash_url(u): return hashlib.sha1(u.encode()).hexdigest()

def fetch(session, url):
    r = session.get(url, headers={"User-Agent":UA}, timeout=15, allow_redirects=True)
    r.raise_for_status()
    ctype = r.headers.get("content-type","").lower()
    data = r.content
    return ctype, data, r.url

def index_chunks(conn, title, url, tool, version, license_, chunks, embs):
    rows=[]
    for chunk, emb in zip(chunks, embs):
        rows.append((
            os.popen("uuidgen").read().strip(),
            title[:512], url, tool, version, license_,
            chunk, str(hash(chunk)), json.dumps({"source_url":url}), emb.tolist()
        ))
    cur = conn.cursor()
    cur.executemany("""
      INSERT INTO sage_docs (id,title,source_url,tool,version,license,chunk,chunk_hash,meta,embedding)
      VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
      ON CONFLICT DO NOTHING
    """, rows)
    conn.commit(); cur.close()

def crawl_site(site):
    base = site["base"].rstrip("/")
    allow = site.get("allow",[])
    deny  = site.get("deny",[])
    max_pages = int(site.get("max_pages", 500))
    rate = float(site.get("rate_per_sec", 0.5))
    tool = site.get("tool","misc")
    version = site.get("version","unknown")
    license_ = site.get("license","unknown")

    seen=set()
    q=queue.Queue()
    q.put(base)
    conn = psycopg2.connect(DB_DSN)
    session = requests.Session()

    last = 0.0
    pages = 0

    while not q.empty() and pages < max_pages:
        url = q.get()
        if url in seen: continue
        seen.add(url)
        if not allowed(url, allow, deny): continue

        # polite rate limiting
        now = time.time()
        sleep = max(0.0, (1.0/rate) - (now-last))
        if sleep > 0: time.sleep(sleep)
        last = time.time()

        try:
            ctype, data, final_url = fetch(session, url)
        except Exception:
            continue

        text=""
        title=url
        if "text/html" in ctype:
            html = data.decode("utf-8","ignore")
            text = text_from_html(html)
            soup = BeautifulSoup(html, "lxml")
            if soup.title and soup.title.string:
                title = soup.title.string.strip()[:256]
            # enqueue links
            for a in soup.find_all("a", href=True):
                href = urllib.parse.urljoin(final_url, a["href"])
                if href.startswith(base) and allowed(href, allow, deny):
                    q.put(href)
        elif "application/pdf" in ctype:
            text = text_from_pdf(data)
        else:
            continue

        text = text.strip()
        if not text or len(text) < 200:
            continue

        chunks = list(simple_chunks(text, max_words=400))
        if not chunks:
            continue

        embs = embed_texts(chunks)
        index_chunks(conn, title, final_url, tool, version, license_, chunks, embs)
        pages += 1

    conn.close()

def main():
    import sys
    cfg = load_yaml(sys.argv[1] if len(sys.argv)>1 else "./ingest/sites.yaml")
    for site in cfg.get("sites", []):
        crawl_site(site)

if __name__=="__main__":
    main()
