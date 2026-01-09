import hashlib, json, re

VOLATILE_FIELDS = {"_time","_raw","_indextime","linecount"}

def stable_event_hash(ev: dict) -> str:
    """Hash event sans volatile fields so similar events dedupe."""
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
