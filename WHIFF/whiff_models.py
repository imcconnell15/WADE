import os
import numpy as np
from typing import List
from llama_cpp import Llama

_EMBED_MODEL = None
_LLM = None

def init_models():
    global _EMBED_MODEL, _LLM

    # Embeddings (sentence-transformers). Offline: point to a local dir.
    from sentence_transformers import SentenceTransformer

    embed_path = os.environ.get("WHIFF_EMBED_PATH", "/opt/whiff/models/emb/e5-small-v2")
    _EMBED_MODEL = SentenceTransformer(embed_path)  # must exist on disk
    # typical dims: 384/512/768; adjust SQL dim to match your model

    # LLM (llama.cpp) — load local .gguf
    llm_path = os.environ.get("WHIFF_LLM_MODEL", "/opt/whiff/models/whiff-7b-q4.gguf")
    n_threads = int(os.environ.get("WHIFF_THREADS", "8"))
    ctx = int(os.environ.get("WHIFF_CTX", "4096"))
    _LLM = Llama(model_path=llm_path, n_threads=n_threads, n_ctx=ctx, verbose=False)

def embed_texts(texts: List[str]) -> np.ndarray:
    if _EMBED_MODEL is None: init_models()
    # Normalize to unit vectors for cosine
    vecs = _EMBED_MODEL.encode(texts, normalize_embeddings=True, convert_to_numpy=True)
    return vecs

def generate(prompt: str, max_tokens=400, temperature=0.2) -> str:
    if _LLM is None: init_models()
    sysmsg = "You are Whiff, a DFIR assistant. Be concise. Cite sources if given."
    out = _LLM.create_chat_completion(
        messages=[{"role":"system","content":sysmsg},
                  {"role":"user","content":prompt}],
        temperature=temperature,
        max_tokens=max_tokens
    )
    return out["choices"][0]["message"]["content"].strip()
