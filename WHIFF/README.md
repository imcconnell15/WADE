# WHIFF --- Wide-area Hunting Intelligence and Forensics Framework

**AI-powered DFIR companion for context-aware analysis and interactive knowledge retrieval.**

---

## 🎯 Overview

WHIFF is a **Retrieval-Augmented Generation (RAG)** system designed specifically for digital forensics and incident response. It provides:

- 🧠 **Intelligent Q&A** --- Ask natural language questions about forensic tools, techniques, and TTPs
- 🔍 **Event Annotation** --- Automatically explain and contextualize suspicious events with MITRE ATT&CK mappings
- 📚 **Curated Knowledge Base** --- Embeddings from MITRE ATT&CK, Volatility, Hayabusa, YARA, Capa, and more
- 🚀 **Offline-First** --- Runs entirely on-premise with local models (no external API calls)
- 🔗 **Splunk Integration** --- Query WHIFF directly from Splunk dashboards via custom command

**Key Design Principles:**
- ✅ **CPU-friendly** --- Optimized for CPU inference with quantized models (Q4_K_M)
- ✅ **Air-gapped ready** --- All models and dependencies can be pre-staged for offline deployment
- ✅ **Source attribution** --- Every answer cites specific documentation chunks
- ✅ **MITRE-aware** --- Automatically maps events to ATT&CK tactics and techniques

---

## 🏗️ Architecture

```mermaid
graph TB
    A[User Query] --> B[WHIFF API]
    B --> C[Embedding Model]
    C --> D[PostgreSQL + pgvector]
    D --> E[Vector Similarity Search]
    E --> F[Top-K Context Chunks]
    F --> G[LLM Llama 3.1 8B]
    G --> H[Answer + Sources]
    H --> I[Response JSON]

    J[WADE Events] --> K[Annotate Endpoint]
    K --> C
    K --> L[Cache Check]
    L --> M{Cached?}
    M -->|Yes| N[Return Cached]
    M -->|No| E

    O[Docs Ingestion] --> P[whiff_index.py]
    P --> Q[Chunk + Embed]
    Q --> D

    R[Splunk Dashboard] --> S[whiff.py Command]
    S --> B

    style G fill:#f9f,stroke:#333,stroke-width:2px
    style D fill:#bbf,stroke:#333,stroke-width:2px
```

Components:

1.  whiff_api.py --- FastAPI REST service with `/ask` and `/annotate` endpoints
2.  whiff_models.py --- Model loading and inference (embeddings + LLM)
3.  whiff_index.py --- Knowledge base ingestion and chunking
4.  whiff_crawl.py --- Optional web scraper for documentation sites
5.  whiff_utils.py --- Event hashing and caching utilities
6.  PostgreSQL + pgvector --- Vector database for semantic search
7.  Splunk Integration --- Custom search command for interactive queries

* * * * *

📦 Features
-----------

### 1\. Interactive Q&A (`/ask`)

Example Query:

```source-json
{
  "query": "How do I detect process injection in a memory dump?",
  "k": 6,
  "tool_hint": "volatility",
  "version_hint": "3.0"
}
```

Response:

```source-json
{
  "answer": "To detect process injection:\n1\. Run `volatility -f mem.dmp windows.malfind` to find injected code\n2\. Use `windows.hollowprocesses` to detect process hollowing\n3\. Check `windows.ldrmodules` for unlinked DLLs\n\nNext Steps:\n- Examine suspicious PIDs with `windows.dlllist`\n- Extract injected memory regions with `windows.memmap`\n- Cross-reference with YARA rules for known malware\n\nMITRE ATT&CK: T1055 (Process Injection)\n\nSources: Volatility 3 Process Analysis, MITRE ATT&CK T1055",
  "sources": [
    {
      "title": "Volatility 3 - windows.malfind",
      "chunk": "The malfind plugin scans process memory...",
      "url": "https://volatility3.readthedocs.io/...",
      "tool": "volatility",
      "version": "3.0",
      "distance": 0.23
    }
  ]
}
```

### 2\. Event Annotation (`/annotate`)

Example Event:

```source-json
{
  "event": {
    "tool": "hayabusa",
    "EventID": 4688,
    "Computer": "DESKTOP-ABC123",
    "CommandLine": "powershell.exe -enc <base64>",
    "ParentImage": "explorer.exe"
  }
}
```

Response:

```source-json
{
  "help": {
    "summary": "Process creation event showing PowerShell execution with base64-encoded command",
    "significance": "High - Base64 encoding is commonly used to obfuscate malicious PowerShell",
    "mitre": [
      {
        "tactic": "Execution",
        "technique": "T1059.001 - PowerShell",
        "confidence": 0.9
      },
      {
        "tactic": "Defense Evasion",
        "technique": "T1027 - Obfuscated Files or Information",
        "confidence": 0.85
      }
    ],
    "next_steps": [
      "Decode base64 payload to analyze commands",
      "Check parent process legitimacy (explorer.exe spawning PowerShell is suspicious)",
      "Search for related network connections with windows.netscan",
      "Look for persistence mechanisms created by this process"
    ],
    "spl_suggestions": [
      "index=wade_hayabusa EventID=4688 CommandLine=*-enc* | stats count by Computer ParentImage",
      "index=wade_volatility module=windows.pslist ImageFileName=powershell.exe | table PID PPID CommandLine"
    ],
    "refs": [
      {"title": "MITRE ATT&CK T1059.001", "url": "https://attack.mitre.org/techniques/T1059/001/"},
      {"title": "PowerShell Obfuscation Analysis", "url": "https://..."}
    ],
    "confidence": 0.88,
    "sources_used": ["MITRE ATT&CK v14.1", "Hayabusa Detection Rules"]
  },
  "cached": false
}
```

### 3\. Splunk Integration

Custom Search Command:

```
| makeresults
| eval question="What Volatility plugins detect lateral movement?"
| whiff question tool="volatility"
| table answer sources

```

Dashboard Integration:

```text-xml
<dashboard>
  <label>Ask WHIFF</label>
  <row>
    <panel>
      <input type="text" token="question">
        <label>Ask WHIFF a DFIR question:</label>
      </input>
      <table>
        <search>
          <query>
            | makeresults | eval q="$question$" | whiff q | table answer sources
          </query>
        </search>
      </table>
    </panel>
  </row>
</dashboard>
```

* * * * *

🚀 Installation
---------------

### Prerequisites

-   Ubuntu 20.04+ or RHEL 8+
-   Python 3.8+
-   PostgreSQL 14+ with `pgvector` extension
-   8GB+ RAM (16GB recommended for larger models)
-   ~10GB disk space for models

### Quick Install (Automated)

```source-shell
# Clone WADE repository
git clone https://github.com/imcconnell15/WADE.git
cd WADE/WHIFF

# Run installer (idempotent, supports online/offline modes)
sudo bash install_whiff.sh
```

The installer will:

1.  Create `whiff` system user
2.  Install Python dependencies in virtualenv
3.  Download models (or use pre-staged ones)
4.  Set up PostgreSQL database with pgvector
5.  Seed knowledge base from included documentation
6.  Configure systemd service

### Manual Installation

#### 1\. System Dependencies

```source-shell
sudo apt-get update
sudo apt-get install -y python3-venv build-essential libopenblas-dev postgresql-14 postgresql-client-14
```

#### 2\. PostgreSQL + pgvector

```source-shell
# Install pgvector extension
sudo apt-get install -y postgresql-14-pgvector

# Create database and user
sudo -u postgres psql <<EOF
CREATE DATABASE whiff;
CREATE USER whiff WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE whiff TO whiff;
\c whiff
CREATE EXTENSION IF NOT EXISTS vector;
EOF

# Bootstrap schema
psql -U whiff -h 127.0.0.1 -d whiff -f sql/00_bootstrap.sql
```

#### 3\. User and Directories

```source-shell
sudo useradd -r -s /usr/sbin/nologin whiff
sudo mkdir -p /opt/whiff /etc/whiff /var/log/whiff /opt/whiff/models/emb
sudo chown -R whiff:whiff /opt/whiff /var/log/whiff
```

#### 4\. Python Environment

```source-shell
cd /opt/whiff
sudo -u whiff python3 -m venv .venv
sudo -u whiff .venv/bin/pip install --upgrade pip
sudo -u whiff .venv/bin/pip install -r requirements.txt
```

#### 5\. Models

Option A: Download Models (Online)

```source-shell
# Embedding model (Snowflake Arctic Embed M-v2, ~500MB)
sudo -u whiff .venv/bin/python3 <<EOF
from sentence_transformers import SentenceTransformer
model = SentenceTransformer("Snowflake/snowflake-arctic-embed-m-v2")
model.save("/opt/whiff/models/emb/snowflake-m-v2")
EOF

# LLM (Llama 3.1 8B Instruct Q4_K_M, ~4.7GB)
sudo -u whiff wget -O /opt/whiff/models/whiff-llm.gguf\
  https://huggingface.co/bartowski/Meta-Llama-3.1-8B-Instruct-GGUF/resolve/main/Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf
```

Option B: Use Pre-Staged Models (Offline)

```source-shell
# Copy models from USB/network share
sudo cp /path/to/models/whiff-llm.gguf /opt/whiff/models/
sudo cp -r /path/to/models/emb/snowflake-m-v2 /opt/whiff/models/emb/
sudo chown -R whiff:whiff /opt/whiff/models/
```

#### 6\. Configuration

```source-shell
# Create environment file
sudo tee /etc/whiff/whiff.env <<EOF
WHIFF_DB_DSN=postgresql://whiff:your_secure_password@127.0.0.1:5432/whiff
WHIFF_TOPK=6
WHIFF_LLM_MODEL=/opt/whiff/models/whiff-llm.gguf
WHIFF_EMBED_PATH=/opt/whiff/models/emb/snowflake-m-v2
WHIFF_THREADS=8
WHIFF_CTX=4096
WHIFF_BIND=127.0.0.1
WHIFF_PORT=8088
EOF

sudo chmod 640 /etc/whiff/whiff.env
sudo chown root:whiff /etc/whiff/whiff.env
```

#### 7\. Systemd Service

```source-shell
sudo cp packaging/whiff-api.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable whiff-api.service
sudo systemctl start whiff-api.service

# Check status
sudo systemctl status whiff-api.service

# Test API
curl -s http://127.0.0.1:8088/health
# Expected: {"ok":true}
```

#### 8\. Knowledge Base Ingestion

```source-shell
# Seed with included documentation
cd /opt/whiff
sudo -u whiff bash <<'EOF'
source .venv/bin/activate
export WHIFF_DB_DSN="postgresql://whiff:your_password@127.0.0.1:5432/whiff"
python3 whiff_index.py ./docs_ingest
EOF
```

* * * * *

📚 Knowledge Base Management
----------------------------

### Included Documentation

WHIFF ships with embeddings for:

| Documentation | Version | License | Coverage |
| --- | --- | --- | --- |
| MITRE ATT&CK | v14.1 | CC-BY-4.0 | Enterprise tactics, techniques, procedures |
| Volatility3 | 2.7 | Apache-2.0 | Memory analysis plugins and usage |
| Hayabusa | 2.18 | MIT | Windows event log detection rules |
| Capa | 7.1 | Apache-2.0 | Malware capability analysis |
| YARA | 4.5 | Apache-2.0 | Rule writing and scanning |
| Dissect | 3.x | AGPL-2.0 | Forensic artifact parsing |
| Arkime | 3.9 | Apache-2.0 | Packet capture analysis |
| JA3/JA4 | 2024 | Various | TLS fingerprinting |

### Adding Custom Documentation

1\. Organize Documentation:

```
/opt/whiff/docs_ingest/
└── custom_sop/
    ├── incident_response.md
    ├── malware_analysis.md
    └── network_forensics.md

```

2\. Index Documents:

```source-shell
cd /opt/whiff
sudo -u whiff bash <<'EOF'
source .venv/bin/activate
export WHIFF_DB_DSN="postgresql://whiff:password@127.0.0.1:5432/whiff"
python3 whiff_index.py ./docs_ingest/custom_sop
EOF
```

3\. Verify Ingestion:

```source-shell
psql -U whiff -h 127.0.0.1 -d whiff -c\
  "SELECT COUNT(*), tool FROM sage_docs GROUP BY tool ORDER BY COUNT(*) DESC;"
```

### Web Crawling

```source-shell
# Configure sites in ingest/sites.yaml
cat > ingest/sites.yaml <<EOF
sites:
  - name: Custom KB
    url: https://internal-wiki.company.com/dfir
    max_depth: 3
    tool: custom_kb
    version: "2025-01"
EOF

# Run crawler
cd /opt/whiff
sudo -u whiff bash <<'EOF'
source .venv/bin/activate
export WHIFF_DB_DSN="postgresql://whiff:password@127.0.0.1:5432/whiff"
python3 whiff_crawl.py ingest/sites.yaml
EOF
```

* * * * *

⚙️ Configuration
----------------

### Environment Variables

| Variable | Default | Description |
| --- | --- | --- |
| `WHIFF_DB_DSN` | `postgresql://whiff:whiff@127.0.0.1:5432/whiff` | PostgreSQL connection string |
| `WHIFF_TOPK` | `6` | Number of context chunks to retrieve |
| `WHIFF_LLM_MODEL` | `/opt/whiff/models/whiff-llm.gguf` | Path to GGUF model |
| `WHIFF_EMBED_PATH` | `/opt/whiff/models/emb/snowflake-m-v2` | Path to embedding model |
| `WHIFF_THREADS` | `8` | CPU threads for LLM inference |
| `WHIFF_CTX` | `4096` | LLM context window size |
| `WHIFF_BIND` | `127.0.0.1` | API bind address |
| `WHIFF_PORT` | `8088` | API port |

### Model Selection

Embedding Models:

-   Snowflake Arctic Embed M-v2 (recommended, 512 dims, ~500MB)
-   e5-small-v2 (384 dims, ~130MB, faster)
-   e5-base-v2 (768 dims, ~440MB, higher accuracy)

LLM Models:

-   Llama 3.1 8B Instruct Q4_K_M (recommended, ~4.7GB)
-   Llama 3.1 8B Instruct Q5_K_M (higher quality, ~5.7GB)
-   Mistral 7B Instruct Q4_K_M (alternative, ~4.1GB)

Changing Models:

```source-shell
# Update environment
sudo nano /etc/whiff/whiff.env
# Set WHIFF_LLM_MODEL=/path/to/new/model.gguf

# Restart service
sudo systemctl restart whiff-api.service
```

* * * * *

🔌 API Reference
----------------

### POST `/ask`

Request:

```source-json
{
  "query": "How do I find persistence mechanisms in Windows?",
  "k": 6,
  "tool_hint": "volatility",
  "version_hint": "3.0"
}
```

Response:

```source-json
{
  "answer": "Answer text with sources...",
  "sources": [
    {
      "title": "Document title",
      "chunk": "Relevant text chunk",
      "url": "https://...",
      "tool": "volatility",
      "version": "3.0",
      "distance": 0.25
    }
  ]
}
```

### POST `/annotate`

Request:

```source-json
{
  "event": {
    "tool": "hayabusa",
    "EventID": 4720,
    "Computer": "DC01",
    "TargetUserName": "admin2",
    "sourcetype": "wade:hayabusa:detections"
  }
}
```

Response:

```source-json
{
  "help": {
    "summary": "User account creation event",
    "significance": "Medium - New privileged account created",
    "mitre": [...],
    "next_steps": [...],
    "spl_suggestions": [...],
    "refs": [...],
    "confidence": 0.82,
    "sources_used": [...]
  },
  "cached": false
}
```

### GET `/health`

Response:

```source-json
{"ok": true}
```

* * * * *

🔍 Usage Examples
-----------------

### Python Client

```source-python
import requests

WHIFF_URL = "http://localhost:8088"

# Ask a question
response = requests.post(f"{WHIFF_URL}/ask", json={
    "query": "What Volatility plugins detect lateral movement?",
    "tool_hint": "volatility"
})
result = response.json()
print(result["answer"])
for source in result["sources"]:
    print(f"  - {source['title']} ({source['url']})")

# Annotate an event
event = {
    "tool": "volatility",
    "module": "windows.netscan",
    "ForeignAddr": "192.168.1.100:445",
    "State": "ESTABLISHED",
    "PID": 1234,
    "Owner": "lsass.exe"
}
response = requests.post(f"{WHIFF_URL}/annotate", json={"event": event})
help_text = response.json()["help"]
print(f"Summary: {help_text['summary']}")
print(f"MITRE: {help_text['mitre']}")
```

### Curl Examples

```source-shell
# Ask question
curl -X POST http://localhost:8088/ask\
  -H "Content-Type: application/json"\
  -d '{
    "query": "How do I detect process injection?",
    "k": 5,
    "tool_hint": "volatility"
  }' | jq .

# Annotate event
curl -X POST http://localhost:8088/annotate\
  -H "Content-Type: application/json"\
  -d '{
    "event": {
      "EventID": 4688,
      "CommandLine": "powershell.exe -enc <base64>"
    }
  }' | jq .help.summary
```

### Splunk Dashboard

```text-xml
<dashboard>
  <label>WHIFF - DFIR Assistant</label>
  <row>
    <panel>
      <title>Ask WHIFF</title>
      <input type="text" token="question">
        <label>Question:</label>
        <default>How do I analyze memory dumps with Volatility?</default>
      </input>
      <table>
        <search>
          <query>
            | makeresults
            | eval query="$question$"
            | whiff query
            | table answer sources
          </query>
        </search>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <title>Annotate Suspicious Events</title>
      <input type="dropdown" token="event_index">
        <label>Event Source:</label>
        <choice value="wade_hayabusa">Hayabusa Detections</choice>
        <choice value="wade_volatility">Volatility Memory</choice>
        <default>wade_hayabusa</default>
      </input>
      <table>
        <search>
          <query>
            index=$event_index$ Level IN ("High", "Critical")
            | head 10
            | whiff annotate=true
            | table _time Computer help.summary help.mitre help.next_steps
          </query>
        </search>
      </table>
    </panel>
  </row>
</dashboard>
```

* * * * *

🛠️ Troubleshooting
-------------------

### API Not Starting

```source-shell
# Check service status
sudo systemctl status whiff-api.service

# View logs
sudo journalctl -u whiff-api -f

# Common issues:
# 1\. Models not found
ls -lh /opt/whiff/models/
sudo chown -R whiff:whiff /opt/whiff/models/

# 2\. PostgreSQL connection failed
psql -U whiff -h 127.0.0.1 -d whiff -c "SELECT 1;"

# 3\. Port already in use
sudo lsof -i :8088
# Change WHIFF_PORT in /etc/whiff/whiff.env
```

### Slow Responses

```source-shell
# Increase threads (edit /etc/whiff/whiff.env)
WHIFF_THREADS=12

# Reduce context window
WHIFF_CTX=2048

# Use smaller model
WHIFF_LLM_MODEL=/opt/whiff/models/mistral-7b-q4.gguf

# Restart
sudo systemctl restart whiff-api.service
```

### Out of Memory

```source-shell
# Use Q4 quantization (smaller model)
# Reduce concurrent workers in systemd unit
sudo nano /etc/systemd/system/whiff-api.service
# Change: --workers 2 → --workers 1

# Add memory limit
sudo systemctl edit whiff-api.service
# [Service]
# MemoryMax=8G

sudo systemctl daemon-reload
sudo systemctl restart whiff-api.service
```

### No Results / Poor Answers

```source-shell
# Check knowledge base size
psql -U whiff -h 127.0.0.1 -d whiff -c\
  "SELECT COUNT(*), tool FROM sage_docs GROUP BY tool;"

# Re-index documentation
cd /opt/whiff
sudo -u whiff bash <<'EOF'
source .venv/bin/activate
export WHIFF_DB_DSN="postgresql://whiff:password@127.0.0.1:5432/whiff"
python3 whiff_index.py ./docs_ingest --force
EOF

# Test embedding similarity
python3 <<EOF
from whiff_models import embed_texts
vecs = embed_texts(["test query", "similar text"])
print(f"Cosine similarity: {vecs[0] @ vecs[1].T}")
# Should be close to 1.0 for similar texts
EOF
```

### Cache Issues

```source-shell
# Clear annotation cache
psql -U whiff -h 127.0.0.1 -d whiff -c "TRUNCATE annotation_cache;"

# View cache hit rate
psql -U whiff -h 127.0.0.1 -d whiff -c\
  "SELECT COUNT(*), MAX(created_at) FROM annotation_cache;"
```

* * * * *

📊 Performance Tuning
---------------------

### CPU Optimization

```source-shell
# Pin to specific cores (NUMA-aware)
sudo systemctl edit whiff-api.service
# [Service]
# CPUAffinity=0-7  # Cores 0-7
# Nice=-5          # Higher priority

sudo systemctl daemon-reload
sudo systemctl restart whiff-api.service
```

### PostgreSQL Tuning

```source-shell
sudo nano /etc/postgresql/14/main/postgresql.conf

# Add:
shared_buffers = 2GB
effective_cache_size = 8GB
maintenance_work_mem = 512MB
work_mem = 32MB
max_wal_size = 2GB

# Restart PostgreSQL
sudo systemctl restart postgresql
```

### Batch Processing

```source-python
# Process multiple questions efficiently
import requests
WHIFF_URL = "http://localhost:8088"

questions = [
    "How to detect ransomware?",
    "Lateral movement indicators?",
    "Memory injection techniques?"
]

# Reuse session for connection pooling
with requests.Session() as session:
    for q in questions:
        resp = session.post(f"{WHIFF_URL}/ask", json={"query": q})
        print(f"Q: {q}\nA: {resp.json()['answer']}\n")
```

* * * * *

🔐 Security Considerations
--------------------------

### Network Isolation

```source-shell
# Bind to localhost only (default)
WHIFF_BIND=127.0.0.1

# Use reverse proxy for external access
# nginx config:
location /whiff/ {
    proxy_pass http://127.0.0.1:8088/;
    proxy_set_header Host $host;
}
```

### Authentication

```source-shell
# Add API key middleware (example)
# whiff_api.py:
from fastapi import Security, HTTPException
from fastapi.security import APIKeyHeader

API_KEY = os.environ.get("WHIFF_API_KEY")
api_key_header = APIKeyHeader(name="X-API-Key")

async def verify_api_key(key: str = Security(api_key_header)):
    if key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")

@app.post("/ask", dependencies=[Depends(verify_api_key)])
def ask(body: AskBody):
    ...
```

### Database Security

```source-shell
# Use strong passwords
psql -U postgres -c "ALTER USER whiff WITH PASSWORD 'your_very_secure_password';"

# Restrict PostgreSQL access
sudo nano /etc/postgresql/14/main/pg_hba.conf
# Change:
# host  whiff  whiff  127.0.0.1/32  scram-sha-256

sudo systemctl restart postgresql
```

* * * * *

📚 Resources
------------

-   [Llama.cpp Documentation](https://github.com/ggerganov/llama.cpp)
-   [Sentence Transformers](https://www.sbert.net/)
-   [pgvector Extension](https://github.com/pgvector/pgvector)
-   [FastAPI Documentation](https://fastapi.tiangolo.com/)
-   [MITRE ATT&CK](https://attack.mitre.org/)

* * * * *

🛣️ Roadmap
-----------

### Near-Term

-   [ ]  Multi-user authentication and API keys
-   [ ]  Query history and analytics dashboard
-   [ ]  Automated KB updates (weekly crawl jobs)
-   [ ]  Fine-tuned model for DFIR domain
-   [ ]  Support for custom YARA rule explanations

### Mid-Term

-   [ ]  Multi-modal support (analyze screenshots, diagrams)
-   [ ]  Integration with VirusTotal, MISP, OTX
-   [ ]  Adversary emulation plan generation
-   [ ]  Interactive Jupyter notebook integration
-   [ ]  GraphRAG for entity relationship mapping

### Long-Term

-   [ ]  Distributed deployment (model sharding)
-   [ ]  Active learning from analyst feedback
-   [] Automated report generation
-   [ ]  Voice interface for hands-free operation
-   [ ]  AR/VR visualization integration

* * * * *

For more information:

-   [Main README](https://github.com/imcconnell15/WADE/README.md)
-   [Worker Documentation](https://github.com/imcconnell15/WADE/wade_workers/README.md)
-   [Staging Documentation](https://github.com/imcconnell15/WADE/staging/README.md)
