Ai integration for fun and profit.

# 0) OS deps
sudo apt-get update
sudo apt-get install -y python3-venv build-essential libopenblas-dev postgresql-client

# 1) user + dirs
sudo useradd -r -s /usr/sbin/nologin whiff || true
sudo mkdir -p /opt/whiff /etc/whiff /var/log/whiff /opt/whiff/models/emb
sudo chown -R whiff:whiff /opt/whiff /var/log/whiff
sudo cp -r whiff/* /opt/whiff/  # if you cloned elsewhere, copy repo in

# 2) venv + deps
cd /opt/whiff
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# 3) Postgres (run once on your DB host)
# psql -U postgres -h 127.0.0.1
# CREATE DATABASE whiff;
# CREATE USER whiff WITH PASSWORD 'whiff';
# GRANT ALL PRIVILEGES ON DATABASE whiff TO whiff;
# \c whiff
# \i /opt/whiff/sql/00_bootstrap.sql;

# 4) Models: place files on disk (no downloads here)
#   /opt/whiff/models/whiff-7b-q4.gguf
#   /opt/whiff/models/emb/e5-small-v2/* (model files)
# Ensure readable by user 'whiff'

# 5) Env + systemd
sudo cp packaging/whiff.env.example /etc/whiff/whiff.env
sudo chmod 640 /etc/whiff/whiff.env
sudo chown root:whiff /etc/whiff/whiff.env
sudo cp packaging/whiff-api.service /etc/systemd/system/whiff-api.service
sudo systemctl daemon-reload
sudo systemctl enable --now whiff-api
curl -s http://127.0.0.1:8088/health

Seed docs:
/opt/whiff/docs_ingest/
  mitre_attack/v14.1/CC-BY-4.0/*.md
  volatility3/2.7/docs/Apache-2.0/*.md
  hayabusa/2.18/docs/MIT/*.md
  capa/7.1/docs/Apache-2.0/*.md
  yara/4.5/docs/Apache-2.0/*.md
  wade_sop/2025-10-25/Proprietary/*.md
  arkime/3.9/docs/AGPL-2.0/*.md
  ja3_ja4/2024/docs/Various/*.md

Finally:
cd /opt/whiff
. .venv/bin/activate
WHIFF_DB_DSN="postgresql://whiff:whiff@127.0.0.1:5432/whiff" \
python3 whiff_index.py ./docs_ingest


Splunk integration

Copy splunk/SA-WADE-Search/bin/whiff.py and splunk/SA-WADE-Search/default/commands.conf into your Splunk app (same one we’ve been using). Restart Splunkd.
