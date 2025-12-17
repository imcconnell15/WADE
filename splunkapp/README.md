# WADE Splunk Integration

Splunk apps and add-ons for ingesting, indexing, and analyzing WADE forensic artifacts.

---

## 🎯 Overview

The WADE Splunk integration provides:
- **Universal Forwarder configs** to monitor JSONL outputs
- **Indexer configurations** for index creation and retention
- **Search-head app** with dashboards, saved searches, and field extractions

---

## 📂 Structure

splunkapp/
├── TA-wade-uf/ # Universal Forwarder (data collection)
│ ├── default/
│ │ ├── inputs.conf # Monitor paths
│ │ └── outputs.conf # Forwarding destinations
│ └── local/ # Site-specific overrides
├── TA-wade-indexer/ # Indexer (data storage)
│ ├── default/
│ │ ├── indexes.conf # Index definitions
│ │ ├── props.conf # Sourcetype parsing
│ │ └── transforms.conf # Field extractions
│ └── local/
└── SA-wade-search/ # Search Head (analysis)
├── default/
│ ├── data/
│ │ └── ui/
│ │ ├── views/ # Dashboards
│ │ └── nav/ # Navigation
│ ├── props.conf # Field aliases
│ ├── savedsearches.conf
│ └── eventtypes.conf
└── local/


---

## 📥 Universal Forwarder Configuration

### inputs.conf

```ini
[monitor:///home/autopsy/DataSources/**/volatility/**/*.jsonl]
sourcetype = wade:volatility:memory
index = wade_volatility
disabled = false
recursive = true
followTail = 0

[monitor:///home/autopsy/DataSources/**/dissect/**/*.jsonl]
sourcetype = wade:dissect:filesystem
index = wade_dissect
disabled = false
recursive = true

[monitor:///home/autopsy/DataSources/**/hayabusa/**/*.jsonl]
sourcetype = wade:hayabusa:detections
index = wade_hayabusa
disabled = false
recursive = true

[monitor:///home/autopsy/DataSources/**/plaso/**/*.jsonl]
sourcetype = wade:plaso:timeline
index = wade_plaso
disabled = false
recursive = true

[monitor:///home/autopsy/DataSources/**/yara/**/*.jsonl]
sourcetype = wade:yara:scan
index = wade_yara
disabled = false
recursive = true

[monitor:///home/autopsy/DataSources/**/bulk_extractor/**/*.jsonl]
sourcetype = wade:bulk_extractor:scan
index = wade_bulk_extractor
disabled = false
recursive = true

[monitor:///var/wade/logs/**/*.jsonl]
sourcetype = wade:events
index = wade_events
disabled = false
recursive = true
outputs.conf
[tcpout]
defaultGroup = wade_indexers

[tcpout:wade_indexers]
server = splunk-indexer1:9997, splunk-indexer2:9997
compressed = true
useSSL = true
sslVerifyServerCert = false
🗄️ Indexer Configuration
indexes.conf
[wade_volatility]
homePath = $SPLUNK_DB/wade_volatility/db
coldPath = $SPLUNK_DB/wade_volatility/colddb
thawedPath = $SPLUNK_DB/wade_volatility/thaweddb
maxTotalDataSizeMB = 500000
frozenTimePeriodInSecs = 7776000  # 90 days

[wade_dissect]
homePath = $SPLUNK_DB/wade_dissect/db
coldPath = $SPLUNK_DB/wade_dissect/colddb
thawedPath = $SPLUNK_DB/wade_dissect/thaweddb
maxTotalDataSizeMB = 500000

[wade_hayabusa]
homePath = $SPLUNK_DB/wade_hayabusa/db
coldPath = $SPLUNK_DB/wade_hayabusa/colddb
thawedPath = $SPLUNK_DB/wade_hayabusa/thaweddb
maxTotalDataSizeMB = 200000

[wade_plaso]
homePath = $SPLUNK_DB/wade_plaso/db
coldPath = $SPLUNK_DB/wade_plaso/colddb
thawedPath = $SPLUNK_DB/wade_plaso/thaweddb
maxTotalDataSizeMB = 1000000

[wade_yara]
homePath = $SPLUNK_DB/wade_yara/db
coldPath = $SPLUNK_DB/wade_yara/colddb
thawedPath = $SPLUNK_DB/wade_yara/thaweddb
maxTotalDataSizeMB = 50000

[wade_bulk_extractor]
homePath = $SPLUNK_DB/wade_bulk_extractor/db
coldPath = $SPLUNK_DB/wade_bulk_extractor/colddb
thawedPath = $SPLUNK_DB/wade_bulk_extractor/thaweddb
maxTotalDataSizeMB = 100000

[wade_events]
homePath = $SPLUNK_DB/wade_events/db
coldPath = $SPLUNK_DB/wade_events/colddb
thawedPath = $SPLUNK_DB/wade_events/thaweddb
maxTotalDataSizeMB = 10000
frozenTimePeriodInSecs = 2592000  # 30 days
props.conf
[wade:volatility:memory]
INDEXED_EXTRACTIONS = JSON
KV_MODE = json
TIME_PREFIX = "processed_utc":\s*"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S
MAX_TIMESTAMP_LOOKAHEAD = 32
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)

[wade:dissect:filesystem]
INDEXED_EXTRACTIONS = JSON
KV_MODE = json
TIME_PREFIX = "processed_utc":\s*"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S
SHOULD_LINEMERGE = false

[wade:hayabusa:detections]
INDEXED_EXTRACTIONS = JSON
KV_MODE = json
TIME_PREFIX = "Timestamp":\s*"
TIME_FORMAT = %Y-%m-%d %H:%M:%S
SHOULD_LINEMERGE = false
🔍 Search Examples
Process Analysis (Volatility)
index=wade_volatility sourcetype=wade:volatility:memory module=windows.pslist
| table host case_id PID ImageFileName Threads Handles CreateTime
| sort -Threads
Malware Detection (YARA)
index=wade_yara sourcetype=wade:yara:scan
| stats count by rule host case_id
| sort -count
Windows Event Analysis (Hayabusa)
index=wade_hayabusa sourcetype=wade:hayabusa:detections
| search Level IN ("High", "Critical")
| table Timestamp Computer EventID RuleTitle Details MitreTactics
| sort -Timestamp
Timeline Correlation (Plaso)
index=wade_plaso sourcetype=wade:plaso:timeline host="DESKTOP-ABC123"
| timechart count by source_module
Network Connections (Volatility)
index=wade_volatility module=windows.netscan
| table host LocalAddr LocalPort ForeignAddr ForeignPort State PID Owner
| where State="ESTABLISHED"
📊 Dashboards
Overview Dashboard
Panels:

Total artifacts processed (by tool)
Recent staging activity
Active cases
Top hosts by artifact count
Processing timeline
SPL:

index=wade_events event_type=staged
| stats count by tool classification
| sort -count
Memory Analysis Dashboard
Panels:

Process tree visualization
Network connections map
DLL injection detections (malfind)
Handle analysis
Service enumeration
Threat Detection Dashboard
Panels:

YARA rule hits (top 10)
Hayabusa high-severity events
Suspicious process behavior
Network IOCs
Timeline of detections
🚀 Deployment
Install on Universal Forwarder
# Copy TA to UF apps directory
sudo cp -r TA-wade-uf /opt/splunkforwarder/etc/apps/

# Update outputs.conf with your indexer
sudo nano /opt/splunkforwarder/etc/apps/TA-wade-uf/local/outputs.conf

# Restart UF
sudo /opt/splunkforwarder/bin/splunk restart
Install on Indexer
# Copy TA to indexer apps directory
sudo cp -r TA-wade-indexer /opt/splunk/etc/apps/

# Restart indexer
sudo /opt/splunk/bin/splunk restart
Install on Search Head
# Copy SA to search head apps directory
sudo cp -r SA-wade-search /opt/splunk/etc/apps/

# Restart search head
sudo /opt/splunk/bin/splunk restart
📚 Resources
Splunk Documentation
JSONL Ingestion Best Practices
Building Splunk Apps
For more information:

Main README
Worker Documentation
