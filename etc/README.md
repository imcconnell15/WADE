---

## 📄 etc/README.md

```markdown
# WADE Configuration Directory

This directory contains all configuration files for the WADE framework. Configuration follows a layered approach: defaults → YAML → environment variables.

## 📁 Files

### `wade.env`

**Runtime environment variables** loaded by systemd services and scripts.

**Core Settings:**
```bash
# User and paths
WADE_OWNER_USER=autopsy
WADE_DATADIR=/home/autopsy/DataSources
WADE_STAGINGDIR=/home/autopsy/Staging
WADE_QUEUE_DIR=/home/autopsy/DataSources/_queue
WADE_LOG_DIR=/var/wade/logs

# Staging behavior
WADE_STAGE_STABLE_SECONDS=10
WADE_STAGE_POLL_INTERVAL=30
WADE_STAGE_REQUIRE_CLOSE_WRITE=true
WADE_STAGE_VERIFY_NO_WRITERS=true
WADE_STAGE_RECURSIVE=false
WADE_STAGE_ACCEPT_DOCS=false
WADE_STAGE_AUTO_DEFRAG_E01=false

# Tool paths (auto-detected if not set)
WADE_VOLATILITY3_PATH=/opt/volatility3/vol.py
WADE_EWFINFO_PATH=/usr/bin/ewfinfo
WADE_EWFEXPORT_PATH=/usr/bin/ewfexport
WADE_LSOF_PATH=/usr/bin/lsof

# Splunk integration
SPLUNK_DEFAULT_INDEX=wade_events
SPLUNK_UF_RCVR_HOSTS=splunk-indexer:9997
SPLUNK_UF_COMPRESSED=true
SPLUNK_UF_SSL_VERIFY=false

# Feature flags
OFFLINE=false
WHIFF_ENABLE=false
Tool Routing Overrides:

# Per-classification routing (+ to add, - to remove)
WADE_ROUTE_E01_FULL=dissect,hayabusa,plaso,+yara,-autopsy
WADE_ROUTE_MEMORY_FULL=volatility,+yara_mem

# Global enable/disable
WADE_DISABLE_TOOLS=autopsy,bulk_extractor
WADE_ENABLE_TOOLS=yara_mem
wade.conf
Default values for all environment variables. This file is sourced by install.sh and provides fallbacks when wade.env variables are not set.

Purpose: Provides a complete reference of all configurable options with sensible defaults.

config.yaml
Declarative configuration for tool routing and module selection.

Structure:

# Tool routing by classification and profile
routing:
  defaults:
    e01:
      full: [dissect, hayabusa, plaso, bulk_extractor, yara]
      light: [dissect, hayabusa]
    disk_raw:
      full: [dissect, hayabusa, plaso, bulk_extractor]
      light: [dissect]
    memory:
      full: [volatility, yara_mem]
      light: [volatility]
    vm_disk:
      full: [dissect]
      light: []
    vm_package:
      full: [dissect]
      light: []
    network_config:
      full: [netcfg]
      light: []
    malware:
      full: [yara, capa]
      light: [yara]

  # Globally disable specific tools
  disabled_tools:
    - autopsy

  # OS-specific adjustments
  os_overrides:
    windows:
      add:
        memory.full: [hayabusa]
      remove:
        disk_raw.full: []
    linux:
      remove:
        memory.full: [hayabusa]

  # Location-specific adjustments
  location_overrides:
    datacenterA:
      add:
        e01.full: [yara_mem]
    remote_site_B:
      remove:
        e01.full: [plaso]  # Skip heavy processing at remote sites

# Tool-specific module configuration
volatility:
  modules:
    - windows.info
    - windows.pslist
    - windows.pstree
    - windows.cmdline
    - windows.netscan
    - windows.handles
    - windows.dlllist
    - windows.services
    - windows.malfind
  # Disable specific modules
  disabled_modules:
    - windows.bigpools  # Too verbose

dissect:
  modules:
    - filesystem
    - registry
    - evtx
    - prefetch
    - timeline
    - amcache
    - shellbags
  disabled_modules: []

hayabusa:
  # Hayabusa supports subcommands; default is json-timeline
  # Options: json-timeline, csv-timeline, logon-summary, metrics
  output_format: json-timeline

plaso:
  output_modules:
    - json_line
  # Options: dynamic, json, json_line, xlsx, elastic, opensearch
  disabled_modules: []

bulk_extractor:
  scanners:
    - email
    - url
    - ccn
    - telephone
    - base64
  disabled_scanners:
    - exif  # Can be noisy

yara:
  rules_dir: /opt/wade/yara
  # Additional rule directories (comma-separated or list)
  additional_rules:
    - /opt/custom_yara_rules
Override Precedence:

Defaults in code (DEFAULT_MATRIX in tool_routing.py)
YAML routing.defaults
YAML os_overrides (based on detected OS family)
YAML location_overrides (based on staging location)
Environment variables (WADE_ROUTE_<CLASS>_<PROFILE>)
Global disable/enable (WADE_DISABLE_TOOLS, WADE_ENABLE_TOOLS)
logrotate.d/wade
Log rotation policy for WADE event logs.

/var/wade/logs/*/*.jsonl {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    missingok
    create 0640 autopsy autopsy
    sharedscripts
    postrotate
        systemctl reload wade-staging.service >/dev/null 2>&1 || true
    endscript
}
Settings:

daily: Rotate once per day
rotate 30: Keep 30 days of compressed logs
compress: Gzip old logs
delaycompress: Don't compress most recent rotation (allows continued writes)
postrotate: Send SIGUSR1 to staging daemon to reopen log files
🔄 Configuration Workflow
1. Initial Setup (via install.sh)
# Install seeds default config files
sudo bash ./install.sh
Results:

/etc/wade/wade.conf — Defaults (don't edit)
/etc/wade/wade.env — Runtime config (edit this)
/etc/wade/config.yaml — Tool routing (edit this)
/etc/logrotate.d/wade — Log rotation (rarely edit)
2. Customizing Configuration
Environment Variables:

# Edit runtime config
sudo nano /etc/wade/wade.env

# Example: Change staging directory
WADE_STAGINGDIR=/mnt/evidence/Staging

# Example: Disable Autopsy and Bulk Extractor globally
WADE_DISABLE_TOOLS=autopsy,bulk_extractor

# Reload service
sudo systemctl restart wade-staging.service
YAML Configuration:

# Edit tool routing
sudo nano /etc/wade/config.yaml

# Example: Add YARA to all E01 processing
routing:
  defaults:
    e01:
      full: [dissect, hayabusa, plaso, yara]

# Reload service (config is read at ticket generation)
sudo systemctl restart wade-staging.service
3. Per-Tool Module Selection
Volatility Modules:

volatility:
  modules:
    - windows.info
    - windows.pslist
    # Add custom module
    - windows.hollowprocesses
Environment Override:

# Override via environment (highest precedence)
WADE_VOLATILITY_MODULES=windows.info,windows.pslist,+windows.malfind,-windows.handles
Syntax:

tool1,tool2,tool3 — Replace entire list
+tool — Add tool to existing list
-tool — Remove tool from existing list
4. Validation
# Validate YAML syntax
python3 -c "
import yaml
with open('/etc/wade/config.yaml') as f:
    config = yaml.safe_load(f)
    print('✓ Valid YAML')
    print(f'Routes defined: {len(config[\"routing\"][\"defaults\"])}')
"

# Test tool routing
python3 -c "
from staging.tool_routing import ToolRouting
router = ToolRouting()
tools = router.select_tools('e01', 'full', {'os_family': 'Windows'})
print(f'E01 full pipeline: {tools}')
"

# Verify environment variables
source /etc/wade/wade.env
echo \"Staging dir: \$WADE_STAGINGDIR\"
echo \"Data dir: \$WADE_DATADIR\"
🎯 Common Configuration Patterns
Minimal Triage Configuration
Goal: Fast processing, minimal tools

# config.yaml
routing:
  defaults:
    e01:
      light: [dissect]
    memory:
      light: [volatility]
    disk_raw:
      light: [dissect]
# wade.env
WADE_ROUTE_E01_LIGHT=dissect
WADE_ROUTE_MEMORY_LIGHT=volatility
WADE_VOLATILITY_MODULES=windows.info,windows.pslist,windows.netscan
Full Forensic Analysis
Goal: Comprehensive tool coverage

# config.yaml
routing:
  defaults:
    e01:
      full: [dissect, hayabusa, plaso, bulk_extractor, yara, autopsy]
    memory:
      full: [volatility, yara_mem, capa]
# wade.env
WADE_ENABLE_TOOLS=autopsy,bulk_extractor,capa
WADE_VOLATILITY_MODULES=windows.info,windows.pslist,windows.pstree,windows.cmdline,windows.netscan,windows.handles,windows.dlllist,windows.malfind,windows.memmap
Incident-Specific Configuration
Goal: Focus on specific threat indicators

# config.yaml for ransomware investigation
routing:
  defaults:
    e01:
      full: [dissect, hayabusa, yara]
    memory:
      full: [volatility, yara_mem]

volatility:
  modules:
    - windows.malfind
    - windows.hollowprocesses
    - windows.pslist
    - windows.cmdline
    - windows.netscan

yara:
  rules_dir: /opt/yara_rules/ransomware
Air-Gapped / Offline Mode
Goal: No external dependencies or network calls

# wade.env
OFFLINE=true
WHIFF_ENABLE=false
SPLUNK_UF_RCVR_HOSTS=  # Disable Splunk forwarding
🔐 Security Considerations
File Permissions
# Recommended ownership and permissions
sudo chown root:autopsy /etc/wade/*.conf /etc/wade/*.env /etc/wade/*.yaml
sudo chmod 0640 /etc/wade/*.conf /etc/wade/*.env /etc/wade/*.yaml
sudo chmod 0755 /etc/wade
Secrets Management
Never commit secrets to Git!

# Use /etc/wade/secrets.env for sensitive values
# (This file is not in version control)
echo "WADE_API_KEY=supersecret" | sudo tee -a /etc/wade/secrets.env
sudo chmod 0600 /etc/wade/secrets.env
Load in systemd unit:

[Service]
EnvironmentFile=/etc/wade/wade.env
EnvironmentFile=-/etc/wade/secrets.env  # Optional, ignore if missing
📚 Reference
All Configurable Variables
Variable	Type	Default	Description
WADE_OWNER_USER	string	autopsy	Service owner user
WADE_DATADIR	path	/home/autopsy/DataSources	Root for processed artifacts
WADE_STAGINGDIR	path	/home/autopsy/Staging	Incoming evidence directory
WADE_QUEUE_DIR	path	/home/autopsy/DataSources/_queue	Work order queue
WADE_LOG_DIR	path	/var/wade/logs	Event log directory
WADE_CONFIG_PATH	path	/etc/wade/config.yaml	YAML config file
WADE_STAGE_STABLE_SECONDS	int	10	File stability wait time
WADE_STAGE_POLL_INTERVAL	int	30	Directory scan interval
WADE_STAGE_REQUIRE_CLOSE_WRITE	bool	true	Wait for inotify CLOSE_WRITE
WADE_STAGE_VERIFY_NO_WRITERS	bool	true	Check lsof for open writers
WADE_STAGE_RECURSIVE	bool	false	Recursively watch subdirectories
WADE_STAGE_ACCEPT_DOCS	bool	false	Accept Office docs, PDFs
WADE_STAGE_AUTO_DEFRAG_E01	bool	false	Auto-reassemble E01 fragments
WADE_VOLATILITY3_PATH	path	auto-detected	Path to vol.py
WADE_EWFINFO_PATH	path	auto-detected	Path to ewfinfo
WADE_EWFEXPORT_PATH	path	auto-detected	Path to ewfexport
WADE_LSOF_PATH	path	auto-detected	Path to lsof
WADE_DISABLE_TOOLS	csv	``	Globally disabled tools
WADE_ENABLE_TOOLS	csv	``	Globally enabled tools (overrides disabled)
WADE_ROUTE_<CLASS>_<PROFILE>	csv	from YAML	Per-classification tool list
Full list: See wade.conf for all 100+ variables.

🛠️ Troubleshooting
Configuration Not Loading
# Check systemd unit is loading environment files
sudo systemctl cat wade-staging.service | grep EnvironmentFile

# Verify file exists and is readable
ls -la /etc/wade/wade.env
sudo cat /etc/wade/wade.env

# Test environment in service context
sudo -u autopsy bash -c 'source /etc/wade/wade.env && env | grep WADE'
YAML Syntax Errors
# Validate YAML
python3 -c "import yaml; yaml.safe_load(open('/etc/wade/config.yaml'))"

# Online validator
# https://coderabbit.ai/configuration/yaml-validator
Tool Not Found
# Check tool discovery
python3 -c "
from wade_workers.wade_workers.subprocess_utils import get_default_registry
reg = get_default_registry()
print('Volatility:', reg.find_tool('volatility'))
print('ewfinfo:', reg.find_tool('ewfinfo'))
"

# Set explicit path
echo "WADE_VOLATILITY3_PATH=/opt/volatility3/vol.py" | sudo tee -a /etc/wade/wade.env
sudo systemctl restart wade-staging.service
For more details, see:

Main README
Staging Documentation
Worker Documentation
