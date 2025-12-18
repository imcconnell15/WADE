# WADE YARA Rules

This directory contains YARA rules for malware detection and IOC scanning within the WADE framework.

---

## 🎯 Overview

YARA rules are used by the **YaraWorker** to scan:
- Disk images and filesystems
- Memory dumps
- Individual files and archives
- Network packet captures (future)

---

## 📂 Directory Structure

```

yara/\
├── packed_rules.yar # Compiled/packed rules (ready to use)\
├── malware/ # Malware family rules\
│ ├── emotet.yar\
│ ├── cobalt_strike.yar\
│ └── ransomware.yar\
├── apt/ # APT group rules\
│ ├── apt28.yar\
│ └── apt29.yar\
├── tools/ # Offensive tool signatures\
│ ├── mimikatz.yar\
│ ├── metasploit.yar\
│ └── powershell_empire.yar\
├── general/ # Generic indicators\
│ ├── base64.yar\
│ ├── crypto.yar\
│ └── network_indicators.yar\
└── custom/ # Case-specific rules

```

---

## 📝 Rule Management

### Adding New Rules

```bash
# Create new rule file
cat > yara/malware/new_threat.yar <<'EOF'
rule NewThreat_Variant1 {
    meta:
        author = "DFIR Team"
        description = "Detects NewThreat malware variant 1"
        date = "2025-12-16"
        version = "1.0"
        reference = "https://example.com/analysis"

    strings:
        $s1 = "unique_string_1" ascii wide
        $s2 = { 4D 5A 90 00 03 ?? ?? ?? }  // PE header with wildcard
        $s3 = /https?:\/\/[a-z0-9]+\.badsite\.com/ nocase

    condition:
        uint16(0) == 0x5A4D and  // PE file
        filesize < 5MB and
        2 of ($s*)
}
EOF

# Validate syntax
yara -w yara/malware/new_threat.yar /dev/null

# Add to packed rules (optional)
cat yara/malware/*.yar > yara/packed_rules.yar

```

### Compiling Rules

```source-shell
# Compile for faster loading
yarac yara/packed_rules.yar yara/compiled_rules.yarc

# Use compiled rules in worker
WADE_YARA_COMPILED_RULES=/opt/wade/yara/compiled_rules.yarc
```

### Testing Rules

```source-shell
# Test against sample file
yara yara/malware/new_threat.yar /path/to/sample.exe

# Test entire ruleset
yara yara/packed_rules.yar /path/to/test/directory/

# Scan memory dump
yara yara/packed_rules.yar /path/to/memory.dmp
```

* * * * *

🔧 Configuration
----------------

### Worker Configuration

```source-yaml
# etc/config.yaml
yara:
  rules_dir: /opt/wade/yara
  additional_rules:
    - /opt/custom_yara_rules
    - /mnt/shared/threat_intel/yara
  compiled_rules: /opt/wade/yara/compiled_rules.yarc  # Optional
```

### Environment Variables

```source-shell
# Override rules directory
WADE_YARA_RULES_DIR=/opt/custom_yara

# Use compiled rules
WADE_YARA_COMPILED_RULES=/opt/wade/yara/compiled_rules.yarc

# Tool path
WADE_YARA_PATH=/usr/local/bin/yara
```

* * * * *

🎯 Usage in WADE
----------------

### Automatic Scanning

YARA runs automatically when configured in tool routing:

```source-yaml
# etc/config.yaml
routing:
  defaults:
    malware:
      full: [yara, capa]
    e01:
      full: [dissect, hayabusa, plaso, yara]
    memory:
      full: [volatility, yara_mem]
```

### Manual Scanning

```source-shell
# Scan specific file via worker
python3 -m wade_workers.cli\
  --worker yara\
  --ticket /path/to/ticket.json

# Direct YARA scan
yara /opt/wade/yara/packed_rules.yar /path/to/suspicious.exe
```

* * * * *

📊 Output Format
----------------

JSONL Output:

```source-json
{
  "tool": "yara",
  "module": "scan",
  "host": "DESKTOP-ABC123",
  "case_id": "2025-001",
  "file_path": "/mnt/evidence/suspicious.exe",
  "rule": "Emotet_Variant2",
  "namespace": "malware",
  "tags": ["banker", "trojan"],
  "matches": [
    {
      "offset": 4096,
      "identifier": "$s1",
      "data": "base64_encoded_match"
    }
  ],
  "meta": {
    "author": "DFIR Team",
    "description": "Emotet banking trojan variant 2",
    "date": "2025-12-01",
    "reference": "https://example.com/emotet"
  }
}
```

* * * * *

🛡️ Best Practices
------------------

### Rule Writing

1\. Descriptive metadata:

```source-yara
meta:
    author = "Your Name / Team"
    description = "Clear description of what this detects"
    date = "2025-12-16"
    version = "1.0"
    hash = "md5_of_sample"  // If based on specific sample
    reference = "URL to analysis or report"
```

2\. Efficient conditions:

```source-yara
// Good: Fast pre-checks
condition:
    uint16(0) == 0x5A4D and  // PE header check
    filesize < 10MB and       // Size limit
    3 of ($s*)                // String matches

// Bad: Expensive operations first
condition:
    all of them and
    pe.imports("kernel32.dll", "CreateRemoteThread")
```

3\. String encoding:

```source-yara
strings:
    $s1 = "malware" ascii wide nocase
    // Matches: ASCII, UTF-16 LE, case-insensitive
```

4\. Hex patterns with wildcards:

```source-yara
strings:
    $hex = { 4D 5A ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 45 }
    // Matches PE with variable bytes between MZ and PE headers
```

### Rule Organization

-   Namespace by category (malware, apt, tools)
-   One family per file for modularity
-   Version rules (Emotet_v1, Emotet_v2) as variants evolve
-   Include parent rules for broad detection + specific variants

* * * * *

🔄 Rule Updates
---------------

### Automated Updates

```source-shell
# Cron job to sync rules from GitHub
cat > /etc/cron.daily/yara-rules-update <<'EOF'
#!/bin/bash
cd /opt/wade/yara
git pull origin main
yarac packed_rules.yar compiled_rules.yarc
systemctl reload wade-queue@autopsy.service
EOF

chmod +x /etc/cron.daily/yara-rules-update
```

### Manual Updates

```source-shell
# Pull latest rules
cd /opt/wade/yara
git pull

# Recompile
cat malware/*.yar apt/*.yar tools/*.yar general/*.yar > packed_rules.yar
yarac packed_rules.yar compiled_rules.yarc

# Reload workers (optional, rules are loaded per-execution)
sudo systemctl reload wade-queue@autopsy.service
```

* * * * *

📚 Resources
------------

-   [YARA Documentation](https://yara.readthedocs.io/)
-   [YARA-Rules GitHub](https://github.com/Yara-Rules/rules)
-   [Awesome YARA](https://github.com/InQuest/awesome-yara)
-   [VirusTotal YARA](https://www.virustotal.com/gui/intelligence-overview)

* * * * *

For more information:

-   [Main README](https://github.com/imcconnell15/WADE/README.md)
-   [Worker Documentation](https://github.com/imcconnell15/WADE/wade_workers/README.md)
