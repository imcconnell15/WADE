#!/usr/bin/env python3
"""
Security Onion -> WADE harvester (pcap/logs):
- Copies recent pcaps into /home/$WADE_OWNER_USER/$WADE_DATADIR/Network/<host>/YYYYmmdd/
- Leaves a small ticket in _queue so WADE can index summaries later if desired
"""
import os, shutil, time, socket, json
from pathlib import Path
from wade_workers.utils import load_env, wade_paths, now_iso

SO_PCAP_DIRS = [Path("/nsm/pcap"), Path("/opt/so/log/pcap")]  # adjust to your SO layout

def main():
    env = load_env()
    host = socket.gethostname()
    paths = wade_paths(env, host)
    net_root = paths["datas"]/ "Network" / host / time.strftime("%Y%m%d")
    net_root.mkdir(parents=True, exist_ok=True)

    copied = 0
    for d in SO_PCAP_DIRS:
        if d.exists():
            for p in sorted(d.glob("*.pcap*"))[-20:]:  # last 20 files
                dst = net_root / p.name
                if not dst.exists():
                    try:
                        shutil.copy2(p, dst)
                        copied += 1
                    except Exception:
                        pass

    if copied:
        # Drop a lightweight ticket
        t = {
            "ts": now_iso(), "ticket":"network/pcap-copied",
            "host": host, "kind":"pcap", "count":copied, "dest_path": str(net_root)
        }
        q = paths["queue"]/f"pcap-{int(time.time())}.json"
        q.write_text(json.dumps(t), encoding="utf-8")

if __name__ == "__main__":
    main()
