#!/usr/bin/env python3
"""
Pack YARA rules:
- Lints & compiles a rules directory into one consolidated file
"""
import argparse, sys, os, yara
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rules_dir", help="Path to YARA rules directory")
    ap.add_argument("-o", "--out", default="/opt/wade/yara/packed_rules.yar",
                    help="Output compiled rule file")
    args = ap.parse_args()

    rules_dir = Path(args.rules_dir)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    sources = {}
    for p in rules_dir.rglob("*.yar"):
        sources[str(p)] = p.read_text(encoding="utf-8", errors="ignore")

    try:
        comp = yara.compile(sources=sources)
    except Exception as e:
        print(f"[-] YARA compile error: {e}", file=sys.stderr)
        sys.exit(1)

    # Save a source-concatenated pack (keeps readability)
    with out.open("w", encoding="utf-8") as f:
        for k in sorted(sources.keys()):
            f.write("// ---- " + k + " ----\n")
            f.write(sources[k] + "\n\n")
    print(f"[+] Packed YARA rules -> {out}")

if __name__ == "__main__":
    main()
