#!/usr/bin/env python3
import os, io, json, shutil, subprocess, tempfile, time, socket
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple

WADE_ENV_FILE = Path("/etc/wade/wade.env")
JQ_DIR        = Path("/etc/wade/json_injection.d")  # your installer seeds 00-universal.jq
DEFAULTS = {
    "WADE_OWNER_USER": "autopsy",
    "WADE_DATADIR": "DataSources",
    "WADE_STAGINGDIR": "Staging",
    "WADE_QUEUE_DIR": "_queue",
    "WADE_LOG_DIR": "/var/wade/logs",
}

def load_env() -> Dict[str, str]:
    env = dict(os.environ)
    if WADE_ENV_FILE.exists():
        for line in WADE_ENV_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    for k, v in DEFAULTS.items():
        env.setdefault(k, v)
    return env

def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()

def wade_paths(env: Dict[str,str], host: Optional[str]=None) -> Dict[str, Path]:
    user   = env["WADE_OWNER_USER"]
    base   = Path("/home")/user
    datas  = base/env["WADE_DATADIR"]
    hosts  = datas/"Hosts"
    queue  = datas/env["WADE_QUEUE_DIR"]
    logs   = Path(env["WADE_LOG_DIR"])
    return {
        "base": base, "datas": datas, "hosts": hosts, "queue": queue, "logs": logs,
        "host_root": (hosts/(host or env.get("WADE_HOSTNAME") or socket.gethostname()))
    }

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)
    os.umask(0o002)

def cmd_ok(cmd: List[str]) -> bool:
    try:
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except Exception:
        return False

def _apply_jq_chain(tmp_in: Path, jq_dir: Path) -> Path:
    """Optionally apply jq filters (your 00-universal.jq etc.). Returns new tmp file."""
    if not jq_dir.exists():
        return tmp_in
    filters = sorted([p for p in jq_dir.iterdir() if p.suffix == ".jq"])
    if not filters:
        return tmp_in
    outp = Path(tmp_in.parent) / (tmp_in.name + ".jqtmp")
    with outp.open("wb") as w:
        # Stream line-by-line to avoid holding whole file; apply each filter in sequence
        with tmp_in.open("rb") as r:
            for raw in r:
                try:
                    line = raw.decode("utf-8").rstrip("\n")
                    if not line:
                        continue
                    data = line.encode("utf-8")
                    for flt in filters:
                        proc = subprocess.run(["jq", "-c", "-f", str(flt)],
                                              input=data, stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE, check=True)
                        data = proc.stdout
                    w.write(data + b"\n")
                except Exception:
                    # On jq failure, write original line to avoid data loss
                    w.write(raw)
    return outp

def finalize_records_to_json(
    env: Dict[str,str],
    host: str,
    tool: str,
    module: str,
    records: Iterable[dict],
    help_text: str,
    image_path: Optional[str] = None,
    prefer_jsonl: bool = True
) -> Tuple[Optional[Path], int]:
    """
    Writes to DataSources/Hosts/<host>/<tool>/<module>/<host>_<module>_<ts>.json(.nosj => .json)
    Injects 'hostname', 'module', 'help' (per spec) and .wade block.
    Uses jq filters from /etc/wade/json_injection.d if present (00-universal.jq adds .wade.* already).
    Returns (final_path_or_None_if_empty, count)
    """
    paths = wade_paths(env, host)
    outdir = paths["host_root"]/tool/module
    ensure_dir(outdir)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = f"{host}_{module}_{ts}"
    ext = ".jsonl" if prefer_jsonl else ".json"
    tmp_path = outdir / (stem + ext + ".nosj")

    count = 0
    with tmp_path.open("w", encoding="utf-8") as f:
        for obj in records:
            obj = dict(obj or {})
            # required injections
            obj.setdefault("hostname", host)
            obj.setdefault("module", module)
            obj.setdefault("help", help_text)
            # minimal .wade block in case jq chain is missing
            obj.setdefault("wade", {})
            obj["wade"].setdefault("hostname", env.get("WADE_HOSTNAME") or host)
            obj["wade"].setdefault("module", module)
            if image_path:
                obj["wade"].setdefault("image_path", image_path)
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
            count += 1

    if count == 0:
        # Create placeholder per spec; do NOT flip to .json
        ph = outdir / (stem + ".placeholder.txt")
        ph.write_text(
            f"{now_iso()} :: module '{module}' ran with no valid outputs.\n", encoding="utf-8"
        )
        tmp_path.unlink(missing_ok=True)
        return (None, 0)

    # Optional jq transforms
    final_stream = tmp_path
    if shutil.which("jq"):
        try:
            final_stream = _apply_jq_chain(tmp_path, JQ_DIR)
        except Exception:
            final_stream = tmp_path  # fail-open

    final_path = outdir / (stem + ext)  # flip .nosj → real extension
    try:
        if final_stream != tmp_path:
            # replace tmp with jq-processed output
            tmp_path.unlink(missing_ok=True)
            final_stream.replace(final_path)
        else:
            tmp_path.replace(final_path)
    except Exception:
        # last resort copy
        shutil.copy2(final_stream, final_path)
        tmp_path.unlink(missing_ok=True)
        if final_stream != tmp_path:
            final_stream.unlink(missing_ok=True)

    return (final_path, count)

def read_ticket(p: Path) -> Optional[dict]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None
