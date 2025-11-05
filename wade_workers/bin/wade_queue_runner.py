#!/usr/bin/env python3
import os, sys, time, signal, subprocess
from pathlib import Path

try:
    from wade_workers.utils import load_env
except Exception:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from wade_workers.utils import load_env  # type: ignore

RUNNING = True
def _stop(*_):
    global RUNNING
    RUNNING = False

def _queue_root(env: dict) -> Path:
    owner   = env.get("WADE_OWNER_USER","autopsy")
    datadir = env.get("WADE_DATADIR","DataSources")
    qdir    = env.get("WADE_QUEUE_DIR","_queue")
    base = Path(f"/home/{owner}")/datadir
    q = Path(qdir)
    return q if q.is_absolute() else (base/q)

def _tickets(qroot: Path):
    for p in qroot.glob("*/*/*.json"):
        if any(s in p.suffixes for s in (".work",".done",".dead",".tmp")):
            continue
        yield p

def _lock(p: Path) -> Path | None:
    locked = p.with_name(p.stem + f".work-{os.getpid()}" + "".join(p.suffixes))
    try:
        p.rename(locked)
        return locked
    except Exception:
        return None

def main():
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    env = load_env()
    qroot = _queue_root(env)
    cli = Path(__file__).resolve().parents[1] / "wade_workers" / "cli.py"

    print(f"[*] WADE queue runner watching {qroot}", flush=True)
    qroot.mkdir(parents=True, exist_ok=True)

    while RUNNING:
        worked = 0
        for t in list(_tickets(qroot)):
            l = _lock(t)
            if not l:
                continue
            worked += 1
            # >>> VERBOSE: show the lock and dispatch
            print(f"[*] lock {l.name} -> dispatching {cli.name}", flush=True)
            try:
                rc = subprocess.call([sys.executable, str(cli), str(l)])
                base = l.with_suffix("")
                if rc == 0:
                    dst = base.with_suffix(".done.json")
                    print(f"[+] {t.name} -> DONE", flush=True)
                else:
                    dst = base.with_suffix(".dead.json")
                    print(f"[!] {t.name} -> DEAD (rc={rc})", flush=True)
                dst.write_bytes(l.read_bytes())
                l.unlink(missing_ok=True)
            except Exception as e:
                # catastrophic → dead-letter
                try:
                    base = l.with_suffix("")
                    base.with_suffix(".dead.json").write_bytes(l.read_bytes())
                    print(f"[!] {t.name} -> DEAD (exception: {e})", flush=True)
                    l.unlink(missing_ok=True)
                except Exception:
                    pass

        if worked == 0:
            time.sleep(2)

if __name__ == "__main__":
    main()
PY
