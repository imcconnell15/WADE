#!/usr/bin/env python3
"""
Queue runner:
- Watches /home/$WADE_OWNER_USER/$WADE_DATADIR/$WADE_QUEUE_DIR for tickets
- Locks each ticket by renaming to .work-<pid> and dispatches to cli
"""
import os, time, subprocess, signal
from pathlib import Path
from wade_workers.utils import load_env, wade_paths, now_iso

RUNNING = True
def _stop(sig, frm):
    global RUNNING
    RUNNING = False

def main():
    env = load_env()
    paths = wade_paths(env)
    queue = paths["queue"]
    cli = Path("/opt/wade/WADE/wade_workers/cli.py")  # adjust if repo path differs
    queue.mkdir(parents=True, exist_ok=True)

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    while RUNNING:
        for t in sorted(queue.glob("*.json")):
            work = t.with_suffix(t.suffix + f".work-{os.getpid()}")
            try:
                t.rename(work)  # atomic lock
            except Exception:
                continue
            try:
                subprocess.run(["/usr/bin/env", "python3", str(cli), str(work)],
                               check=False)
            finally:
                # processed or not, archive ticket
                done = work.with_suffix(".done")
                try:
                    work.rename(done)
                except Exception:
                    work.unlink(missing_ok=True)
        time.sleep(2)

if __name__ == "__main__":
    main()
