"""Activity log: in-memory ring for the dashboard + JSONL on disk with rotation."""
import collections
import itertools
import json
import os
import sys
import threading
from datetime import datetime
from pathlib import Path

_lock = threading.Lock()
_ring = collections.deque(maxlen=1000)
_ids = itertools.count(1)
_file: Path = None
MAX_BYTES = 5 * 1024 * 1024
KEEP = 3


def init(state_dir: Path):
    global _file, _ids
    state_dir.mkdir(parents=True, exist_ok=True)
    _file = state_dir / "activity.jsonl"
    last = 0
    if _file.exists():
        try:
            with open(_file, "rb") as f:
                f.seek(max(0, _file.stat().st_size - 65536))
                tail = f.read().decode("utf-8", "replace").splitlines()
            for line in tail[-200:]:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                last = max(last, int(rec.get("id", 0)))
                _ring.append(rec)
        except OSError:
            pass
    _ids = itertools.count(last + 1)


def _rotate():
    try:
        if _file and _file.exists() and _file.stat().st_size > MAX_BYTES:
            for i in range(KEEP - 1, 0, -1):
                src = _file.with_suffix(f".jsonl.{i}")
                if src.exists():
                    os.replace(src, _file.with_suffix(f".jsonl.{i + 1}"))
            os.replace(_file, _file.with_suffix(".jsonl.1"))
    except OSError:
        pass


def log(action: str, detail: str = "", status: str = "ok", ms: int = None, client: str = ""):
    with _lock:
        rec = {"id": next(_ids), "ts": datetime.now().strftime("%H:%M:%S"), "date": datetime.now().strftime("%Y-%m-%d"),
               "action": action, "detail": (detail or "")[:400], "status": status}
        if ms is not None:
            rec["ms"] = ms
        if client:
            rec["client"] = client
        _ring.append(rec)
        if _file:
            _rotate()
            try:
                with open(_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            except OSError:
                pass
    try:
        line = f"[{rec['ts']}] [{status.upper()}] {action}: {rec['detail']}"
        print(line[:300], flush=True)
    except Exception:
        pass
    return rec


def since(last_id: int = 0, limit: int = 200):
    with _lock:
        items = [r for r in _ring if r["id"] > last_id]
    return items[-limit:]
