"""Change journal with content-addressed backups (outside the workspace) and undo.

- Every file-tool write records the bytes before and after (zlib-compressed blobs, deduplicated by sha256).
- One tool call = one batch (apply_patch on 5 files is undone as a unit).
- Undo refuses to clobber files that changed after the batch (unless force=True) and is itself undoable.
- Stored in <bridge>/state/history, never inside the workspace, so `git add -A` cannot pick it up
  and the model cannot tamper with it through file tools.
"""
import json
import os
import shutil
import threading
import time
import zlib
from datetime import datetime
from pathlib import Path

from nb import runtime, textio

_lock = threading.RLock()


class HistoryError(Exception):
    pass


class History:
    def __init__(self, state_dir: Path):
        self.dir = Path(state_dir) / "history"
        self.blobs = self.dir / "blobs"
        self.journal = self.dir / "journal.jsonl"
        self.blobs.mkdir(parents=True, exist_ok=True)
        self._batches = {}   # id -> batch dict
        self._next = 1
        self._load()

    # ------------------------------------------------------------ storage
    def _load(self):
        if not self.journal.exists():
            return
        with open(self.journal, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if rec.get("type") == "batch":
                    self._batches[rec["id"]] = rec
                    self._next = max(self._next, rec["id"] + 1)
                elif rec.get("type") == "undone" and rec.get("id") in self._batches:
                    self._batches[rec["id"]]["undone_by"] = rec.get("by")

    def _append(self, rec):
        with open(self.journal, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            f.flush()

    def put_blob(self, data: bytes) -> str:
        h = textio.sha256(data)
        p = self.blobs / h[:2] / (h + ".z")
        if not p.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(".tmp")
            with open(tmp, "wb") as f:
                f.write(zlib.compress(data, 6))
            os.replace(tmp, p)
        return h

    def get_blob(self, h: str) -> bytes:
        p = self.blobs / h[:2] / (h + ".z")
        if not p.exists():
            raise HistoryError(f"Backup blob {h[:12]} is missing (pruned?).")
        return zlib.decompress(p.read_bytes())

    def _max_file(self):
        return (runtime.config.get("backups") or {}).get("max_file_mb", 50) * 1024 * 1024

    def enabled(self):
        return (runtime.config.get("backups") or {}).get("enabled", True)

    # ------------------------------------------------------------ recording
    def begin(self, tool: str, summary: str):
        return Batch(self, tool, summary)

    def _commit(self, batch):
        if not batch.entries:
            return None
        with _lock:
            bid = self._next
            self._next += 1
            rec = {"type": "batch", "id": bid, "ts": datetime.now().isoformat(timespec="seconds"),
                   "tool": batch.tool, "summary": batch.summary[:300], "entries": batch.entries,
                   "client": runtime.client_ip.get("")}
            if batch.undo_of:
                rec["undo_of"] = batch.undo_of
            self._batches[bid] = rec
            self._append(rec)
            if batch.undo_of and batch.undo_of in self._batches:
                self._batches[batch.undo_of]["undone_by"] = bid
                self._append({"type": "undone", "id": batch.undo_of, "by": bid})
            return bid

    # ------------------------------------------------------------ queries
    def list(self, limit=20, path_filter=""):
        with _lock:
            items = sorted(self._batches.values(), key=lambda b: -b["id"])
        out = []
        for b in items:
            if path_filter and not any(path_filter.lower() in (e.get("display") or "").lower() for e in b["entries"]):
                continue
            out.append(b)
            if len(out) >= limit:
                break
        return out

    def get(self, bid):
        b = self._batches.get(bid)
        if not b:
            raise HistoryError(f"Change #{bid} not found.")
        return b

    def latest_undoable(self):
        for b in self.list(500):
            if not b.get("undone_by") and not b.get("undo_of"):
                return b
        return None

    def stats(self):
        size = 0
        n = 0
        for root, _, files in os.walk(self.blobs):
            for f in files:
                try:
                    size += os.path.getsize(os.path.join(root, f))
                    n += 1
                except OSError:
                    pass
        return {"batches": len(self._batches), "blobs": n, "size_mb": round(size / 1048576, 1)}

    # ------------------------------------------------------------ undo
    def undo(self, bid=None, force=False):
        from nb import paths  # local import to avoid cycles
        with _lock:
            b = self.get(bid) if bid else self.latest_undoable()
            if not b:
                raise HistoryError("Nothing to undo.")
            if b.get("undone_by"):
                raise HistoryError(f"Change #{b['id']} was already undone by #{b['undone_by']}. Undo #{b['undone_by']} to redo it.")
            plan, conflicts = [], []
            for e in reversed(b["entries"]):
                p = Path(e["abs"])
                if not any(paths.is_within(p, r) for r in paths.workspaces().values()):
                    conflicts.append(f"{e['display']}: no longer inside a configured workspace")
                    continue
                kind = e["kind"]
                if kind in ("modify", "create", "delete"):
                    cur = p.read_bytes() if p.is_file() else None
                    cur_sha = textio.sha256(cur) if cur is not None else None
                    if e.get("before") in ("too-large", "disabled"):
                        conflicts.append(f"{e['display']}: was not backed up ({e['before']}), cannot restore")
                        continue
                    if cur_sha != e.get("after"):
                        conflicts.append(f"{e['display']}: changed after #{b['id']} (current content differs)")
                    plan.append(e)
                elif kind == "move":
                    src, dst = Path(e["abs"]), Path(e["dst_abs"])
                    if not dst.exists() or src.exists():
                        conflicts.append(f"{e['display']} -> {e['dst_display']}: cannot move back (destination missing or source exists)")
                    plan.append(e)
                elif kind == "mkdir":
                    plan.append(e)
            if conflicts and not force:
                raise HistoryError("Undo of #%d refused:\n- %s\nRe-run with force=true to overwrite anyway (the current state is backed up first)." % (b["id"], "\n- ".join(conflicts)))

            ub = self.begin(f"undo #{b['id']}", f"undo of #{b['id']} ({b['tool']})")
            ub.undo_of = b["id"]
            done = []
            for e in plan:
                p = Path(e["abs"])
                kind = e["kind"]
                if kind in ("modify", "create", "delete"):
                    before = None if e.get("before") is None else self.get_blob(e["before"])
                    cur = p.read_bytes() if p.is_file() else None
                    if before is None:
                        if cur is not None:
                            ub.record(p, e["display"], cur, None)
                            textio.remove_file(p)
                            done.append(f"deleted {e['display']}")
                    else:
                        ub.record(p, e["display"], cur, before)
                        textio.atomic_write(p, before)
                        done.append(f"restored {e['display']}")
                elif kind == "move":
                    src, dst = Path(e["abs"]), Path(e["dst_abs"])
                    if dst.exists() and not src.exists():
                        src.parent.mkdir(parents=True, exist_ok=True)
                        shutil.move(str(dst), str(src))
                        ub.record_move(dst, e["dst_display"], src, e["display"])
                        if e.get("overwritten"):
                            data = self.get_blob(e["overwritten"])
                            textio.atomic_write(dst, data)
                            ub.record(dst, e["dst_display"], None, data)
                        done.append(f"moved back {e['dst_display']} -> {e['display']}")
                elif kind == "mkdir":
                    try:
                        textio.remove_dir(p)
                        done.append(f"removed empty folder {e['display']}")
                    except OSError:
                        done.append(f"kept folder {e['display']} (not empty)")
            nb_id = ub.commit()
            return b, nb_id, done, conflicts


class Batch:
    def __init__(self, hist: History, tool: str, summary: str):
        self.h, self.tool, self.summary = hist, tool, summary
        self.entries = []
        self.undo_of = None
        self.committed_id = None

    def record(self, abs_path: Path, display: str, before, after):
        """before/after: bytes or None (None = file absent)."""
        h = self.h
        if before is None and after is None:
            return
        kind = "create" if before is None else ("delete" if after is None else "modify")
        e = {"kind": kind, "abs": str(abs_path), "display": display}
        lim, on = h._max_file(), h.enabled()
        if before is None:
            e["before"] = None
        elif not on:
            e["before"] = "disabled"
        elif len(before) > lim:
            e["before"] = "too-large"
        else:
            e["before"] = h.put_blob(before)
        if after is None:
            e["after"] = None
        elif on and len(after) <= lim:
            e["after"] = h.put_blob(after)        # blob name == sha256, used for conflict checks and diffs
        else:
            e["after"] = textio.sha256(after)
        e["size"] = len(after) if after is not None else 0
        self.entries.append(e)

    def record_move(self, src_abs, src_display, dst_abs, dst_display, overwritten: bytes = None):
        e = {"kind": "move", "abs": str(src_abs), "display": src_display, "dst_abs": str(dst_abs), "dst_display": dst_display}
        if overwritten is not None:
            e["overwritten"] = self.h.put_blob(overwritten)
        self.entries.append(e)

    def record_mkdir(self, abs_path, display):
        self.entries.append({"kind": "mkdir", "abs": str(abs_path), "display": display})

    def commit(self):
        self.committed_id = self.h._commit(self)
        return self.committed_id


def prune(hist: History):
    """Drop batches older than max_age_days and keep blob storage under max_total_mb."""
    cfg = runtime.config.get("backups") or {}
    max_age = cfg.get("max_age_days", 30) * 86400
    max_total = cfg.get("max_total_mb", 1024) * 1048576
    now = time.time()
    with _lock:
        keep = {}
        for bid, b in sorted(hist._batches.items()):
            try:
                ts = datetime.fromisoformat(b["ts"]).timestamp()
            except (ValueError, KeyError):
                ts = now
            if now - ts <= max_age:
                keep[bid] = b
        referenced = {}
        for bid in sorted(keep, reverse=True):  # newest first
            for e in keep[bid]["entries"]:
                for k in ("before", "after", "overwritten"):
                    v = e.get(k)
                    if v and v not in ("too-large", "disabled"):
                        referenced.setdefault(v, bid)
        # size budget: walk newest -> oldest
        sizes, total, allowed = {}, 0, set()
        for h_, bid in sorted(referenced.items(), key=lambda kv: -kv[1]):
            p = hist.blobs / h_[:2] / (h_ + ".z")
            sz = p.stat().st_size if p.exists() else 0
            if total + sz <= max_total:
                total += sz
                allowed.add(h_)
        dropped_batches = [bid for bid, b in keep.items()
                           if any(e.get("before") and e["before"] not in ("too-large", "disabled") and e["before"] not in allowed
                                  for e in b["entries"])]
        for bid in dropped_batches:
            keep.pop(bid, None)
        removed = 0
        for root, _, files in os.walk(hist.blobs):
            for f in files:
                if f.endswith(".z") and f[:-2] not in allowed:
                    try:
                        os.unlink(os.path.join(root, f))
                        removed += 1
                    except OSError:
                        pass
        if len(keep) != len(hist._batches) or removed:
            tmp = hist.journal.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                for bid in sorted(keep):
                    b = dict(keep[bid])
                    undone = b.pop("undone_by", None)
                    f.write(json.dumps(b, ensure_ascii=False) + "\n")
                    if undone:
                        f.write(json.dumps({"type": "undone", "id": bid, "by": undone}) + "\n")
            os.replace(tmp, hist.journal)
            hist._batches = keep
        return removed
