"""MCP tools. Every tool: capability check (mode), activity log, typed errors -> isError results,
annotations (readOnly/destructive/idempotent), plain-text output (no duplicated structuredContent),
blocking work offloaded to threads so one slow call never freezes the server."""
import asyncio
import fnmatch
import functools
import inspect
import os
import re
import shutil
import subprocess
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Annotated, List, Optional

from pydantic import BaseModel, Field
from mcp.server.fastmcp import Context, FastMCP, Image
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations

import config_manager
from nb import __version__, activity, approvals, docs, gitops, history, latex, paths, procs, runtime, symbols, textio
from nb import edit as E
from nb import paths as pathsmod

IS_WIN = os.name == "nt"
HIST: history.History = None
TUNNEL = None
RG = ""
_TOOLS = []
CAP_LABEL = {"read": "read access", "write": "file write access (Developer mode)", "exec": "command execution (Developer mode)",
             "git_write": "git write access (Developer mode)", "screen": "screen capture (Agent mode)"}
IMAGE_EXTS = {".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".gif": "gif", ".webp": "webp", ".bmp": "bmp"}
DOC_EXTS = {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".pdf"}
MAX_READ_CHARS = 100_000
MAX_LINE = 2000
SEARCH_IGNORES = ["node_modules", "__pycache__", ".venv", "venv", ".mypy_cache", ".pytest_cache", ".tox", ".next"]
EXPECTED_ERRORS = (paths.PathError, E.EditError, history.HistoryError, gitops.GitError, docs.DocError, symbols.SymbolError,
                   textio.TextDecodeError, ValueError, KeyError, FileNotFoundError, FileExistsError, IsADirectoryError,
                   NotADirectoryError, PermissionError, RuntimeError, TimeoutError)

_locks_guard = threading.Lock()
_locks = {}


def file_lock(p: Path):
    key = os.path.normcase(str(p))
    with _locks_guard:
        return _locks.setdefault(key, threading.Lock())


def _summ(kwargs) -> str:
    parts = []
    for k, v in kwargs.items():
        if k == "ctx" or v in (None, "", [], False):
            continue
        if k in ("content", "new_text", "old_text", "new_content", "patch", "new_code", "text", "edits", "message"):
            parts.append(f"{k}=<{len(str(v))} chars>")
        else:
            parts.append(f"{k}={str(v)[:90]}")
    return ", ".join(parts)[:300]


REDACTED = "[REDACTED: bridge secret]"


def _redact(res):
    """Never hand the bridge's own secrets to the model, wherever they appear (a copy of config.json inside a
    workspace, a log, command output, git history...)."""
    secrets_ = [v for v in (runtime.config.get("token"), runtime.config.get("cloudflare_tunnel_token"))
                if isinstance(v, str) and len(v) >= 16]
    if not secrets_:
        return res

    def clean(t):
        for sv in secrets_:
            if sv in t:
                t = t.replace(sv, REDACTED)
        return t
    if isinstance(res, str):
        return clean(res)
    if isinstance(res, (list, tuple)):
        return type(res)(clean(x) if isinstance(x, str) else x for x in res)
    return res


def tool(cap: str, title: str, ro=False, destructive=False, idempotent=False, open_world=False):
    def deco(fn):
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            name = fn.__name__
            t0 = time.time()
            client = runtime.client_ip.get("")
            if not runtime.has_cap(cap):
                activity.log(name, f"blocked in {runtime.mode()} mode", status="blocked", client=client)
                raise ToolError(f"Permission denied: {name} needs {CAP_LABEL[cap]}, but the bridge is in "
                                f"'{runtime.mode()}' mode. Ask the user to switch the mode in the bridge dashboard.")
            try:
                if inspect.iscoroutinefunction(fn):
                    res = await fn(*args, **kwargs)
                else:
                    res = await asyncio.to_thread(fn, *args, **kwargs)
            except ToolError as e:
                activity.log(name, f"{_summ(kwargs)} -> {str(e)[:150]}", status="error", ms=int((time.time() - t0) * 1000), client=client)
                raise
            except EXPECTED_ERRORS as e:
                msg = e.args[0] if isinstance(e, KeyError) and e.args else str(e)
                activity.log(name, f"{_summ(kwargs)} -> {msg[:150]}", status="error", ms=int((time.time() - t0) * 1000), client=client)
                raise ToolError(_redact(msg)) from None
            except asyncio.CancelledError:
                activity.log(name, f"{_summ(kwargs)} -> cancelled by client", status="error", client=client)
                raise
            except Exception as e:
                _crash_log(name, kwargs)
                activity.log(name, f"{_summ(kwargs)} -> internal error {type(e).__name__}: {e}", status="error", client=client)
                raise ToolError(_redact(f"Internal error in {name}: {type(e).__name__}: {e} (details in state/errors.log)")) from None
            activity.log(name, _summ(kwargs), status="ok", ms=int((time.time() - t0) * 1000), client=client)
            return _redact(res)
        _TOOLS.append((fn.__name__, title, wrapper, ToolAnnotations(title=title, readOnlyHint=ro, destructiveHint=destructive,
                                                                       idempotentHint=idempotent, openWorldHint=open_world)))
        return fn
    return deco


def _crash_log(name, kwargs):
    try:
        p = config_manager.STATE_DIR / "errors.log"
        with open(p, "a", encoding="utf-8") as f:
            f.write(f"\n=== {datetime.now().isoformat()} {name} {_summ(kwargs)}\n{traceback.format_exc()}")
    except OSError:
        pass


def register(mcp: FastMCP, hist, tunnel, rg_path: str):
    global HIST, TUNNEL, RG
    HIST, TUNNEL, RG = hist, tunnel, rg_path
    disabled = set(runtime.config.get("disabled_tools") or [])
    n = 0
    for name, title, fn, ann in _TOOLS:
        if name in disabled:
            continue
        doc = inspect.cleandoc(fn.__doc__ or "")
        mcp.tool(name=name, title=title, description=doc, annotations=ann, structured_output=False)(fn)
        n += 1
    return n


# ============================================================== helpers
def _human(n) -> str:
    if n is None:
        return ""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def _mtime(p: Path) -> str:
    try:
        return datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
    except OSError:
        return "?"


def _is_link(entry) -> bool:
    try:
        if entry.is_symlink():
            return True
        j = getattr(entry, "is_junction", None)
        return bool(j and j())
    except OSError:
        return False


def _load_doc(r: paths.Resolved) -> textio.TextDoc:
    if not r.path.is_file():
        raise FileNotFoundError(f"File not found: {r.display}" + (" (it is a directory)" if r.path.is_dir() else ""))
    return textio.read_doc(r.path)


def _write(r: paths.Resolved, doc: Optional[textio.TextDoc], new_text: str, tool_name: str, summary: str, encoding: str = ""):
    """Encode + backup + atomic write. Returns (change_id or None, bytes)."""
    base = doc if doc is not None else textio.new_doc(r.path, encoding)
    data = textio.encode(base, new_text, encoding if doc is not None else "")
    before = doc.raw if (doc is not None and r.path.exists()) else None
    if before is not None and before == data:
        return None, data
    b = HIST.begin(tool_name, summary)
    b.record(r.path, r.display, before, data)
    textio.atomic_write(r.path, data)
    return b.commit(), data


def _change_note(cid) -> str:
    return f" · change #{cid} (undo_change {cid})" if cid else ""


def _extra_warnings(r, old, new):
    w = symbols.syntax_warning(r.path.suffix, old, new)
    return [w] if w else []


def _check_version(doc, expected_version):
    if expected_version and doc is not None and doc.version != expected_version.strip():
        raise E.EditError(f"File changed since you read it (version {doc.version}, expected {expected_version}). "
                          "Read it again before editing.")


# ============================================================== status
@tool("read", "Bridge status", ro=True, idempotent=True)
def get_status() -> str:
    """Show the bridge state: mode and what it allows, workspaces (aliases for paths), tools available on this PC
    (shell, git, ripgrep), tunnel and backups. Call this first if unsure which paths or capabilities exist."""
    cfg = runtime.config
    wss = paths.workspaces()
    lines = [f"Open Notion Bridge {__version__} · mode: {runtime.mode()} · capabilities: {', '.join(sorted(runtime.caps()))}",
             "Workspaces (relative paths use the default; others via '@alias/path'):"]
    for a, root in wss.items():
        mark = " (default)" if a == paths.default_alias() else ""
        lines.append(f"  @{a}{mark}: {root}" + ("" if root.is_dir() else "  [MISSING]"))
    sh = procs.detect_shell()
    git = gitops.git_exe()
    lines += [f"Shell: {sh[0]} ({sh[1]}) · command confirmation: {cfg.get('confirm_commands')}",
              f"git: {git or 'not found'} · ripgrep: {RG or 'not found (slower Python search)'}",
              "LaTeX: " + (("latexmk" if shutil.which("latexmk") else "") + (" pdflatex" if shutil.which("pdflatex") else "")
                           + (" tectonic" if latex.find_tectonic() else "")).strip().replace(" ", ", ") if (shutil.which("latexmk") or shutil.which("pdflatex") or latex.find_tectonic()) else "LaTeX: not found",
              f"Tunnel: {TUNNEL.status if TUNNEL else 'n/a'} {('· ' + TUNNEL.provider) if TUNNEL and TUNNEL.provider else ''}",
              f"Backups: {HIST.stats() if HIST else 'n/a'}",
              "Security model (honest): file tools are confined to the workspaces and block secrets "
              "(.env, keys, .ssh ...). run_command / start_process are NOT sandboxed: they run as the Windows user; "
              "risky commands require the user's approval in the dashboard. Changes made by commands are not covered by undo_change."]
    return "\n".join(lines)


# ============================================================== reading
def _read_block(r: paths.Resolved, offset: int, max_lines: int, line_numbers: bool, char_budget: int = MAX_READ_CHARS) -> str:
    doc = _load_doc(r)
    text = doc.text
    if not text:
        return f"(empty file) [{r.display} · {doc.label} · version {doc.version}]"
    lines = text.split("\n")
    if text.endswith("\n"):
        lines.pop()
    total = len(lines)
    start = max(0, total + offset) if offset < 0 else max(0, offset - 1)
    if start >= total:
        return f"(offset {offset} is past the end: file has {total} lines) [version {doc.version}]"
    max_lines = max(1, min(int(max_lines), 5000))
    out, used, cut_lines, i = [], 0, 0, start
    while i < total and i < start + max_lines:
        ln = lines[i]
        if len(ln) > MAX_LINE:
            ln = ln[:MAX_LINE] + f" … [line truncated, {len(lines[i])} chars]"
            cut_lines += 1
        piece = (f"{i + 1:>6}\t{ln}" if line_numbers else ln)
        if used + len(piece) > char_budget and out:
            break
        out.append(piece)
        used += len(piece) + 1
        i += 1
    last = i
    footer = f"[{r.display}: lines {start + 1}-{last} of {total} · {doc.label} · version {doc.version}"
    footer += (f"; next: offset={last + 1}]" if last < total else "; end of file]")
    if cut_lines:
        footer += f" ({cut_lines} long lines truncated)"
    return textio.for_display("\n".join(out)) + "\n\n" + footer


@tool("read", "Read file", ro=True, idempotent=True)
def read_file(path: Annotated[str, Field(description="File path, relative to the workspace or '@alias/...'")],
              offset: Annotated[int, Field(description="1-based first line. Negative = last N lines (tail), e.g. -100")] = 1,
              max_lines: Annotated[int, Field(description="Max lines to return (<=5000)")] = 1000,
              line_numbers: Annotated[bool, Field(description="Prefix lines with their numbers (for edit_lines). Never copy the prefixes into edit_file old_text")] = False):
    """Read a text file (any encoding: UTF-8/UTF-16/cp1251 are detected; line endings preserved on write).
    Big files are paged: the footer shows the line range, total lines and the next offset.
    Images (.png/.jpg/.gif/.webp) are returned as images; .docx/.xlsx/.pptx/.pdf are converted to text.
    The footer's 'version' can be passed to edit_lines/write_file as expected_version."""
    r = paths.resolve(path, must_exist=True)
    if r.path.is_dir():
        raise IsADirectoryError(f"{r.display} is a directory; use list_directory.")
    ext = r.path.suffix.lower()
    if ext in IMAGE_EXTS:
        size = r.path.stat().st_size
        if size > 8 * 1024 * 1024:
            raise ValueError(f"Image is too large to return ({_human(size)}).")
        return Image(data=r.path.read_bytes(), format=IMAGE_EXTS[ext])
    if ext in DOC_EXTS:
        return _read_document(r, "", 0, 60000)
    try:
        return _read_block(r, int(offset), int(max_lines), bool(line_numbers))
    except textio.TextDecodeError as e:
        raise textio.TextDecodeError(f"{r.display}: {e} Size {_human(r.path.stat().st_size)}. "
                                     "Use get_file_info, or read_document for Office/PDF files.")


@tool("read", "Read several files", ro=True, idempotent=True)
def read_multiple_files(paths: Annotated[List[str], Field(description="List of file paths")],
                        max_lines_each: int = 400) -> str:
    """Read several text files in one call (each truncated to max_lines_each lines). Errors are reported per file."""
    out = []
    budget = MAX_READ_CHARS
    for p in paths[:30]:
        try:
            r = pathsmod.resolve(p, must_exist=True)
            block = _read_block(r, 1, max_lines_each, False, char_budget=max(2000, budget // max(1, len(paths))))
        except EXPECTED_ERRORS as e:
            block = f"ERROR: {e}"
        out.append(f"===== {p} =====\n{block}")
    return "\n\n".join(out)


def _read_document(r, pages, offset_chars, max_chars):
    text = docs.extract(r.path, pages)
    total = len(text)
    offset_chars = max(0, int(offset_chars))
    chunk = text[offset_chars:offset_chars + max(1000, min(int(max_chars), 200_000))]
    end = offset_chars + len(chunk)
    footer = f"\n\n[{r.display}: characters {offset_chars}-{end} of {total}" + (f"; next: offset_chars={end}]" if end < total else "; end]")
    return chunk + footer


@tool("read", "Read document (docx/xlsx/pptx/pdf)", ro=True, idempotent=True)
def read_document(path: str, pages: Annotated[str, Field(description="PDF pages, e.g. '1-5,8'")] = "",
                  offset_chars: int = 0, max_chars: int = 60000) -> str:
    """Extract text from Word (.docx), Excel (.xlsx, per sheet, tab-separated), PowerPoint (.pptx) or PDF.
    Headings become '#', tables become '| a | b |'. Long documents are paged with offset_chars."""
    r = paths.resolve(path, must_exist=True)
    return _read_document(r, pages, offset_chars, max_chars)


@tool("read", "File info", ro=True, idempotent=True)
def get_file_info(path: str) -> str:
    """Metadata: type, size, dates, read-only flag; for text files also encoding, line endings, line count, version."""
    r = paths.resolve(path, must_exist=True)
    st = r.path.stat()
    info = [f"path: {r.display}", f"absolute: {r.path}",
            f"type: {'directory' if r.path.is_dir() else 'file'}",
            f"modified: {_mtime(r.path)}", f"created: {datetime.fromtimestamp(st.st_ctime).strftime('%Y-%m-%d %H:%M')}"]
    if r.path.is_dir():
        try:
            n = sum(1 for _ in os.scandir(r.path))
        except OSError:
            n = "?"
        info.append(f"entries: {n}")
    else:
        info += [f"size: {_human(st.st_size)} ({st.st_size} bytes)", f"read_only: {not os.access(str(r.path), os.W_OK)}"]
        if st.st_size <= 20 * 1024 * 1024:
            try:
                doc = textio.read_doc(r.path)
                nl = doc.text.count("\n") + (0 if doc.text.endswith("\n") or not doc.text else 1)
                info += [f"text: yes · {doc.label}", f"lines: {nl}", f"version: {doc.version}"]
            except textio.TextDecodeError:
                info.append("text: no (binary)")
    return "\n".join(info)


@tool("read", "List directory", ro=True, idempotent=True)
def list_directory(path: str = ".", depth: Annotated[int, Field(description="1 = this folder only, up to 6")] = 1,
                   show_hidden: bool = False, max_entries: int = 400) -> str:
    """List a folder as a compact tree (folders first, sizes for files). Heavy folders (.git, node_modules,
    __pycache__, venv) are shown but not expanded; symlinks/junctions are not followed; secrets are marked [protected]."""
    r = paths.resolve(path, must_exist=True)
    if not r.path.is_dir():
        raise NotADirectoryError(f"{r.display} is a file; use read_file or get_file_info.")
    depth = max(1, min(int(depth), 6))
    max_entries = max(10, min(int(max_entries), 3000))
    lines, stats = [], {"dirs": 0, "files": 0, "hidden": 0, "truncated": False}

    def walk(d: Path, rel: str, level: int, indent: str):
        try:
            entries = list(os.scandir(d))
        except OSError as e:
            lines.append(f"{indent}(cannot read: {e.strerror})")
            return
        entries.sort(key=lambda e: (not e.is_dir(follow_symlinks=False), e.name.casefold()))
        for e in entries:
            if stats["truncated"]:
                return
            hidden = e.name.startswith(".")
            if IS_WIN and not hidden:
                try:
                    hidden = bool(e.stat(follow_symlinks=False).st_file_attributes & 2)
                except (OSError, AttributeError):
                    pass
            if hidden and not show_hidden:
                stats["hidden"] += 1
                continue
            erel = f"{rel}/{e.name}" if rel else e.name
            if stats["dirs"] + stats["files"] >= max_entries:
                stats["truncated"] = True
                return
            prot = "  [protected]" if paths.is_denied(erel) else ""
            link = _is_link(e)
            try:
                isdir = e.is_dir(follow_symlinks=False) or (link and e.is_dir())
            except OSError:
                isdir = False
            if isdir:
                stats["dirs"] += 1
                note = ""
                if link:
                    note = "  (link, not followed)"
                elif e.name in paths.DEFAULT_IGNORED_DIRS:
                    note = "  (not expanded)"
                elif level >= depth and not prot:
                    try:
                        note = f"  ({sum(1 for _ in os.scandir(e.path))} items)"
                    except OSError:
                        note = ""
                lines.append(f"{indent}{e.name}/{note}{prot}")
                if level < depth and not link and not prot and e.name not in paths.DEFAULT_IGNORED_DIRS:
                    walk(Path(e.path), erel, level + 1, indent + "  ")
            else:
                stats["files"] += 1
                try:
                    size = _human(e.stat(follow_symlinks=False).st_size)
                except OSError:
                    size = "?"
                lines.append(f"{indent}{e.name}  {size}{prot}")

    walk(r.path, r.rel, 1, "")
    head = f"{r.display}/  ({stats['dirs']} folders, {stats['files']} files shown)"
    tail = []
    if stats["hidden"]:
        tail.append(f"{stats['hidden']} hidden entries skipped (show_hidden=true to include)")
    if stats["truncated"]:
        tail.append(f"listing truncated at {max_entries} entries: narrow the path or lower depth")
    return "\n".join([head] + lines + ([f"[{'; '.join(tail)}]"] if tail else []))


def _rg_base():
    args = [RG, "--color", "never", "--path-separator", "/", "--no-messages"]
    for pat in paths.deny_patterns():
        pat = pat.strip().replace("\\", "/").strip("/")
        if pat:
            args += ["-g", f"!{pat}"] + (["-g", f"!{pat}/**"] if "/" in pat else [])
    return args


def _run_rg(args, cwd, timeout=30):
    kw = {"creationflags": procs.CREATE_NO_WINDOW} if IS_WIN else {}
    try:
        p = subprocess.run(args, cwd=str(cwd), capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL, **kw)
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"Search timed out after {timeout}s; narrow the path or glob.")
    return p.returncode, p.stdout.decode("utf-8", "replace").replace("\r\n", "\n"), p.stderr.decode("utf-8", "replace")


def _walk_files(root: Path, start: Path, include_ignored: bool):
    for dirpath, dirnames, filenames in os.walk(start):
        relbase = os.path.relpath(dirpath, root).replace("\\", "/")
        relbase = "" if relbase == "." else relbase
        keep = []
        for d in dirnames:
            drel = f"{relbase}/{d}" if relbase else d
            full = os.path.join(dirpath, d)
            if os.path.islink(full) or paths.is_denied(drel):
                continue
            if not include_ignored and (d.startswith(".") or d in paths.DEFAULT_IGNORED_DIRS):
                continue
            keep.append(d)
        dirnames[:] = keep
        for f in filenames:
            frel = f"{relbase}/{f}" if relbase else f
            if paths.is_denied(frel) or (not include_ignored and f.startswith(".")):
                continue
            yield frel


def _list_files(r: paths.Resolved, include_ignored: bool):
    target = r.rel or "."
    if RG:
        args = _rg_base() + ["--files"]
        if include_ignored:
            args += ["--no-ignore", "--hidden"]
        else:
            for ig in SEARCH_IGNORES:
                args += ["-g", f"!{ig}"]
        code, out, err = _run_rg(args + ["--", target], r.root)
        files = [l for l in out.split("\n") if l]
        return [f[2:] if f.startswith("./") else f for f in files]
    return list(_walk_files(r.root, r.path, include_ignored))


@tool("read", "Find files", ro=True, idempotent=True)
def find_files(pattern: Annotated[str, Field(description="Glob like '*.tex' or 'src/**/test_*.py', or a plain substring of the file name")] = "",
               path: str = ".", max_results: int = 200,
               sort: Annotated[str, Field(description="'path' or 'modified' (newest first)")] = "path",
               include_ignored: Annotated[bool, Field(description="Also search .gitignored/hidden files and node_modules/venv")] = False) -> str:
    """Find files by name (recursive, respects .gitignore). Use search_code to search inside files."""
    r = paths.resolve(path, must_exist=True)
    files = _list_files(r, include_ignored)
    pat = pattern.strip().replace("\\", "/")
    if pat:
        if any(c in pat for c in "*?["):
            rx = paths._glob_to_re(pat)
            files = [f for f in files if (rx.match(f) if "/" in pat else rx.match(f.rsplit("/", 1)[-1]))]
        else:
            low = pat.lower()
            files = [f for f in files if low in f.rsplit("/", 1)[-1].lower()]
    total = len(files)
    if sort == "modified":
        def mt(f):
            try:
                return (r.root / f).stat().st_mtime
            except OSError:
                return 0
        files = sorted(files[:20000], key=mt, reverse=True)
    else:
        files = sorted(files, key=str.casefold)
    max_results = max(1, min(int(max_results), 2000))
    shown = files[:max_results]
    prefix = "" if r.alias == paths.default_alias() else f"@{r.alias}/"
    lines = [f"{prefix}{f}" + (f"  ({_mtime(r.root / f)})" if sort == "modified" else "") for f in shown]
    head = f"{total} file(s) found" + (f", showing {len(shown)}" if total > len(shown) else "")
    return head + ("\n" + "\n".join(lines) if lines else "")


@tool("read", "Search in files", ro=True, idempotent=True)
def search_code(query: Annotated[str, Field(description="Regex (ripgrep syntax) or plain text if regex=false")],
                path: str = ".", glob: Annotated[str, Field(description="Filter files, e.g. '*.py' or '!*.min.js'")] = "",
                regex: bool = True,
                case: Annotated[str, Field(description="'smart' (case-insensitive unless the query has capitals), 'sensitive', 'insensitive'")] = "smart",
                context: Annotated[int, Field(description="Lines of context around matches (<=10)")] = 0,
                max_results: Annotated[int, Field(description="Max output lines (<=1000)")] = 100,
                encoding: Annotated[str, Field(description="Force file encoding, e.g. 'cp1251' for old Windows files")] = "",
                include_ignored: bool = False) -> str:
    """Search file contents (ripgrep: fast, respects .gitignore, skips binaries). Output: path:line:text.
    For a symbol's definition in Python prefer find_symbol."""
    if not query:
        raise ValueError("query is empty")
    r = paths.resolve(path, must_exist=True)
    context = max(0, min(int(context), 10))
    max_results = max(1, min(int(max_results), 1000))
    note = ""
    if RG:
        args = _rg_base() + ["--line-number", "--no-heading", "--with-filename", "--max-columns", "300",
                             "--max-columns-preview", "--max-filesize", "20M", "--max-count", "200"]
        args += {"smart": ["-S"], "sensitive": ["-s"], "insensitive": ["-i"]}.get(case, ["-S"])
        if not regex:
            args.append("-F")
        if context:
            args += ["-C", str(context)]
        if encoding:
            args += ["-E", encoding]
        if glob:
            args += ["-g", glob]
        if include_ignored:
            args += ["--no-ignore", "--hidden"]
        else:
            for ig in SEARCH_IGNORES:
                args += ["-g", f"!{ig}"]
        target = r.rel or "."
        code, out, err = _run_rg(args + ["-e", query, "--", target], r.root)
        if code == 2 and regex and ("regex" in err.lower() or "parse" in err.lower()):
            code, out, err = _run_rg(args + ["-F", "-e", query, "--", target], r.root)
            note = "(invalid regex: searched as plain text) "
        if code == 2 and not out:
            raise ValueError(f"ripgrep error: {err.strip()[:500]}")
        lines = [l[2:] if l.startswith("./") else l for l in out.split("\n") if l]
    else:
        lines = _py_search(r, query, regex, case, context, max_results + 1, glob, include_ignored)
    if not lines:
        return note + "No matches."
    shown = lines[:max_results]
    head = note + (f"{len(lines)}+ lines, showing first {max_results} (narrow with path/glob):" if len(lines) > max_results else "")
    if r.alias != paths.default_alias():
        shown = [f"@{r.alias}/{l}" if not l.startswith("--") else l for l in shown]
    return textio.for_display((head + "\n" if head else "") + "\n".join(shown))


def _py_search(r, query, regex, case, context, limit, glob, include_ignored):
    flags = re.IGNORECASE if case == "insensitive" or (case == "smart" and query == query.lower()) else 0
    try:
        rx = re.compile(query if regex else re.escape(query), flags)
    except re.error:
        rx = re.compile(re.escape(query), flags)
    out = []
    for f in (_walk_files(r.root, r.path, include_ignored) if r.path.is_dir() else [r.rel]):
        if glob and not fnmatch.fnmatch(f.rsplit("/", 1)[-1].lower(), glob.lower().lstrip("!")):
            continue
        p = r.root / f
        try:
            if p.stat().st_size > 20 * 1024 * 1024:
                continue
            doc = textio.read_doc(p)
        except (OSError, textio.TextDecodeError):
            continue
        ls = doc.text.split("\n")
        for i, line in enumerate(ls):
            if rx.search(line):
                for j in range(max(0, i - context), min(len(ls), i + context + 1)):
                    sep = ":" if j == i else "-"
                    out.append(f"{f}{sep}{j + 1}{sep}{ls[j][:300]}")
                if len(out) >= limit:
                    return out
    return out


# ============================================================== writing
_OMIT_RE = re.compile(
    r"^[ \t]*(?:#|//|/\*+|<!--|%|--|;|\*|')[ \t]*(?:\.{2,}|…)?[ \t]*\[?\(?"
    r"(?:rest of (?:the )?(?:code|file|implementation|function|class|content|methods)|"
    r"(?:existing|remaining|other|previous) (?:code|methods|functions|content|implementation)|"
    r"code (?:remains |stays )?(?:the same|unchanged)|unchanged (?:code|content|part)|same as before|"
    r"остальн\w* (?:код|часть|содержимое|функции|методы)|(?:код|остальное|всё остальное) без изменений|как было|без изменений)",
    re.I | re.M)


def _omission_lines(old: str, new: str):
    old_set = {m.group(0).strip() for m in _OMIT_RE.finditer(old)}
    return [m.group(0).strip() for m in _OMIT_RE.finditer(new) if m.group(0).strip() not in old_set]


@tool("write", "Write file", destructive=True)
def write_file(path: str, content: str,
               mode: Annotated[str, Field(description="'rewrite' (default), 'append', or 'create' (fail if the file exists)")] = "rewrite",
               encoding: Annotated[str, Field(description="Only to force an encoding: 'utf-8', 'utf-8-sig', 'cp1251'. Default keeps the file's encoding")] = "",
               expected_version: Annotated[str, Field(description="Optional 'version' from read_file; refuses if the file changed since")] = "",
               force: Annotated[bool, Field(description="Allow content with placeholders like '# ... rest of code ...'")] = False) -> str:
    """Create or overwrite a whole file (parent folders are created). For changes to an existing file prefer
    edit_file / apply_patch: rewriting risks dropping code. Encoding, BOM and line endings of an existing file are
    preserved. Never write placeholders like '... rest of the code unchanged ...': the content is stored literally."""
    r = paths.resolve(path, write=True, allow_root=False)
    if r.path.is_dir():
        raise IsADirectoryError(f"{r.display} is a directory.")
    if len(content) > 20_000_000:
        raise ValueError("Content is larger than 20 MB.")
    content = E.norm_newlines(content)
    with file_lock(r.path):
        exists = r.path.exists()
        if exists and mode == "create":
            raise FileExistsError(f"{r.display} already exists (mode='create'). Use edit_file or mode='rewrite'.")
        doc = _load_doc(r) if exists else None
        _check_version(doc, expected_version)
        old = doc.text if doc else ""
        if mode == "append":
            sep = "\n" if old and not old.endswith("\n") and not content.startswith("\n") else ""
            new = old + sep + content
        else:
            new = content
            if doc and doc.trailing_nl and new and not new.endswith("\n"):
                new += "\n"
            if doc and not force and old.count("\n") >= 20:
                om = _omission_lines(old, new)
                if om:
                    raise E.EditError(
                        "Refused: the new content contains placeholder comments that would delete real code: "
                        + "; ".join(repr(x[:80]) for x in om[:3])
                        + ". Use edit_file for partial changes, or write the complete file. (force=true overrides)")
        cid, data = _write(r, doc, new, "write_file", f"{mode} {r.display}", encoding)
    add, rem = E.diffstat(old, new)
    label = doc.label if doc else textio.new_doc(r.path, encoding).label
    verb = "Appended to" if mode == "append" else ("Overwrote" if exists else "Created")
    if exists and cid is None:
        return f"No changes: {r.display} already has this content."
    msg = [f"{verb} {r.display}: {len(data)} bytes, +{add} -{rem} lines · {label}{_change_note(cid)}"]
    if exists and rem > 30 and rem > 0.5 * max(1, old.count("\n")):
        msg.append(f"NOTE: {rem} of {old.count(chr(10))} lines were removed/replaced. If unintended: undo_change {cid}.")
    msg += _extra_warnings(r, old, new)
    return "\n".join(msg)


class EditOp(BaseModel):
    old_text: str = Field(description="Exact text to find (copy from read_file, including indentation)")
    new_text: str = Field(description="Replacement text")
    expected_replacements: int = Field(1, description="How many occurrences must match; 0 = replace all")
    near_line: int = Field(0, description="If old_text occurs several times, pick the one closest to this line")


@tool("write", "Edit file (search/replace)", destructive=True)
def edit_file(path: str,
              old_text: Annotated[str, Field(description="Exact existing text to replace. Include 1-3 unchanged lines of context so it is unique")] = "",
              new_text: Annotated[str, Field(description="Replacement text (can be empty to delete)")] = "",
              expected_replacements: Annotated[int, Field(description="Occurrences that must match (default 1); 0 = all")] = 1,
              edits: Annotated[Optional[List[EditOp]], Field(description="Several replacements applied in order, all-or-nothing. Use instead of old_text/new_text")] = None,
              dry_run: Annotated[bool, Field(description="Only show the diff, do not write")] = False,
              encoding: str = "") -> str:
    """Targeted search/replace edit of an existing file - the preferred way to change code.
    old_text must match exactly once (unless expected_replacements says otherwise). If it does not match exactly,
    safe fallbacks are tried (trailing whitespace, uniform indentation shift, smart quotes, copied line numbers);
    a fuzzy match is never applied silently: the closest region and a diff are returned instead.
    Returns a compact diff of what changed so you don't need to re-read the file."""
    r = paths.resolve(path, write=True, must_exist=True)
    if edits and old_text:
        raise ValueError("Use either old_text/new_text or edits, not both.")
    ops = [e.model_dump() if hasattr(e, "model_dump") else dict(e) for e in edits] if edits else \
        [{"old_text": old_text, "new_text": new_text, "expected_replacements": expected_replacements}]
    with file_lock(r.path):
        doc = _load_doc(r)
        res = E.apply_edits(doc.text, ops)
        diff = E.unified_diff(doc.text, res.text, r.rel or r.path.name)
        add, rem = E.diffstat(doc.text, res.text)
        if dry_run:
            return f"DRY RUN (nothing written) {r.display}: +{add} -{rem}\n" + "\n".join(res.notes) + "\n" + diff
        cid, data = _write(r, doc, res.text, "edit_file", f"{len(ops)} edit(s) in {r.display}", encoding)
    out = [f"Edited {r.display}: {len(ops)} edit(s), +{add} -{rem} lines · {doc.label}{_change_note(cid)}"]
    out += [n for n in res.notes if "[" in n or "(" in n]
    out += [f"warning: {w}" for w in res.warnings] + _extra_warnings(r, doc.text, res.text)
    out.append(diff)
    return textio.for_display("\n".join(out))


@tool("write", "Edit lines by number", destructive=True)
def edit_lines(path: str,
               start_line: Annotated[int, Field(description="First line to replace (1-based)")],
               end_line: Annotated[int, Field(description="Last line to replace (inclusive). Use start_line-1 to insert before start_line")],
               new_content: Annotated[str, Field(description="New lines (empty string deletes the range)")],
               expected_version: Annotated[str, Field(description="'version' from read_file - strongly recommended, refuses if the file changed")] = "",
               dry_run: bool = False) -> str:
    """Replace, insert or delete whole lines by number (get numbers via read_file line_numbers=true).
    Examples: replace 10-12 -> start 10, end 12; insert before 5 -> start 5, end 4; append -> start N+1, end N."""
    r = paths.resolve(path, write=True, must_exist=True)
    with file_lock(r.path):
        doc = _load_doc(r)
        _check_version(doc, expected_version)
        new = E.replace_lines(doc.text, int(start_line), int(end_line), new_content)
        diff = E.unified_diff(doc.text, new, r.rel or r.path.name)
        if dry_run:
            return "DRY RUN (nothing written)\n" + diff
        cid, _ = _write(r, doc, new, "edit_lines", f"lines {start_line}-{end_line} in {r.display}")
    add, rem = E.diffstat(doc.text, new)
    msg = [f"Edited {r.display} lines {start_line}-{end_line}: +{add} -{rem}{_change_note(cid)}"] + _extra_warnings(r, doc.text, new)
    return textio.for_display("\n".join(msg + [diff]))


@tool("write", "Apply patch (multi-file)", destructive=True)
def apply_patch(patch: Annotated[str, Field(description="Unified diff (git diff format) or '*** Begin Patch' format (Update/Add/Delete File, @@ hunks)")],
                dry_run: bool = False) -> str:
    """Apply a multi-hunk / multi-file patch atomically: if any hunk fails nothing is written.
    Hunk line numbers are only hints - hunks are located by their context lines, so slightly stale
    line numbers still apply. Supports new files, deletions and renames. One undo_change reverts everything."""
    fps = E.parse_patch(patch)
    plan, report = [], []
    for fp in fps:
        if fp.kind == "add":
            r = paths.resolve(fp.path, write=True, allow_root=False)
            if r.path.exists():
                raise FileExistsError(f"{r.display} already exists (patch tries to add it).")
            plan.append(("add", r, None, E.norm_newlines(fp.content), None))
            report.append(f"add    {r.display} (+{fp.content.count(chr(10))})")
        elif fp.kind == "delete":
            r = paths.resolve(fp.path, write=True, must_exist=True, allow_root=False)
            plan.append(("delete", r, None, None, None))
            report.append(f"delete {r.display}")
        else:
            r = paths.resolve(fp.path, write=True, must_exist=True, allow_root=False)
            doc = _load_doc(r)
            res = E.apply_hunks(doc.text, fp.hunks, r.display) if fp.hunks else E.EditResult(doc.text)
            dst = paths.resolve(fp.new_path, write=True, allow_root=False) if fp.new_path else None
            if dst and dst.path.exists():
                raise FileExistsError(f"Rename target {dst.display} already exists.")
            plan.append(("update", r, doc, res.text, dst))
            a, d = E.diffstat(doc.text, res.text)
            report.append(f"update {r.display}{(' -> ' + dst.display) if dst else ''} (+{a} -{d})" +
                          (f"  [{'; '.join(n for n in res.notes if '[' in n)}]" if any('[' in n for n in res.notes) else ""))
            report += [f"  warning: {w}" for w in res.warnings] + ["  " + w for w in _extra_warnings(r, doc.text, res.text)]
    if dry_run:
        diffs = [E.unified_diff(p[2].text, p[3], p[1].rel, max_lines=40) for p in plan if p[0] == "update"]
        return "DRY RUN (nothing written)\n" + "\n".join(report) + ("\n\n" + "\n".join(diffs) if diffs else "")
    batch = HIST.begin("apply_patch", f"{len(plan)} file(s)")
    for kind, r, doc, new, dst in plan:
        with file_lock(r.path):
            if kind == "add":
                data = textio.encode(textio.new_doc(r.path), new)
                batch.record(r.path, r.display, None, data)
                textio.atomic_write(r.path, data)
            elif kind == "delete":
                before = r.path.read_bytes()
                batch.record(r.path, r.display, before, None)
                textio.remove_file(r.path)
            else:
                data = textio.encode(doc, new)
                if dst:
                    batch.record(r.path, r.display, doc.raw, None)
                    batch.record(dst.path, dst.display, None, data)
                    textio.atomic_write(dst.path, data)
                    textio.remove_file(r.path)
                elif data != doc.raw:
                    batch.record(r.path, r.display, doc.raw, data)
                    textio.atomic_write(r.path, data)
    cid = batch.commit()
    return "Patch applied" + _change_note(cid) + ":\n" + "\n".join(report)


# ============================================================== file management
def _collect_files(root: Path, limit_files=5000, limit_bytes=500 * 1024 * 1024):
    files, total = [], 0
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if not textio.is_link_like(os.path.join(dp, d))]  # symlinks AND junctions
        for f in fn:
            p = Path(dp) / f
            try:
                total += p.stat().st_size
            except OSError:
                continue
            files.append(p)
            if len(files) > limit_files or total > limit_bytes:
                raise ValueError(f"Folder is too big for a tracked operation (> {limit_files} files or {_human(limit_bytes)}). "
                                 "Use run_command (not undoable) if you really need it.")
    return files


@tool("write", "Create folder", idempotent=True)
def create_directory(path: str) -> str:
    """Create a folder (and missing parents). No error if it already exists."""
    r = paths.resolve(path, write=True, allow_root=False)
    if r.path.exists():
        if r.path.is_dir():
            return f"{r.display}/ already exists."
        raise FileExistsError(f"{r.display} exists and is a file.")
    missing = []
    p = r.path
    while not p.exists():
        missing.append(p)
        p = p.parent
    r.path.mkdir(parents=True)
    b = HIST.begin("create_directory", r.display)
    for m in reversed(missing):  # shallowest first; undo walks entries backwards (deepest first)
        b.record_mkdir(m, paths.display_for(m))
    return f"Created {r.display}/" + _change_note(b.commit())


@tool("write", "Move / rename", destructive=True)
def move_path(source: str, destination: Annotated[str, Field(description="New path. End with '/' to move into an existing folder")],
              overwrite: bool = False) -> str:
    """Move or rename a file or folder inside the workspaces (undoable)."""
    src = paths.resolve(source, write=True, must_exist=True, allow_root=False)
    if destination.endswith(("/", "\\")):
        base = destination.rstrip("/\\")
        folder = paths.resolve(base or ".", must_exist=True)
        if not folder.path.is_dir():
            raise NotADirectoryError(f"{folder.display} is not a folder.")
        destination = f"{base}/{src.path.name}" if base else src.path.name
    dst = paths.resolve(destination, write=True, allow_root=False)
    if paths.is_within(dst.path, src.path):
        raise ValueError("Cannot move a folder into itself.")
    overwritten = None
    if dst.path.exists():
        if not overwrite:
            raise FileExistsError(f"{dst.display} already exists (overwrite=true to replace a file).")
        if dst.path.is_dir():
            raise IsADirectoryError(f"{dst.display} is an existing folder; refusing to overwrite a folder.")
        overwritten = dst.path.read_bytes()
    dst.path.parent.mkdir(parents=True, exist_ok=True)
    b = HIST.begin("move_path", f"{src.display} -> {dst.display}")
    shutil.move(str(src.path), str(dst.path))
    b.record_move(src.path, src.display, dst.path, dst.display, overwritten)
    return f"Moved {src.display} -> {dst.display}" + _change_note(b.commit())


@tool("write", "Copy", destructive=False)
def copy_path(source: str, destination: str, overwrite: bool = False) -> str:
    """Copy a file or folder inside the workspaces (undoable: undo deletes the copy)."""
    src = paths.resolve(source, must_exist=True)
    dst = paths.resolve(destination, write=True, allow_root=False)
    if dst.path.exists() and (not overwrite or dst.path.is_dir()):
        raise FileExistsError(f"{dst.display} already exists" + ("" if dst.path.is_dir() else " (overwrite=true to replace)") + ".")
    b = HIST.begin("copy_path", f"{src.display} -> {dst.display}")
    if src.path.is_dir():
        if paths.is_within(dst.path, src.path):
            raise ValueError("Cannot copy a folder into itself.")
        files = _collect_files(src.path)
        for f in files:
            rel = os.path.relpath(f, src.path)
            if paths.is_denied((src.rel + "/" + rel.replace("\\", "/")).lstrip("/")):
                continue
            target = dst.path / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            data = f.read_bytes()
            b.record(target, paths.display_for(target), None, data)
            shutil.copy2(str(f), str(target))
        msg = f"Copied folder {src.display} -> {dst.display} ({len(files)} files)"
    else:
        before = dst.path.read_bytes() if dst.path.exists() else None
        dst.path.parent.mkdir(parents=True, exist_ok=True)
        data = src.path.read_bytes()
        b.record(dst.path, dst.display, before, data)
        shutil.copy2(str(src.path), str(dst.path))
        msg = f"Copied {src.display} -> {dst.display} ({_human(len(data))})"
    return msg + _change_note(b.commit())


@tool("write", "Delete (recoverable)", destructive=True)
def delete_path(path: str, recursive: Annotated[bool, Field(description="Required to delete a non-empty folder")] = False) -> str:
    """Delete a file or folder. Contents are backed up first, so undo_change restores them."""
    r = paths.resolve(path, write=True, must_exist=True, allow_root=False)
    b = HIST.begin("delete_path", r.display)
    if r.path.is_dir() and not textio.is_link_like(r.path):
        entries = list(os.scandir(r.path))
        if entries and not recursive:
            raise ValueError(f"{r.display} is not empty ({len(entries)} entries). Pass recursive=true to delete it.")
        files = _collect_files(r.path)
        done = 0
        try:
            for f in files:            # file by file: every deleted file is in the backup before it disappears
                data = f.read_bytes()
                textio.remove_file(f)
                b.record(f, paths.display_for(f), data, None)
                done += 1
            for dp, dn, fn in os.walk(str(r.path), topdown=False):
                for d in dn:
                    textio.remove_dir(os.path.join(dp, d))   # links/junctions: removes the link only
            textio.remove_dir(r.path)
        except OSError as e:
            cid = b.commit() if done else None
            note = f" {done} of {len(files)} files were deleted before the error" + (_change_note(cid) if cid else "") + "."
            raise PermissionError(f"Could not delete everything in {r.display}: {e.strerror or e}.{note} "
                                  "A program (Explorer, editor, antivirus, a running process) may be using it.") from None
        msg = f"Deleted folder {r.display} ({len(files)} files backed up)"
    else:
        data = r.path.read_bytes() if r.path.is_file() else b""
        if textio.is_link_like(r.path) and r.path.is_dir():
            textio.remove_dir(r.path)
            msg = f"Deleted link {r.display} (target untouched)"
        else:
            textio.remove_file(r.path)
            b.record(r.path, r.display, data, None)
            msg = f"Deleted {r.display}"
    cid = b.commit()
    return msg + _change_note(cid)


# ============================================================== history
@tool("read", "List changes (backups)", ro=True, idempotent=True)
def list_changes(limit: int = 15, path: Annotated[str, Field(description="Only changes touching this path (substring)")] = "",
                 change_id: Annotated[int, Field(description="Show details and diffs of one change")] = 0) -> str:
    """Journal of file changes made through the bridge's file tools (with backups). Each entry can be undone."""
    if change_id:
        b = HIST.get(int(change_id))
        out = [f"#{b['id']} {b['ts']} {b['tool']}: {b['summary']}" + (f"  [undone by #{b['undone_by']}]" if b.get("undone_by") else "")]
        budget = 300
        for e in b["entries"]:
            out.append(f"- {e['kind']}: {e['display']}" + (f" -> {e['dst_display']}" if e["kind"] == "move" else ""))
            if e["kind"] in ("modify", "create", "delete") and budget > 0:
                try:
                    before = HIST.get_blob(e["before"]) if e.get("before") and e["before"] not in ("too-large", "disabled") else b""
                    after = HIST.get_blob(e["after"]) if e.get("after") else b""
                    bt = textio.doc_from_bytes(before).text if before else ""
                    at = textio.doc_from_bytes(after).text if after else ""
                    d = E.unified_diff(bt, at, e["display"], max_lines=min(80, budget))
                    budget -= d.count("\n") + 1
                    out.append(d)
                except (history.HistoryError, textio.TextDecodeError):
                    out.append("  (binary or not stored)")
        return textio.for_display("\n".join(out))
    items = HIST.list(max(1, min(int(limit), 100)), path)
    if not items:
        return "No changes recorded yet."
    out = []
    for b in items:
        files = ", ".join(sorted({e["display"] for e in b["entries"]}))[:160]
        flag = f" [undone by #{b['undone_by']}]" if b.get("undone_by") else ""
        out.append(f"#{b['id']} {b['ts'][5:16].replace('T', ' ')} {b['tool']}: {files}{flag}")
    return "\n".join(out) + "\n(use list_changes change_id=N for diffs, undo_change N to revert)"


@tool("write", "Undo change", destructive=True)
def undo_change(change_id: Annotated[int, Field(description="Change number from list_changes; 0 = the latest one")] = 0,
                force: Annotated[bool, Field(description="Restore even if the files were modified afterwards")] = False) -> str:
    """Revert one change made by the file tools (restores backups). Refuses if the files changed afterwards
    unless force=true. The undo itself is recorded, so it can be undone too."""
    b, nid, done, conflicts = HIST.undo(int(change_id) or None, bool(force))
    msg = [f"Reverted #{b['id']} ({b['tool']})" + (f" as change #{nid}" if nid else "") + ":"] + ["- " + d for d in done]
    if conflicts:
        msg.append("Forced despite: " + "; ".join(conflicts))
    return "\n".join(msg)


# ============================================================== commands
async def _approve(tool_name, command, display_cwd):
    reasons = procs.assess(command)
    if procs.needs_approval(reasons):
        ok, note = await approvals.request(tool_name, f"{command}\n(cwd: {display_cwd})",
                                           reasons or ["confirm_commands=always"], runtime.config.get("approval_timeout_sec", 50))
        if not ok:
            raise ToolError(f"Command was NOT executed: {note}. Risk flags: {', '.join(reasons) or 'n/a'}. "
                            "Explain to the user why it is needed, or choose a safer approach.")
        return reasons
    return []


def _cwd(cwd: str) -> paths.Resolved:
    r = paths.resolve(cwd or ".", must_exist=True)
    if not r.path.is_dir():
        raise NotADirectoryError(f"cwd {r.display} is not a folder.")
    return r


@tool("exec", "Run command (PowerShell)", destructive=True, open_world=True)
async def run_command(command: Annotated[str, Field(description="PowerShell command(s); multi-line scripts are fine")],
                      cwd: Annotated[str, Field(description="Working folder inside the workspace")] = ".",
                      timeout_sec: Annotated[int, Field(description="Kill the whole process tree after this many seconds (<=1800)")] = 120,
                      max_output_chars: int = 30000, ctx: Context = None) -> str:
    """Run a shell command (PowerShell 7 if installed, else Windows PowerShell 5.1; output is UTF-8) and wait for it.
    Not sandboxed: runs as the Windows user. Risky commands (deletes, registry, network, git push, paths outside the
    workspace...) wait for the user's approval in the dashboard. Long output keeps the beginning and the end.
    For servers/watchers/long builds use start_process. File changes made by commands are not covered by undo_change.
    Prefer the dedicated tools (read_file, search_code, git_*) when they fit."""
    r = _cwd(cwd)
    reasons = await _approve("run_command", command, r.display)
    timeout_sec = max(1, min(int(timeout_sec), 1800))
    limit = max(2000, min(int(max_output_chars), 200_000))
    t0 = time.time()
    res = None
    for encoded in (False, True):
        p, tree, res, threads, tmp = await asyncio.to_thread(procs.start_run, command, r.path, encoded)
        next_beat = 15
        try:
            while True:
                try:
                    await asyncio.to_thread(p.wait, 0.5)
                    break
                except subprocess.TimeoutExpired:
                    pass
                el = time.time() - t0
                if el > timeout_sec:
                    res.timed_out = True
                    await asyncio.to_thread(tree.kill)
                    try:
                        await asyncio.to_thread(p.wait, 5)
                    except subprocess.TimeoutExpired:
                        pass
                    break
                if ctx is not None and el > next_beat:
                    next_beat += 15
                    try:
                        await ctx.report_progress(el, timeout_sec, f"still running ({int(el)}s)")
                    except Exception:
                        pass
        except asyncio.CancelledError:
            tree.kill()
            raise
        res = await asyncio.to_thread(procs.finish_run, p, tree, res, threads, tmp, t0)
        if not encoded and res.shell in ("pwsh", "powershell") and procs.policy_blocked(res):
            continue  # Group Policy blocks .ps1 files -> retry via -EncodedCommand
        break
    out = procs.render_stream(res.out, limit)
    err = procs.render_stream(res.err, max(2000, limit // 3))
    head = f"exit code: {res.code if not res.timed_out else 'killed'} · {res.duration:.1f}s · {res.shell} · cwd: {r.display}"
    parts = [head]
    if res.timed_out:
        parts.append(f"TIMEOUT after {timeout_sec}s: the process tree was killed. Use start_process for long tasks.")
    if reasons:
        parts.append("approved by user (" + ", ".join(reasons) + ")")
    if res.note:
        parts.append("note: " + res.note)
    if out.strip():
        parts.append("--- stdout ---\n" + out.rstrip())
    if err.strip():
        parts.append("--- stderr ---\n" + err.rstrip())
    if not out.strip() and not err.strip():
        parts.append("(no output)")
    return "\n".join(parts)


@tool("exec", "Start background process", destructive=True, open_world=True)
async def start_process(command: str, cwd: str = ".", name: str = "",
                        wait_seconds: Annotated[float, Field(description="Wait this long and return the first output (<=30)")] = 2.0) -> str:
    """Start a long-running command in the background (dev server, watcher, long build, interactive REPL such as
    'python -u -i'). Returns a process id; then use read_process_output / send_process_input / stop_process.
    Background processes are killed when the bridge stops."""
    r = _cwd(cwd)
    await _approve("start_process", command, r.display)
    p = await asyncio.to_thread(procs.bg_start, command, r.path, r.display, name)
    await asyncio.to_thread(p.new_data.wait, max(0.0, min(float(wait_seconds), 30.0)))
    await asyncio.sleep(0.2)
    text, _ = p.read()
    info = p.info()
    return f"Started {p.id} ({info['status']}) · {p.shell} · cwd: {r.display}\n" + (text or "(no output yet)")


@tool("exec", "Read process output", ro=True)
async def read_process_output(process_id: str,
                              wait_seconds: Annotated[float, Field(description="If there is no new output, wait up to this long (<=60)")] = 0,
                              max_chars: int = 20000, from_start: bool = False) -> str:
    """New output of a background process since the last read (stderr lines are prefixed with [stderr])."""
    p = procs.bg_get(process_id)
    if wait_seconds and p.size == p.read_pos and p.running:
        await asyncio.to_thread(p.new_data.wait, max(0.0, min(float(wait_seconds), 60.0)))
        await asyncio.sleep(0.1)
    text, lost = p.read(from_start, max(1000, min(int(max_chars), 200_000)))
    info = p.info()
    head = f"{p.id} [{info['status']}, {info['seconds']}s]" + (f" ({lost} chars dropped: buffer limit)" if lost else "")
    return head + "\n" + (text if text else "(no new output)")


@tool("exec", "Send input to process", destructive=True)
async def send_process_input(process_id: str, text: str, press_enter: bool = True,
                             wait_seconds: Annotated[float, Field(description="Then wait for output (<=30)")] = 1.0) -> str:
    """Write text to the stdin of a background process (e.g. an interactive REPL) and return its new output."""
    p = procs.bg_get(process_id)
    await asyncio.to_thread(p.write, text + ("\n" if press_enter else ""))
    await asyncio.to_thread(p.new_data.wait, max(0.0, min(float(wait_seconds), 30.0)))
    await asyncio.sleep(0.15)
    out, _ = p.read()
    return f"{p.id} [{p.info()['status']}]\n" + (out or "(no output yet)")


@tool("exec", "List processes", ro=True, idempotent=True)
def list_processes() -> str:
    """Background processes started by start_process (running and recently finished)."""
    items = [p.info() for p in procs.registry.values()]
    if not items:
        return "No background processes."
    return "\n".join(f"{i['id']}  {i['status']:<14} {i['seconds']:>7}s  unread={i['unread_chars']:<6} {i['name']}  (cwd {i['cwd']})" for i in items)


@tool("exec", "Stop process", destructive=True, idempotent=True)
def stop_process(process_id: str) -> str:
    """Kill a background process and all of its children."""
    p = procs.bg_get(process_id)
    was = p.running
    p.stop()
    p.proc.wait(timeout=10)
    text, _ = p.read()
    return (f"Stopped {p.id}." if was else f"{p.id} had already exited ({p.proc.returncode}).") + (("\nLast output:\n" + text[-3000:]) if text else "")


# ============================================================== git
_REF_RE = re.compile(r"^[\w./~^@{}:+\-]+$")  # \w: unicode branch names (feature/тест) are fine


def _ref(ref: str) -> str:
    ref = (ref or "").strip()
    if ref and (ref.startswith("-") or not _REF_RE.match(ref)):
        raise ValueError(f"Invalid git revision {ref!r}.")
    return ref


def _git_ctx(path: str):
    r = paths.resolve(path or ".", must_exist=True)
    cwd = r.path if r.path.is_dir() else r.path.parent
    spec = "." if r.path.is_dir() else r.path.name
    gitops.repo_root(r)
    return r, cwd, spec


def _clip(text, limit=60000, hint="narrow with path= or use stat_only=true"):
    text = textio.for_display(text)
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated {len(text) - limit} chars; {hint}]"


@tool("read", "git status", ro=True, idempotent=True)
def git_status(path: str = ".") -> str:
    """Branch, ahead/behind and changed files (porcelain: XY path; X=staged, Y=unstaged, ??=untracked)."""
    r, cwd, spec = _git_ctx(path)
    _, out, _ = gitops.run(["status", "-b", "--porcelain=v1", "-unormal", "--", spec], cwd)
    lines = out.rstrip("\n").split("\n")
    body = lines[1:]
    if not body:
        return lines[0] + "\nWorking tree clean."
    shown = body[:300]
    return "\n".join([lines[0]] + shown + ([f"... {len(body) - 300} more"] if len(body) > 300 else []))


@tool("read", "git diff", ro=True, idempotent=True)
def git_diff(path: str = ".", staged: Annotated[bool, Field(description="Diff of staged changes (what will be committed)")] = False,
             ref: Annotated[str, Field(description="Compare with a revision, e.g. HEAD~1 or main")] = "",
             context: int = 3, stat_only: bool = False) -> str:
    """Show changes (unstaged by default). Secret files are excluded. Untracked files are not shown (see git_status)."""
    r, cwd, spec = _git_ctx(path)
    args = ["diff", "--no-ext-diff"] + (["--stat"] if stat_only else [f"-U{max(0, min(int(context), 20))}"])
    if staged:
        args.append("--cached")
    ref = _ref(ref)
    if ref:
        args += ["--end-of-options", ref]
    _, out, _ = gitops.run(args + ["--", spec] + gitops.exclude_pathspecs(), cwd)
    return _clip(out) if out.strip() else "No differences."


@tool("read", "git log", ro=True, idempotent=True)
def git_log(path: str = ".", max_count: int = 20, ref: str = "") -> str:
    """Commit history (hash, date, author, subject, refs). Optionally only commits touching a path."""
    r, cwd, spec = _git_ctx(path)
    args = ["log", f"--max-count={max(1, min(int(max_count), 500))}", "--date=short", "--format=%h %ad %an | %s%d"]
    ref = _ref(ref)
    if ref:
        args += ["--end-of-options", ref]
    _, out, _ = gitops.run(args + ["--", spec], cwd)
    return out.strip() or "No commits."


@tool("read", "git show", ro=True, idempotent=True)
def git_show(ref: str = "HEAD", path: Annotated[str, Field(description="If set: show this file's content at that revision")] = "",
             stat_only: bool = False,
             repo_path: Annotated[str, Field(description="Folder inside the repository (when the repo is a subfolder of the workspace)")] = ".") -> str:
    """Show a commit (message + diff) or, with path, a file as it was at that revision."""
    ref = _ref(ref) or "HEAD"
    if path:
        r = paths.resolve(path)
        cwd = r.path.parent
        while not cwd.exists():
            cwd = cwd.parent
        rel = os.path.relpath(str(r.path), str(cwd)).replace("\\", "/")
        _, out, _ = gitops.run(["show", f"{ref}:./{rel}"], cwd)
        return _clip(out, hint="use read_file-like paging: request a smaller file")
    r, cwd, spec = _git_ctx(repo_path or ".")
    args = ["show", "--format=fuller", "--stat" if stat_only else "-U3", "--end-of-options", ref, "--", "."] + gitops.exclude_pathspecs()
    _, out, _ = gitops.run(args, cwd)
    return _clip(out)


def _existing_dir(p: Path) -> Path:
    d = p if p.is_dir() else p.parent
    while not d.exists():
        d = d.parent
    return d


@tool("git_write", "git add", idempotent=True)
def git_add(paths: Annotated[List[str], Field(description="Files or folders to stage ('.' = everything changed in the workspace)")]) -> str:
    """Stage selected changes (new, modified and deleted files). Secret files (deny-list) are never staged, even with '.'."""
    if not paths:
        raise ValueError("paths is empty")
    staged, skipped = [], []
    for p in paths:
        r = pathsmod.resolve(p)
        top = gitops.top_for(_existing_dir(r.path))
        spec = os.path.relpath(str(r.path), str(top)).replace("\\", "/")
        if spec.startswith(".."):
            raise ValueError(f"{r.display} is outside the repository at {top}.")
        files = []
        for xy, f in gitops.changed_files(top, [spec]):
            absf = top / f
            if not pathsmod.is_within(absf, r.root):
                continue
            rel_ws = os.path.relpath(str(absf), str(r.root)).replace("\\", "/")
            if pathsmod.is_denied(rel_ws):
                skipped.append(rel_ws)
                continue
            files.append(f)
        for i in range(0, len(files), 100):
            gitops.run(["add", "-A", "--"] + files[i:i + 100], top)
        staged += files
    if not staged:
        msg = "Nothing to stage (no changes in these paths)."
    else:
        msg = f"Staged {len(staged)} file(s):\n" + "\n".join(staged[:100]) + (f"\n... {len(staged) - 100} more" if len(staged) > 100 else "")
    if skipped:
        msg += "\nNOT staged (protected secrets): " + ", ".join(skipped[:20])
    return msg


@tool("git_write", "git commit")
def git_commit(message: Annotated[str, Field(description="Commit message (multi-line allowed; quotes/$() are safe)")],
               paths: Annotated[Optional[List[str]], Field(description="Optional: stage these first (same as git_add)")] = None,
               repo_path: str = ".") -> str:
    """Commit the staged changes (git is called without a shell; the message goes through stdin). Only what is staged
    is committed - stage with git_add or pass paths. Does not push."""
    if not message.strip():
        raise ValueError("Commit message is empty.")
    pre = ""
    if paths:
        pre = git_add(paths) + "\n"
    r, cwd, _ = _git_ctx(repo_path)
    _, names, _ = gitops.run(["diff", "--cached", "--name-only"], cwd)
    if not names.strip():
        raise ValueError("Nothing is staged. Use git_add (or pass paths) first.")
    gitops.run(["commit", "-F", "-", "--cleanup=strip"], cwd, stdin=message.replace("\r\n", "\n").encode("utf-8"), timeout=180)
    _, out, _ = gitops.run(["show", "--stat", "--format=%h %s", "HEAD"], cwd)
    return pre + "Committed: " + out.strip()


@tool("git_write", "git restore (discard changes)", destructive=True)
def git_restore(paths: Annotated[List[str], Field(description="Files/folders to restore")],
                staged: Annotated[bool, Field(description="true = only unstage (keeps your edits); false = DISCARD working-tree changes")] = False) -> str:
    """Unstage files (staged=true) or discard their uncommitted changes (staged=false). Discarded content is backed up
    first, so undo_change can bring it back."""
    if not paths:
        raise ValueError("paths is empty")
    out = []
    for p in paths:
        r = pathsmod.resolve(p, must_exist=False)
        top = gitops.top_for(_existing_dir(r.path))
        spec = os.path.relpath(str(r.path), str(top)).replace("\\", "/")
        if staged:
            gitops.run(["restore", "--staged", "--", spec], top)
            out.append(f"unstaged {r.display}")
            continue
        cwd = top
        _, names, _ = gitops.run(["diff", "--name-only", "-z", "--", spec], top)
        files = [top / n for n in names.split("\0") if n]
        files = [f for f in files if pathsmod.is_within(f, r.root) and not pathsmod.is_denied(os.path.relpath(str(f), str(r.root)).replace("\\", "/"))]
        if not files:
            out.append(f"no uncommitted changes in {r.display}")
            continue
        b = HIST.begin("git_restore", f"discard changes in {r.display}")
        befores = {}
        for f in files:
            befores[f] = f.read_bytes() if f.is_file() else None
        gitops.run(["restore", "--"] + [os.path.relpath(str(f), str(top)).replace("\\", "/") for f in files], top)
        for f in files:
            after = f.read_bytes() if f.is_file() else None
            b.record(f, pathsmod.display_for(f), befores[f], after)
        cid = b.commit()
        out.append(f"discarded changes in {len(files)} file(s) under {r.display}" + _change_note(cid))
    return "\n".join(out)


@tool("git_write", "git branch")
def git_branch(action: Annotated[str, Field(description="'list', 'create' (create and switch) or 'switch'")] = "list",
               name: str = "", repo_path: str = ".") -> str:
    """List, create or switch branches. Switching refuses if it would overwrite uncommitted changes."""
    r, cwd, _ = _git_ctx(repo_path)
    if action == "list":
        _, out, _ = gitops.run(["branch", "-vv", "--no-color"], cwd)
        return out.strip() or "No branches yet."
    if not name or name.startswith("-"):
        raise ValueError("Branch name is required.")
    gitops.run(["check-ref-format", "--branch", name], cwd)
    if action == "create":
        gitops.run(["switch", "-c", name], cwd)
        return f"Created and switched to {name}."
    if action == "switch":
        gitops.run(["switch", name], cwd)
        return f"Switched to {name}."
    raise ValueError("action must be list, create or switch")


# ============================================================== code intelligence
def _symbol_files(r: paths.Resolved, word: str):
    if RG and r.path.is_dir():
        args = _rg_base() + ["-l", "-w", "-F", "-g", "*.py", "-g", "*.pyw"] + sum((["-g", f"!{i}"] for i in SEARCH_IGNORES), [])
        code, out, _ = _run_rg(args + ["-e", word, "--", r.rel or "."], r.root)
        return [l[2:] if l.startswith("./") else l for l in out.split("\n") if l]
    if r.path.is_file():
        return [r.rel]
    return [f for f in _walk_files(r.root, r.path, False) if f.endswith((".py", ".pyw"))]


@tool("read", "File outline", ro=True, idempotent=True)
def get_outline(path: str) -> str:
    """Structure of a file with line ranges: Python classes/functions/methods (signatures + first docstring line),
    LaTeX \\chapter/\\section/labels/\\input, Markdown headings. Cheap way to navigate before reading."""
    r = paths.resolve(path, must_exist=True)
    doc = _load_doc(r)
    ext = r.path.suffix.lower()
    if ext in (".py", ".pyw"):
        body = symbols.python_outline(doc.text)
    elif ext in (".tex", ".ltx", ".sty", ".cls"):
        body = symbols.tex_outline(doc.text)
    elif ext in (".md", ".markdown", ".rst"):
        body = symbols.md_outline(doc.text)
    else:
        raise ValueError("Outline supports .py, .tex and .md files. Use search_code for other types.")
    return f"{r.display} ({doc.text.count(chr(10))} lines)\n{body}"


@tool("read", "Find Python symbol", ro=True, idempotent=True)
def find_symbol(name: Annotated[str, Field(description="Function/class/method name, or dotted 'Class.method'")],
                path: str = ".", include_body: bool = False, max_results: int = 20) -> str:
    """Find where a Python function/class/method is defined (parsed with ast, not text search).
    For usages/references use search_code with the name."""
    r = paths.resolve(path, must_exist=True)
    word = name.split(".")[-1]
    hits = []
    for f in _symbol_files(r, word)[:2000]:
        p = r.root / f
        try:
            doc = textio.read_doc(p)
            found = symbols.find_in_text(doc.text, name)
        except (SyntaxError, textio.TextDecodeError, OSError, ValueError):
            continue
        for s in found:
            line = f"{f}:{s['start']}-{s['end']}  {s['kind']} {s['name']}  —  {s['sig']}"
            if include_body:
                body = "\n".join(doc.text.split("\n")[s["start"] - 1:s["end"]][:200])
                line += "\n" + body + "\n"
            hits.append(line)
            if len(hits) >= max_results:
                break
        if len(hits) >= max_results:
            break
    return textio.for_display("\n".join(hits)) if hits else f"No definition of {name!r} found under {r.display}."


@tool("write", "Replace Python symbol", destructive=True)
def replace_symbol(path: str, symbol: Annotated[str, Field(description="Dotted name, e.g. 'MyClass.method' or 'func'")],
                   new_code: Annotated[str, Field(description="Full new definition including the def/class line and decorators; indentation is adjusted automatically")],
                   dry_run: bool = False) -> str:
    """Replace a whole Python function/method/class definition by name (decorators included). The result must parse,
    otherwise nothing is written."""
    r = paths.resolve(path, write=True, must_exist=True)
    with file_lock(r.path):
        doc = _load_doc(r)
        new_text, m = symbols.replace_symbol_text(doc.text, symbol, new_code)
        diff = E.unified_diff(doc.text, new_text, r.rel)
        if dry_run:
            return "DRY RUN\n" + diff
        cid, _ = _write(r, doc, new_text, "replace_symbol", f"{m['name']} in {r.display}")
    return f"Replaced {m['kind']} {m['name']} (was L{m['start']}-{m['end']}){_change_note(cid)}\n{diff}"


# ============================================================== LaTeX
@tool("exec", "Build LaTeX", open_world=False)
async def latex_build(main_file: Annotated[str, Field(description="Main .tex file")],
                      engine: Annotated[str, Field(description="'auto' (latexmk/pdflatex/xelatex; Tectonic if no TeX distribution), 'pdflatex', 'xelatex', 'lualatex', 'tectonic'")] = "auto",
                      timeout_sec: int = 300) -> str:
    """Compile a LaTeX document (latexmk if it works, else engine+bibtex/biber passes, or Tectonic; shell-escape
    disabled) and return a short report: errors with file:line, undefined references/citations, overfull boxes, page count."""
    r = paths.resolve(main_file, must_exist=True)
    if r.path.suffix.lower() != ".tex":
        raise ValueError("main_file must be a .tex file")
    res = await asyncio.to_thread(latex.build, r.path, engine, max(30, min(int(timeout_sec), 1800)))
    if "error" in res and not res.get("errors"):
        raise RuntimeError(res["error"])
    out = [f"{'OK' if res['ok'] else 'FAILED'} · engine {res['engine']} · pdf: {res['pdf'] or 'not produced'}"
           + (f" ({res['pages']} pages)" if res.get("pages") else ""),
           "steps: " + ", ".join(f"{s}{'' if c in (0, None) else f'(exit {c})'}" for s, c in res["steps"])]
    if res["errors"]:
        out.append(f"errors ({len(res['errors'])}):")
        for e in res["errors"]:
            loc = f"{e.get('file', '')}:{e['line']}" if e.get("line") else (e.get("file") or "?")
            out.append(f"  {loc}: {e['msg']}" + (("  | " + " / ".join(e['context'])) if e.get("context") else ""))
    if res["counts"]:
        out.append("warnings: " + ", ".join(f"{k}: {v}" for k, v in sorted(res["counts"].items())))
    out += ["  " + w for w in res["warnings"][:10]]
    return textio.for_display("\n".join(out))


# ============================================================== screen
@tool("screen", "Screenshot", ro=True)
def take_screenshot(monitor: Annotated[int, Field(description="1 = primary monitor, 0 = all monitors")] = 1,
                    max_width: int = 1600) -> Image:
    """Capture the screen and return it as an image (downscaled; nothing is saved to disk). Agent mode only."""
    try:
        import mss
        import mss.tools
    except ImportError:
        raise RuntimeError("Screenshots need the 'mss' package: pip install mss")
    with mss.mss() as sct:
        mons = sct.monitors
        idx = monitor if 0 <= monitor < len(mons) else 1
        shot = sct.grab(mons[idx])
        try:
            from PIL import Image as PILImage
            import io
            img = PILImage.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
            w = max(320, min(int(max_width), 3840))
            if img.width > w:
                img = img.resize((w, int(img.height * w / img.width)), PILImage.LANCZOS)
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=80, optimize=True)
            return Image(data=buf.getvalue(), format="jpeg")
        except ImportError:
            return Image(data=mss.tools.to_png(shot.rgb, shot.size), format="png")
