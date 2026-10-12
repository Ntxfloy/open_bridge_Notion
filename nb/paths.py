"""Workspace confinement and secret deny-list.

Every path coming from the model goes through resolve(). It
- supports several workspaces: "src/a.py" (default workspace) or "@alias/src/a.py";
- rejects UNC/device paths, drive-relative paths, NTFS alternate data streams,
  reserved device names (CON, NUL, COM1...) and names with trailing dots/spaces
  (Windows silently strips those, which would bypass the deny-list: ".env." == ".env");
- resolves symlinks/junctions and then checks containment case-insensitively;
- applies the deny-list (secrets) and the write-deny list (.git internals, the bridge itself).
"""
import os
import re
from dataclasses import dataclass
from pathlib import Path

import config_manager
from nb import runtime

IS_WIN = os.name == "nt"
_RESERVED = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}
_DRIVE_ABS = re.compile(r"^[A-Za-z]:[\\/]")
_DRIVE_REL = re.compile(r"^[A-Za-z]:(?![\\/])")
WRITE_DENY = [".git/**", ".git"]  # git internals are changed only through git tools
DEFAULT_IGNORED_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache", ".pytest_cache",
                        ".ruff_cache", ".tox", ".idea", ".vs", ".gradle", ".next", ".nuxt", ".cache"}


class PathError(Exception):
    """User-facing path problem (outside workspace, protected, invalid)."""


@dataclass
class Resolved:
    path: Path        # absolute, symlinks resolved
    alias: str        # workspace alias
    root: Path        # workspace root (resolved)
    rel: str          # posix path relative to root ("" for the root itself)

    @property
    def display(self) -> str:
        r = self.rel or "."
        if self.alias != runtime.config.get("default_workspace"):
            return f"@{self.alias}/{self.rel}" if self.rel else f"@{self.alias}"
        return r


def _norm(p) -> str:
    return os.path.normcase(os.path.normpath(str(p)))


def is_within(child, root) -> bool:
    c, r = _norm(child), _norm(root)
    try:
        return os.path.commonpath([c, r]) == r
    except ValueError:  # different drives
        return False


def workspaces() -> dict:
    """alias -> resolved root Path (only existing folders)."""
    out = {}
    for alias, p in (runtime.config.get("workspaces") or {}).items():
        try:
            out[alias] = Path(os.path.realpath(os.path.expanduser(p)))
        except (OSError, ValueError):
            continue
    return out


def default_alias() -> str:
    return runtime.config.get("default_workspace") or next(iter(runtime.config.get("workspaces") or {"main": ""}))


def check_workspace_root(p: str) -> Path:
    """Validate a folder before it becomes a workspace (used by the dashboard)."""
    root = Path(os.path.realpath(os.path.expanduser(p)))
    if not root.is_dir():
        raise PathError(f"Folder does not exist: {root}")
    if root.parent == root:
        raise PathError("A drive root cannot be a workspace. Choose a project folder.")
    if _norm(root) == _norm(Path.home()):
        raise PathError("Your whole home folder cannot be a workspace (it contains .ssh, AppData, browser data). Choose a project folder.")
    sysroots = [os.environ.get("SystemRoot", r"C:\Windows"), os.environ.get("ProgramFiles", r"C:\Program Files"),
                os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), os.environ.get("ProgramData", r"C:\ProgramData")]
    if not IS_WIN:
        sysroots = ["/etc", "/usr", "/bin", "/sbin", "/var", "/boot", "/proc", "/sys"]
    for s in sysroots:
        if s and is_within(root, s):
            raise PathError(f"System folders cannot be workspaces: {root}")
    if is_within(config_manager.BASE_DIR, root) and _norm(config_manager.BASE_DIR) == _norm(root):
        raise PathError("The bridge folder itself cannot be a workspace.")
    return root


# ---------------------------------------------------------------- deny-list
_glob_cache = {}


def _glob_to_re(pat: str):
    key = pat
    if key in _glob_cache:
        return _glob_cache[key]
    i, out = 0, []
    while i < len(pat):
        c = pat[i]
        if c == "*":
            if pat[i:i + 3] == "**/":
                out.append(r"(?:.*/)?")
                i += 3
                continue
            if pat[i:i + 2] == "**":
                out.append(r".*")
                i += 2
                continue
            out.append(r"[^/]*")
        elif c == "?":
            out.append(r"[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    rx = re.compile("^" + "".join(out) + "$", re.IGNORECASE)
    _glob_cache[key] = rx
    return rx


def _match_any(rel: str, patterns) -> bool:
    if not rel:
        return False
    parts = rel.split("/")
    for pat in patterns:
        pat = pat.strip().replace("\\", "/").strip("/")
        if not pat:
            continue
        rx = _glob_to_re(pat)
        if "/" in pat:
            # match the path itself or any parent directory (dir pattern protects its contents)
            for k in range(1, len(parts) + 1):
                if rx.match("/".join(parts[:k])):
                    return True
        else:
            if any(rx.match(p) for p in parts):
                return True
    return False


def deny_patterns():
    c = runtime.config
    return list(c.get("deny_globs") or []) + list(c.get("extra_deny_globs") or [])


def is_denied(rel: str) -> bool:
    if not rel:
        return False
    if _match_any(rel, deny_patterns()):
        name = rel.rsplit("/", 1)[-1]
        allow = runtime.config.get("deny_allow") or []
        if any(_glob_to_re(a).match(name) for a in allow) and not _match_any(rel.rsplit("/", 1)[0] if "/" in rel else "", deny_patterns()):
            return False
        return True
    return False


def is_write_denied(rel: str) -> bool:
    return _match_any(rel, WRITE_DENY)


def _bridge_dirs():
    # the code folder, the state folder (backups, logs) and the config file itself (it holds the token)
    cf = config_manager.CONFIG_FILE
    return [config_manager.BASE_DIR, config_manager.STATE_DIR, cf, cf.with_suffix(".json.corrupt")]


# ---------------------------------------------------------------- resolve
def _check_component(comp: str, original: str):
    if comp in (".", ".."):
        return
    if comp != comp.rstrip(" ."):
        raise PathError(f"Invalid path '{original}': names ending with a dot or space are not allowed on Windows.")
    if ":" in comp:
        raise PathError(f"Invalid path '{original}': ':' is not allowed in names (NTFS alternate data streams).")
    if any(ch in comp for ch in '<>"|?*') or any(ord(ch) < 32 for ch in comp):
        raise PathError(f"Invalid path '{original}': contains characters not allowed in Windows file names.")
    stem = comp.split(".", 1)[0].upper()
    if stem in _RESERVED:
        raise PathError(f"Invalid path '{original}': {comp!r} is a reserved Windows device name.")


def resolve(path_str: str, *, write: bool = False, must_exist: bool = False, allow_root: bool = True) -> Resolved:
    original = path_str
    s = (path_str or "").strip()
    if s in ("", "./", ".\\"):
        s = "."
    if "\x00" in s:
        raise PathError("Invalid path: NUL character.")
    if s.startswith(("\\\\", "//")):
        raise PathError(f"Network/device paths are not allowed: '{original}'")
    if s.startswith("~"):
        raise PathError(f"'~' paths are not allowed; use a path inside the workspace: '{original}'")
    if _DRIVE_REL.match(s):
        raise PathError(f"Drive-relative paths like 'C:folder' are not allowed: '{original}'")

    wss = workspaces()
    if not wss:
        raise PathError("No workspace configured. Choose a folder in the bridge dashboard.")

    alias = None
    if s.startswith("@"):
        head, _, rest = s[1:].replace("\\", "/").partition("/")
        if head not in wss:
            raise PathError(f"Unknown workspace '@{head}'. Available: " + ", ".join("@" + a for a in wss))
        alias, s = head, (rest or ".")

    is_abs = bool(_DRIVE_ABS.match(s)) or s.startswith("/") or (IS_WIN and s.startswith("\\"))
    if is_abs:
        if IS_WIN and (s.startswith("/") or s.startswith("\\")) and not _DRIVE_ABS.match(s):
            raise PathError(f"Absolute paths must include a drive letter: '{original}'")
        candidate = Path(s)
        comps = re.split(r"[\\/]+", s[2:] if _DRIVE_ABS.match(s) else s)
        for c in comps:
            if c:
                _check_component(c, original)
        found = None
        for a, root in sorted(wss.items(), key=lambda kv: -len(str(kv[1]))):
            if alias and a != alias:
                continue
            if is_within(os.path.normpath(str(candidate)), root):
                found = (a, root)
                break
        if not found:
            raise PathError(f"Access denied: '{original}' is outside the workspaces (" + ", ".join(f"@{a}={r}" for a, r in wss.items()) + ")")
        alias, root = found
    else:
        alias = alias or default_alias()
        if alias not in wss:
            raise PathError(f"Default workspace '@{alias}' is missing. Fix it in the dashboard.")
        root = wss[alias]
        comps = [c for c in re.split(r"[\\/]+", s) if c]
        for c in comps:
            _check_component(c, original)
        candidate = root.joinpath(*comps) if comps else root

    if not root.is_dir():
        raise PathError(f"Workspace folder does not exist: {root}")

    resolved = Path(os.path.realpath(str(candidate)))
    if not is_within(resolved, root):
        raise PathError(f"Access denied: '{original}' resolves outside workspace @{alias} ({root}).")
    rel = os.path.relpath(str(resolved), str(root)).replace("\\", "/")
    rel = "" if rel == "." else rel
    if not rel and not allow_root:
        raise PathError("This operation is not allowed on the workspace root itself.")

    for b in _bridge_dirs():
        if is_within(resolved, b) or (write and is_within(b, resolved)):
            raise PathError("Access denied: the bridge's own folder (config, token, backups) is protected.")
    if is_denied(rel):
        raise PathError(f"Access denied: '{rel}' is protected by the secrets deny-list (deny_globs in config.json).")
    if write and is_write_denied(rel):
        raise PathError(f"Writing to '{rel}' is not allowed (git internals). Use the git tools.")
    if must_exist and not resolved.exists():
        raise FileNotFoundError(f"Not found: '{original}'")
    return Resolved(resolved, alias, root, rel)


def display_for(abs_path: Path) -> str:
    """Best-effort display path for an absolute path inside some workspace."""
    for a, root in workspaces().items():
        if is_within(abs_path, root):
            rel = os.path.relpath(str(abs_path), str(root)).replace("\\", "/")
            rel = "" if rel == "." else rel
            return Resolved(Path(abs_path), a, root, rel).display
    return str(abs_path)
