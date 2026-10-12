"""Git without a shell: argv lists only, message via stdin, secrets excluded from diffs and staging."""
import os
import shutil
import subprocess
from pathlib import Path

from nb import paths, procs

IS_WIN = os.name == "nt"
_git = None


class GitError(Exception):
    pass


def git_exe():
    global _git
    if _git is None:
        exe = shutil.which("git")
        if not exe and IS_WIN:
            for c in (r"C:\Program Files\Git\cmd\git.exe", r"C:\Program Files (x86)\Git\cmd\git.exe"):
                if os.path.exists(c):
                    exe = c
                    break
        _git = exe or ""
    return _git


BASE = ["-c", "core.quotepath=false", "-c", "color.ui=never", "-c", "i18n.logOutputEncoding=utf-8",
        "-c", "i18n.commitEncoding=utf-8", "-c", "core.pager=cat", "--no-pager"]


def run(args, cwd: Path, stdin: bytes = None, timeout=90, check=True):
    exe = git_exe()
    if not exe:
        raise GitError("git is not installed or not in PATH (https://git-scm.com/download/win).")
    kw = {"creationflags": procs.CREATE_NO_WINDOW} if IS_WIN else {}
    env = procs.child_env({"GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C.UTF-8" if not IS_WIN else os.environ.get("LC_ALL", "")})
    try:
        p = subprocess.run([exe] + BASE + list(args), cwd=str(cwd), input=stdin, capture_output=True,
                           timeout=timeout, env=env, stdin=None if stdin is not None else subprocess.DEVNULL, **kw)
    except subprocess.TimeoutExpired:
        raise GitError(f"git {' '.join(args[:2])} timed out after {timeout}s")
    out = procs.smart_decode(p.stdout).replace("\r\n", "\n")
    err = procs.smart_decode(p.stderr).replace("\r\n", "\n")
    if check and p.returncode != 0:
        msg = (err or out).strip()
        if "dubious ownership" in msg:
            msg += "\nHint: run in a terminal: git config --global --add safe.directory <repo path>"
        raise GitError(f"git {args[0]} failed (exit {p.returncode}):\n{msg[:4000]}")
    return p.returncode, out, err


def top_for(cwd: Path) -> Path:
    code, out, _ = run(["rev-parse", "--show-toplevel"], cwd, check=False)
    if code != 0:
        raise GitError(f"{paths.display_for(cwd)} is not inside a git repository. (Initialize with run_command: git init)")
    return Path(os.path.realpath(out.strip()))


def repo_root(r: paths.Resolved) -> Path:
    cwd = r.path if r.path.is_dir() else r.path.parent
    code, out, _ = run(["rev-parse", "--show-toplevel"], cwd, check=False)
    if code != 0:
        raise GitError(f"{r.display} is not inside a git repository. (Initialize with run_command: git init)")
    return Path(out.strip())


def exclude_pathspecs():
    specs = []
    for pat in paths.deny_patterns():
        pat = pat.strip().replace("\\", "/").strip("/")
        if not pat:
            continue
        if "/" in pat:
            specs += [f":(exclude,glob,icase){pat}", f":(exclude,glob,icase){pat}/**", f":(exclude,glob,icase)**/{pat}"]
        else:
            specs += [f":(exclude,glob,icase)**/{pat}", f":(exclude,glob,icase)**/{pat}/**"]
    return specs


def rel_to(path: Path, cwd: Path) -> str:
    rp = os.path.relpath(str(path), str(cwd)).replace("\\", "/")
    return rp


def changed_files(cwd: Path, pathspec):
    """Paths (relative to cwd) with changes or untracked, honoring .gitignore."""
    _, out, _ = run(["status", "--porcelain=v1", "-z", "-uall", "--"] + pathspec, cwd)
    items, parts, i = [], out.split("\0"), 0
    while i < len(parts):
        e = parts[i]
        if len(e) < 4:
            i += 1
            continue
        xy, p = e[:2], e[3:]
        items.append((xy, p))
        if xy[0] in "RC":  # rename: next field is the source
            i += 1
        i += 1
    return items
