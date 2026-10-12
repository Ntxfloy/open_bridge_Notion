"""Command execution: shells, process-tree kill, bounded output, background processes, risk heuristics.

Windows specifics handled here:
- PowerShell gets a temp .ps1 written as UTF-8 *with BOM* (PS 5.1 reads BOM-less scripts as ANSI and
  breaks Cyrillic) and runs with -File, so quoting is never an issue. Fallback: -EncodedCommand.
- CLIXML noise on stderr (#< CLIXML) is decoded to plain text.
- Each command runs in a Job Object: on timeout/cancel the whole tree dies (npm -> node -> ...).
- Children inherit PYTHONUTF8/PYTHONIOENCODING so Python prints UTF-8; console code page is UTF-8.
- stdin is closed (no hanging prompts); GIT_TERMINAL_PROMPT=0; pagers disabled.
"""
import base64
import codecs
import itertools
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from collections import deque
from pathlib import Path

from nb import runtime

IS_WIN = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200

# ---------------------------------------------------------------- Windows Job Objects (ctypes, no pywin32)
if IS_WIN:
    import ctypes
    from ctypes import wintypes as wt

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                                                       "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class _BASIC_LIMIT(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", wt.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wt.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wt.DWORD), ("SchedulingClass", wt.DWORD)]

    class _EXT_LIMIT(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", _BASIC_LIMIT), ("IoInfo", _IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

    _k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wt.LPCWSTR]
    _k32.CreateJobObjectW.restype = wt.HANDLE
    _k32.SetInformationJobObject.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD]
    _k32.SetInformationJobObject.restype = wt.BOOL
    _k32.AssignProcessToJobObject.argtypes = [wt.HANDLE, wt.HANDLE]
    _k32.AssignProcessToJobObject.restype = wt.BOOL
    _k32.TerminateJobObject.argtypes = [wt.HANDLE, wt.UINT]
    _k32.TerminateJobObject.restype = wt.BOOL
    _k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    _k32.OpenProcess.restype = wt.HANDLE
    _k32.CloseHandle.argtypes = [wt.HANDLE]
    _k32.CloseHandle.restype = wt.BOOL
    _JOB_EXT_INFO = 9
    _KILL_ON_CLOSE = 0x2000


class ProcessTree:
    """Kill a process together with all its descendants."""

    def __init__(self, proc: subprocess.Popen, kill_on_close: bool = False):
        self.proc = proc
        self.job = None
        self.pgid = None
        if not IS_WIN:
            try:
                self.pgid = os.getpgid(proc.pid)  # remember now: after the leader is reaped getpgid() fails
            except OSError:
                pass
        if IS_WIN:
            try:
                job = _k32.CreateJobObjectW(None, None)
                if job:
                    if kill_on_close:
                        info = _EXT_LIMIT()
                        info.BasicLimitInformation.LimitFlags = _KILL_ON_CLOSE
                        _k32.SetInformationJobObject(job, _JOB_EXT_INFO, ctypes.byref(info), ctypes.sizeof(info))
                    hp = _k32.OpenProcess(0x0100 | 0x0001, False, proc.pid)  # SET_QUOTA | TERMINATE
                    ok = bool(hp) and _k32.AssignProcessToJobObject(job, hp)
                    if hp:
                        _k32.CloseHandle(hp)
                    if ok:
                        self.job = job
                    else:
                        _k32.CloseHandle(job)
            except Exception:
                self.job = None

    def kill(self):
        p = self.proc
        if IS_WIN:
            if self.job:
                try:
                    _k32.TerminateJobObject(self.job, 1)
                except Exception:
                    pass
            if p.poll() is None:
                tk = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "taskkill.exe")
                try:
                    subprocess.run([tk, "/PID", str(p.pid), "/T", "/F"], capture_output=True, timeout=10,
                                   creationflags=CREATE_NO_WINDOW)
                except Exception:
                    pass
        else:
            try:
                if self.pgid and self.pgid != os.getpgid(0):
                    os.killpg(self.pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        try:
            p.kill()
        except Exception:
            pass

    def close(self):
        if IS_WIN and self.job:
            try:
                _k32.CloseHandle(self.job)
            except Exception:
                pass
            self.job = None


# ---------------------------------------------------------------- shells
_shell_cache = {}


def detect_shell():
    pref = runtime.config.get("shell", "auto")
    if pref in _shell_cache:
        return _shell_cache[pref]
    found = None
    if IS_WIN:
        order = {"auto": ["pwsh", "powershell"], "pwsh": ["pwsh", "powershell"], "powershell": ["powershell"],
                 "cmd": ["cmd"], "bash": ["bash", "powershell"], "sh": ["sh", "powershell"]}[pref]
    else:
        order = {"auto": ["bash", "sh"], "pwsh": ["pwsh", "bash"], "powershell": ["pwsh", "bash"],
                 "cmd": ["bash"], "bash": ["bash", "sh"], "sh": ["sh"]}[pref]
    for name in order:
        exe = shutil.which(name + (".exe" if IS_WIN else ""))
        if not exe and IS_WIN and name == "powershell":
            cand = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), r"System32\WindowsPowerShell\v1.0\powershell.exe")
            exe = cand if os.path.exists(cand) else None
        if exe:
            found = (name, exe)
            break
    _shell_cache[pref] = found or (("powershell", "powershell.exe") if IS_WIN else ("sh", "/bin/sh"))
    return _shell_cache[pref]


PS_PRELUDE = (
    "$ProgressPreference='SilentlyContinue'\n"
    "$ErrorActionPreference='Continue'\n"
    "try { [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false) } catch {}\n"
    "$OutputEncoding=[System.Text.UTF8Encoding]::new($false)\n"
    "$global:LASTEXITCODE=$null\n"
)
PS_EPILOGUE = (
    "\n$__nb_ok=$?\n"
    "if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }\n"
    "if (-not $__nb_ok) { exit 1 }\n"
    "exit 0\n"
)


def build_argv(command: str, encoded: bool = False):
    """Return (argv, tempfile_or_None, shell_name)."""
    name, exe = detect_shell()
    if name in ("pwsh", "powershell"):
        script = PS_PRELUDE + command + PS_EPILOGUE
        base = [exe, "-NoLogo", "-NoProfile", "-NonInteractive"]
        if encoded:
            b64 = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
            return base + ["-OutputFormat", "Text", "-EncodedCommand", b64], None, name
        fd, tmp = tempfile.mkstemp(prefix="nb_cmd_", suffix=".ps1")
        with os.fdopen(fd, "wb") as f:
            f.write(codecs.BOM_UTF8 + script.encode("utf-8"))
        return base + ["-ExecutionPolicy", "Bypass", "-File", tmp], tmp, name
    if name == "cmd":
        return f'"{exe}" /d /s /c "chcp 65001 >nul & {command}"', None, name
    return [exe, "-c", command], None, name


_SECRET_ENV = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH)", re.I)
_KEEP_ENV = {"GIT_ASKPASS", "SSH_AUTH_SOCK"}


def child_env(extra=None):
    env = dict(os.environ)
    if runtime.config.get("scrub_env", True):
        for k in list(env):
            if _SECRET_ENV.search(k) and k.upper() not in _KEEP_ENV:
                env.pop(k, None)
    env.update({
        "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1",
        "GIT_TERMINAL_PROMPT": "0", "GIT_PAGER": "cat", "PAGER": "cat", "LESS": "-FRX",
        "NO_COLOR": "1", "FORCE_COLOR": "0", "TERM": "dumb", "NB_BRIDGE": "1",
        "POWERSHELL_TELEMETRY_OPTOUT": "1", "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
    })
    bundled = os.environ.get("NB_BIN_DIR") or os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "resources", "bin")
    if os.path.isdir(bundled):
        env["PATH"] = env.get("PATH", "") + os.pathsep + bundled
    if extra:
        env.update(extra)
    return env


def spawn(argv, cwd, stdin_pipe=False, kill_on_close=False):
    kw = {}
    if IS_WIN:
        kw["creationflags"] = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
    else:
        kw["start_new_session"] = True
    p = subprocess.Popen(argv, cwd=str(cwd), env=child_env(),
                         stdin=subprocess.PIPE if stdin_pipe else subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=isinstance(argv, str) and not IS_WIN,
                         **kw)
    return p, ProcessTree(p, kill_on_close=kill_on_close)


# ---------------------------------------------------------------- output
class StreamBuffer:
    """Keeps the first `head` bytes and a rolling `tail`; counts everything."""

    def __init__(self, head=16_000, tail=96_000):
        self.head_lim, self.tail_lim = head, tail
        self.head = bytearray()
        self.tail = deque()
        self.tail_len = 0
        self.total = 0
        self.lock = threading.Lock()

    def feed(self, chunk: bytes):
        with self.lock:
            self.total += len(chunk)
            if len(self.head) < self.head_lim:
                take = self.head_lim - len(self.head)
                self.head += chunk[:take]
                chunk = chunk[take:]
            if chunk:
                self.tail.append(chunk)
                self.tail_len += len(chunk)
                while self.tail_len > self.tail_lim and self.tail:
                    drop = self.tail.popleft()
                    self.tail_len -= len(drop)

    def parts(self):
        with self.lock:
            tail = b"".join(self.tail)
            omitted = self.total - len(self.head) - len(tail)
            return bytes(self.head), tail, omitted


def smart_decode(data: bytes) -> str:
    if not data:
        return ""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    loose = data.decode("utf-8", errors="replace")
    if loose.count("\ufffd") <= max(3, len(data) // 200):
        return loose
    for enc in (("oem", "cp866", "cp1251") if IS_WIN else ("cp1251",)):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return loose


_CLIXML_S = re.compile(r'<S S="(?:Error|Warning|Verbose|Debug|Information)">(.*?)</S>', re.S)


def clean_clixml(text: str) -> str:
    if "#< CLIXML" not in text:
        return text
    out = []
    for chunk in text.split("#< CLIXML"):
        if "<Objs" not in chunk:
            if chunk.strip():
                out.append(chunk.strip())
            continue
        for m in _CLIXML_S.finditer(chunk):
            s = m.group(1)
            s = re.sub(r"_x([0-9A-Fa-f]{4})_", lambda mm: chr(int(mm.group(1), 16)), s)
            s = s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&apos;", "'").replace("&amp;", "&")
            out.append(s)
    return "".join(out).replace("\r\n", "\n").strip()


def clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    head = limit // 4
    tail = limit - head
    return text[:head] + f"\n\n[... {len(text) - limit} characters omitted ...]\n\n" + text[-tail:]


def render_stream(buf: StreamBuffer, limit: int) -> str:
    head, tail, omitted = buf.parts()
    if omitted > 0:
        txt = smart_decode(head) + f"\n\n[... {omitted} bytes omitted ...]\n\n" + smart_decode(tail)
    else:
        txt = smart_decode(head + tail)
    return clip(clean_clixml(txt.replace("\r\n", "\n")), limit)


def _pump(stream, buf, on_data=None):
    try:
        while True:
            chunk = stream.read1(65536) if hasattr(stream, "read1") else stream.read(4096)
            if not chunk:
                break
            buf.feed(chunk)
            if on_data:
                on_data(chunk)
    except (OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except Exception:
            pass


# ---------------------------------------------------------------- risk heuristics
_DANGER = [
    (r"\b(remove-item|rm|rmdir|rd|del|erase|ri)\b[^\n|;]*\s-(r|recurse|force|rf|fr)\b", "recursive/forced delete"),
    (r"\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r", "rm -rf"),
    (r"\b(rd|rmdir)\b[^\n]*\s/s\b", "rd /s"),
    (r"\bdel\b[^\n]*\s/[sqf]\b", "del /s /q"),
    # "format" alone = format.com; Format-Table/-List/-Wide/-Hex are harmless output cmdlets
    (r"(?<![\w-])(format(?![\w-])|format-volume|clear-disk|initialize-disk|diskpart|mkfs|bcdedit|vssadmin|wbadmin|cipher\s+/w)\b", "disk/boot operation"),
    (r"\b(reg(\.exe)?\s+(add|delete|import|load)|set-itemproperty\s+[^\n]*hk(lm|cu)|new-itemproperty|remove-itemproperty)\b", "registry change"),
    (r"\b(set-executionpolicy|set-mppreference|add-mppreference|netsh|new-netfirewallrule|sc(\.exe)?\s+(create|delete|config)|new-service|schtasks|register-scheduledtask)\b", "system configuration"),
    (r"(?<![\w-])(stop-computer|restart-computer|shutdown|logoff)(?![\w-])", "shutdown/restart"),
    (r"\b(start-process\b[^\n]*-verb\s+runas|runas\b|sudo\b)", "elevation"),
    (r"\bgit\s+(push|reset\s+--hard|clean\s+-[a-z]*f|checkout\s+--\s|filter-branch|reflog\s+expire|gc\s+--prune)", "destructive/remote git operation"),
    (r"\b(invoke-expression|iex)\b|frombase64string|-enc(odedcommand)?\b", "dynamic code execution"),
    (r"\b(invoke-webrequest|iwr|invoke-restmethod|irm|curl|wget|start-bitstransfer|certutil\s+-urlcache)\b", "network download/upload"),
    (r"\b(pip|pip3|npm|pnpm|yarn|choco|winget|scoop)\s+(install|uninstall|i|add|remove)\b", "package install/uninstall"),
    (r"(?<![\w-])(stop-process|taskkill|kill)(?![\w-])", "kills processes"),
    (r"(\.ssh|id_rsa|id_ed25519|\.env\b|\.git-credentials|\.aws|credentials|\\appdata\\|/appdata/|\\microsoft\\credentials|login data|cookies)", "touches secrets/credentials"),
    (r"\b(set-content|out-file|add-content|copy-item|move-item|new-item)\b[^\n]*[a-z]:\\(windows|program files|users\\[^\\]+\\appdata)", "writes to system/app folders"),
]
_DANGER_RE = [(re.compile(p, re.I), why) for p, why in _DANGER]
_ABS_PATH = re.compile(r"(?<![\w$])([A-Za-z]):[\\/][^\s'\"|;,)]*")


def assess(command: str):
    """Return list of reasons why the command looks risky (heuristic, not a sandbox)."""
    reasons = []
    for rx, why in _DANGER_RE:
        if rx.search(command) and why not in reasons:
            reasons.append(why)
    from nb import paths
    roots = list(paths.workspaces().values())
    for m in _ABS_PATH.finditer(command):
        p = m.group(0).rstrip(".")
        if not any(paths.is_within(os.path.normpath(p), r) for r in roots):
            reasons.append(f"path outside workspaces: {p[:60]}")
            break
    if re.search(r"(^|[\s'\"/\\])\.\.([\\/]|$)", command):
        reasons.append("parent-directory traversal (..)")
    return reasons


def needs_approval(reasons) -> bool:
    mode = runtime.config.get("confirm_commands", "dangerous")
    if mode == "always":
        return True
    if mode == "never":
        return False
    return bool(reasons)


# ---------------------------------------------------------------- foreground run
class RunResult:
    def __init__(self):
        self.out = StreamBuffer()
        self.err = StreamBuffer()
        self.code = None
        self.timed_out = False
        self.cancelled = False
        self.duration = 0.0
        self.note = ""
        self.shell = ""


_active = set()


def start_run(command: str, cwd: Path, encoded=False):
    argv, tmp, shell = build_argv(command, encoded=encoded)
    p, tree = spawn(argv, cwd)
    _active.add(tree)
    r = RunResult()
    r.shell = shell
    threads = [threading.Thread(target=_pump, args=(p.stdout, r.out), daemon=True),
               threading.Thread(target=_pump, args=(p.stderr, r.err), daemon=True)]
    for t in threads:
        t.start()
    return p, tree, r, threads, tmp


def finish_run(p, tree, r, threads, tmp, started):
    for t in threads:
        t.join(timeout=2.0)  # a detached grandchild may keep the pipe open; don't wait for it
    if any(t.is_alive() for t in threads):
        r.note = "a background child process still holds the output pipe; output may be incomplete"
    r.code = p.returncode
    r.duration = time.time() - started
    _active.discard(tree)
    tree.close()
    if tmp:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    return r


def policy_blocked(r: RunResult) -> bool:
    """True when Group Policy blocked our temp .ps1 (then we retry with -EncodedCommand)."""
    if r.code in (0, None):
        return False
    head, tail, _ = r.err.parts()
    t = smart_decode(head + tail).lower()
    markers = ("running scripts is disabled", "is not digitally signed", "pssecurityexception",
               "выполнение сценариев отключено", "не имеет цифровой подписи")
    return any(m in t for m in markers) and ".ps1" in t


# ---------------------------------------------------------------- background processes
class BgProcess:
    _ids = itertools.count(1)

    def __init__(self, command, cwd, display_cwd, name=""):
        self.id = f"p{next(self._ids)}"
        self.command, self.cwd, self.display_cwd = command, cwd, display_cwd
        self.name = name or command.split("\n", 1)[0][:40]
        self.started = time.time()
        self.ended = None
        self.lock = threading.Lock()
        self.chunks = deque()       # (offset, text)
        self.size = 0               # total chars produced
        self.kept_from = 0          # first offset still in memory
        self.read_pos = 0
        self.limit = 2_000_000
        self.decoder_out = codecs.getincrementaldecoder("utf-8")("replace")
        self.decoder_err = codecs.getincrementaldecoder("utf-8")("replace")
        argv, self.tmp, self.shell = build_argv(command)
        self.proc, self.tree = spawn(argv, cwd, stdin_pipe=True)
        self.new_data = threading.Event()
        self._threads = [threading.Thread(target=self._reader, args=(self.proc.stdout, self.decoder_out, ""), daemon=True),
                         threading.Thread(target=self._reader, args=(self.proc.stderr, self.decoder_err, "[stderr] "), daemon=True)]
        for t in self._threads:
            t.start()
        threading.Thread(target=self._waiter, daemon=True).start()

    def _append(self, text):
        with self.lock:
            self.chunks.append((self.size, text))
            self.size += len(text)
            while self.size - self.kept_from > self.limit and self.chunks:
                off, t = self.chunks.popleft()
                self.kept_from = off + len(t)
        self.new_data.set()

    def _reader(self, stream, decoder, prefix):
        pending_line_start = True
        try:
            while True:
                chunk = stream.read1(65536) if hasattr(stream, "read1") else stream.read(4096)
                if not chunk:
                    break
                text = decoder.decode(chunk).replace("\r\n", "\n")
                if prefix:
                    lines = text.split("\n")
                    text = "\n".join((prefix + l) if (i > 0 or pending_line_start) and l else l for i, l in enumerate(lines))
                    pending_line_start = text.endswith("\n")
                self._append(text)
        except (OSError, ValueError):
            pass

    def _waiter(self):
        self.proc.wait()
        for t in self._threads:
            t.join(timeout=2)
        self.ended = time.time()
        self.tree.close()
        if self.tmp:
            try:
                os.unlink(self.tmp)
            except OSError:
                pass
        self.new_data.set()

    @property
    def running(self):
        return self.proc.poll() is None

    def read(self, from_start=False, max_chars=20000):
        with self.lock:
            start = self.kept_from if from_start else max(self.read_pos, self.kept_from)
            lost = (self.kept_from - self.read_pos) if (self.read_pos < self.kept_from and not from_start) else 0
            parts = []
            for off, t in self.chunks:
                end = off + len(t)
                if end <= start:
                    continue
                parts.append(t[max(0, start - off):])
            text = "".join(parts)
            self.read_pos = self.size
            self.new_data.clear()
        return clip(clean_clixml(text), max_chars), lost

    def write(self, text: str):
        if not self.running or not self.proc.stdin:
            raise RuntimeError(f"Process {self.id} is not running.")
        self.proc.stdin.write(text.encode("utf-8"))
        self.proc.stdin.flush()

    def stop(self):
        if self.running:
            self.tree.kill()

    def info(self):
        st = "running" if self.running else f"exited ({self.proc.returncode})"
        dur = (self.ended or time.time()) - self.started
        return {"id": self.id, "name": self.name, "status": st, "seconds": round(dur, 1), "cwd": self.display_cwd,
                "unread_chars": max(0, self.size - self.read_pos), "command": self.command[:200]}


registry = {}
MAX_BG = 8


def bg_start(command, cwd, display_cwd, name=""):
    for pid in [k for k, v in registry.items() if not v.running and v.ended and time.time() - v.ended > 1800]:
        registry.pop(pid, None)
    running = [p for p in registry.values() if p.running]
    if len(running) >= MAX_BG:
        raise RuntimeError(f"Too many background processes ({len(running)}). Stop some with stop_process.")
    p = BgProcess(command, cwd, display_cwd, name)
    registry[p.id] = p
    return p


def bg_get(pid: str) -> BgProcess:
    p = registry.get(pid.strip())
    if not p:
        raise KeyError(f"Unknown process id {pid!r}. Use list_processes.")
    return p


def stop_all():
    for t in list(_active):
        try:
            t.kill()
        except Exception:
            pass
    for p in list(registry.values()):
        try:
            p.stop()
        except Exception:
            pass
