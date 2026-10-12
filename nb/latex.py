"""LaTeX build with a readable error summary (latexmk when it works, manual sequence otherwise)."""
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from nb import procs


def pick_engine(text: str, engine: str) -> str:
    if engine and engine != "auto":
        return engine
    if re.search(r"\\usepackage(\[[^\]]*\])?\{(fontspec|polyglossia|unicode-math)\}", text):
        return "xelatex"
    return "pdflatex"


def _run(args, cwd, timeout, deadline):
    left = max(5, int(deadline - time.time()))
    kw = {"creationflags": procs.CREATE_NO_WINDOW} if os.name == "nt" else {}
    try:
        p = subprocess.run(args, cwd=str(cwd), capture_output=True, stdin=subprocess.DEVNULL,
                           timeout=min(timeout, left), env=procs.child_env(), **kw)
        return p.returncode, procs.smart_decode(p.stdout + p.stderr)
    except subprocess.TimeoutExpired:
        return -1, f"timeout after {min(timeout, left)}s"
    except FileNotFoundError:
        return -2, f"{args[0]} not found"


def find_tectonic() -> str:
    t = shutil.which("tectonic")
    if t:
        return t
    home = Path.home()
    for c in (home / "Tectonic" / "tectonic.exe", home / ".cargo" / "bin" / "tectonic.exe",
              home / "scoop" / "shims" / "tectonic.exe", Path(os.environ.get("LOCALAPPDATA", "")) / "Tectonic" / "tectonic.exe"):
        if c.is_file():
            return str(c)
    return ""


_TT_ERR = re.compile(r"^error: (.+?\.(?:tex|sty|cls|bib)):(\d+): (.+)$")


def _pdf_pages(pdf: Path):
    try:
        from pypdf import PdfReader  # optional
        return len(PdfReader(str(pdf)).pages)
    except Exception:
        try:
            n = len(re.findall(rb"/Type\s*/Page(?![s\w])", pdf.read_bytes()))
            return n or None
        except OSError:
            return None


def build_tectonic(main: Path, exe: str, timeout: int):
    """Tectonic: self-contained engine (XeTeX-based), downloads packages on demand, reruns and runs bibtex itself.
    --untrusted disables shell-escape and other insecure features."""
    cwd, stem = main.parent, main.stem
    deadline = time.time() + timeout
    code, out = _run([exe, "-X", "compile", main.name, "--keep-logs", "--synctex", "--untrusted"], cwd, timeout, deadline)
    if code == 2 and "unexpected argument" in out:  # very old tectonic without the V2 CLI
        code, out = _run([exe, "--keep-logs", "--synctex", main.name], cwd, timeout, deadline)
    res = parse_log(cwd / f"{stem}.log")
    if not (cwd / f"{stem}.log").exists():
        res["errors"] = []
    for ln in out.split("\n"):
        m = _TT_ERR.match(ln.strip())
        if m and not any(e.get("line") == int(m.group(2)) for e in res["errors"]):
            res["errors"].append({"file": m.group(1).lstrip("./"), "line": int(m.group(2)), "msg": m.group(3)})
    if code not in (0,) and not res["errors"]:
        tail = [l for l in out.split("\n") if l.strip().startswith("error")][-3:] or out.strip().split("\n")[-3:]
        res["errors"].append({"msg": " / ".join(t.strip() for t in tail)[:400] or f"tectonic exit {code}"})
    # Tectonic's log has no "Output written" line: fill file:line for "! ..." errors and the page count
    for e in res["errors"]:
        if e.get("line") and not e.get("file"):
            e["file"] = main.name
    pdf = cwd / f"{stem}.pdf"
    if pdf.exists() and code == 0 and res.get("pages") is None:
        res["pages"] = _pdf_pages(pdf)
    res["engine"] = "tectonic"
    res["steps"] = [("tectonic (auto reruns + bibtex)", code)]
    res["pdf"] = pdf.name if pdf.exists() and code == 0 else None
    res["ok"] = bool(res["pdf"]) and not res["errors"]
    return res


def build(main: Path, engine: str = "auto", timeout: int = 300):
    cwd = main.parent
    stem = main.stem
    text = main.read_text(encoding="utf-8", errors="replace")
    if engine == "tectonic":
        exe = find_tectonic()
        if not exe:
            return {"ok": False, "error": "tectonic not found (PATH, %USERPROFILE%\\Tectonic, cargo, scoop)."}
        return build_tectonic(main, exe, timeout)
    eng = pick_engine(text, engine)
    if engine == "auto" and not shutil.which("latexmk") and not shutil.which(eng):
        exe = find_tectonic()
        if exe:  # no TeX Live / MiKTeX, but Tectonic is installed
            return build_tectonic(main, exe, timeout)
    deadline = time.time() + timeout
    steps = []
    common = ["-interaction=nonstopmode", "-file-line-error", "-synctex=1", "-no-shell-escape"]
    used_latexmk = False
    if shutil.which("latexmk"):
        flag = {"pdflatex": "-pdf", "xelatex": "-xelatex", "lualatex": "-lualatex"}.get(eng, "-pdf")
        args = ["latexmk", flag, "-f", "-silent"] + [f"-latexoption={o}" for o in common] + [main.name]
        code, out = _run(args, cwd, timeout, deadline)
        steps.append(("latexmk", code))
        if code == -2 or re.search(r"(perl|script engine).{0,40}(not found|could not|cannot)", out, re.I):
            steps.append(("latexmk unavailable (Perl missing?) -> manual build", None))
        else:
            used_latexmk = True
    if not used_latexmk:
        if not shutil.which(eng):
            return {"ok": False, "error": f"{eng} not found. Install MiKTeX / TeX Live, or Tectonic (engine='tectonic')."}
        for i in range(3):
            code, out = _run([eng] + common + [main.name], cwd, timeout, deadline)
            steps.append((f"{eng} pass {i + 1}", code))
            aux = cwd / f"{stem}.aux"
            if i == 0:
                if (cwd / f"{stem}.bcf").exists() and shutil.which("biber"):
                    steps.append(("biber", _run(["biber", stem], cwd, timeout, deadline)[0]))
                elif aux.exists() and "\\bibdata" in aux.read_text(encoding="utf-8", errors="replace") and shutil.which("bibtex"):
                    steps.append(("bibtex", _run(["bibtex", stem], cwd, timeout, deadline)[0]))
                if (cwd / f"{stem}.idx").exists() and shutil.which("makeindex"):
                    steps.append(("makeindex", _run(["makeindex", stem], cwd, timeout, deadline)[0]))
            log = cwd / f"{stem}.log"
            if log.exists() and i >= 1 and "Rerun to get" not in log.read_text(encoding="utf-8", errors="replace"):
                break
            if code == -1:
                break
    res = parse_log(cwd / f"{stem}.log")
    res["engine"] = eng
    res["steps"] = steps
    pdf = cwd / f"{stem}.pdf"
    res["pdf"] = pdf.name if pdf.exists() else None
    res["ok"] = bool(res["pdf"]) and not res["errors"]
    return res


def _unwrap(log: str) -> list:
    lines, out = log.split("\n"), []
    buf = ""
    for ln in lines:
        buf += ln
        if len(ln) == 79:  # TeX hard-wraps at max_print_line
            continue
        out.append(buf)
        buf = ""
    if buf:
        out.append(buf)
    return out


def parse_log(log_path: Path):
    res = {"errors": [], "warnings": [], "counts": {}, "pages": None}
    if not log_path.exists():
        res["errors"].append({"msg": "No .log produced (engine did not start?)"})
        return res
    raw = log_path.read_bytes().decode("utf-8", errors="replace")
    lines = _unwrap(raw.replace("\r\n", "\n"))
    fle = re.compile(r"^(.*?\.(?:tex|sty|cls|bib|ltx|def)):(\d+): (.*)$")
    for i, ln in enumerate(lines):
        m = fle.match(ln)
        if m:
            ctx = [l for l in lines[i + 1:i + 4] if l.strip()][:2]
            res["errors"].append({"file": m.group(1).lstrip("./"), "line": int(m.group(2)), "msg": m.group(3), "context": ctx})
        elif ln.startswith("! "):
            lno = None
            for l in lines[i + 1:i + 12]:
                mm = re.match(r"^l\.(\d+)", l)
                if mm:
                    lno = int(mm.group(1))
                    break
            if not any(e.get("msg") == ln[2:] for e in res["errors"]):
                res["errors"].append({"line": lno, "msg": ln[2:]})
        mw = re.search(r"(LaTeX|Package [\w-]+|Class [\w-]+) Warning: (.*)", ln)
        if mw:
            msg = mw.group(2)
            if re.search(r"Citation .* undefined", msg):
                key = "undefined citations"
            elif re.search(r"Reference .* undefined", msg):
                key = "undefined references"
            elif "Label(s) may have changed" in msg or "Rerun" in msg:
                key = "rerun needed"
            elif "multiply defined" in msg:
                key = "multiply-defined labels"
            else:
                key = "other warnings"
            res["counts"][key] = res["counts"].get(key, 0) + 1
            if len(res["warnings"]) < 15 and key != "other warnings":
                res["warnings"].append(f"{mw.group(1)}: {msg[:200]}")
        if ln.startswith("Missing character: There is no"):
            res["counts"]["missing characters"] = res["counts"].get("missing characters", 0) + 1
            if res["counts"]["missing characters"] == 1:
                res["warnings"].append("Font has no glyphs for some characters (e.g. Cyrillic): with xelatex/tectonic use "
                                       "\\usepackage{fontspec} + \\setmainfont{Times New Roman} (or babel/polyglossia)")
        if ln.startswith("Overfull \\hbox"):
            res["counts"]["overfull hbox"] = res["counts"].get("overfull hbox", 0) + 1
        if ln.startswith("Underfull \\hbox"):
            res["counts"]["underfull hbox"] = res["counts"].get("underfull hbox", 0) + 1
        mp = re.search(r"Output written on .*?\((\d+) pages?", ln)
        if mp:
            res["pages"] = int(mp.group(1))
        if "No pages of output" in ln:
            res["pages"] = 0
    res["errors"] = res["errors"][:25]
    return res
