"""Plain-text extraction for .docx / .xlsx / .pptx (stdlib only) and .pdf (pypdf or pdftotext)."""
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
R_NS = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
MAX_XML = 80 * 1024 * 1024


class DocError(Exception):
    pass


def _xml(z: zipfile.ZipFile, name: str):
    info = z.getinfo(name)
    if info.file_size > MAX_XML:
        raise DocError(f"{name} is too large to parse ({info.file_size} bytes)")
    return ET.fromstring(z.read(name))


def _para_text(p):
    out = []
    for el in p.iter():
        if el.tag == W + "t":
            out.append(el.text or "")
        elif el.tag == W + "tab":
            out.append("\t")
        elif el.tag in (W + "br", W + "cr"):
            out.append("\n")
    return "".join(out)


def docx(path: Path) -> str:
    with zipfile.ZipFile(path) as z:
        root = _xml(z, "word/document.xml")
    body = root.find(W + "body")
    lines = []
    for el in list(body if body is not None else []):
        if el.tag == W + "p":
            style = el.find(f"{W}pPr/{W}pStyle")
            sval = style.get(W + "val", "") if style is not None else ""
            txt = _para_text(el)
            m = re.search(r"(?:heading|заголовок)\s*(\d)", sval, re.I) or re.match(r"^(\d)$", sval)
            if m and txt.strip():
                txt = "#" * int(m.group(1)) + " " + txt
            elif el.find(f"{W}pPr/{W}numPr") is not None and txt.strip():
                txt = "- " + txt
            lines.append(txt)
        elif el.tag == W + "tbl":
            for tr in el.iter(W + "tr"):
                cells = [" ".join(_para_text(p) for p in tc.iter(W + "p")).strip() for tc in tr.iter(W + "tc")]
                lines.append("| " + " | ".join(cells) + " |")
            lines.append("")
    text = "\n".join(lines)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _col_index(ref: str) -> int:
    n = 0
    for ch in re.match(r"[A-Z]+", ref).group(0):
        n = n * 26 + (ord(ch) - 64)
    return n - 1


def xlsx(path: Path, max_rows: int = 500) -> str:
    with zipfile.ZipFile(path) as z:
        shared = []
        if "xl/sharedStrings.xml" in z.namelist():
            for si in _xml(z, "xl/sharedStrings.xml").iter(S + "si"):
                shared.append("".join(t.text or "" for t in si.iter(S + "t")))
        wb = _xml(z, "xl/workbook.xml")
        rels = {}
        if "xl/_rels/workbook.xml.rels" in z.namelist():
            for rel in _xml(z, "xl/_rels/workbook.xml.rels"):
                rels[rel.get("Id")] = rel.get("Target")
        out = []
        for sh in wb.iter(S + "sheet"):
            name = sh.get("name")
            target = rels.get(sh.get(R_NS + "id"), "")
            target = target.lstrip("/")
            target = target if target.startswith("xl/") else "xl/" + target
            if target not in z.namelist():
                continue
            out.append(f"## Sheet: {name}")
            rows = 0
            for row in _xml(z, target).iter(S + "row"):
                vals = {}
                for c in row.iter(S + "c"):
                    t, v = c.get("t"), c.find(S + "v")
                    if t == "s" and v is not None:
                        val = shared[int(v.text)] if v.text and int(v.text) < len(shared) else ""
                    elif t == "inlineStr":
                        val = "".join(x.text or "" for x in c.iter(S + "t"))
                    elif t == "b" and v is not None:
                        val = "TRUE" if v.text == "1" else "FALSE"
                    else:
                        val = v.text if v is not None and v.text is not None else ""
                        f = c.find(S + "f")
                        if f is not None and f.text and not val:
                            val = "=" + f.text
                    if val != "":
                        vals[_col_index(c.get("r", "A1"))] = val
                if vals:
                    width = max(vals) + 1
                    out.append(f"{row.get('r', '?')}\t" + "\t".join(vals.get(i, "") for i in range(width)))
                    rows += 1
                    if rows >= max_rows:
                        out.append(f"... (truncated after {max_rows} rows)")
                        break
            out.append("")
    return "\n".join(out).strip()


def pptx(path: Path) -> str:
    with zipfile.ZipFile(path) as z:
        names = sorted((n for n in z.namelist() if re.match(r"ppt/slides/slide\d+\.xml$", n)),
                       key=lambda n: int(re.search(r"(\d+)", n.rsplit("/", 1)[1]).group(1)))
        out = []
        for i, n in enumerate(names, 1):
            root = _xml(z, n)
            paras = []
            for p in root.iter(A + "p"):
                t = "".join(x.text or "" for x in p.iter(A + "t"))
                if t.strip():
                    paras.append(t)
            out.append(f"## Slide {i}\n" + "\n".join(paras))
    return "\n\n".join(out).strip()


def _page_range(spec: str, n: int):
    if not spec:
        return list(range(n))
    pages = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            a = int(a or 1)
            b = int(b or n)
            pages.update(range(a - 1, min(b, n)))
        elif part:
            pages.add(int(part) - 1)
    return sorted(p for p in pages if 0 <= p < n)


def pdf(path: Path, pages: str = "") -> str:
    try:
        from pypdf import PdfReader  # optional dependency
        reader = PdfReader(str(path))
        n = len(reader.pages)
        out = []
        for i in _page_range(pages, n):
            out.append(f"--- page {i + 1}/{n} ---\n" + (reader.pages[i].extract_text() or "").strip())
        return "\n\n".join(out)
    except ImportError:
        pass
    exe = shutil.which("pdftotext")
    if exe:
        args = [exe, "-layout", "-enc", "UTF-8"]
        if pages and re.fullmatch(r"\d+(-\d+)?", pages.strip()):
            a, _, b = pages.strip().partition("-")
            args += ["-f", a, "-l", b or a]
        p = subprocess.run(args + [str(path), "-"], capture_output=True, timeout=120)
        return p.stdout.decode("utf-8", "replace")
    raise DocError("PDF support needs pypdf: run  pip install pypdf  (or install poppler's pdftotext).")


def extract(path: Path, pages: str = "") -> str:
    ext = path.suffix.lower()
    try:
        if ext in (".docx", ".docm", ".dotx"):
            return docx(path)
        if ext in (".xlsx", ".xlsm"):
            return xlsx(path)
        if ext in (".pptx", ".pptm"):
            return pptx(path)
        if ext == ".pdf":
            return pdf(path, pages)
    except zipfile.BadZipFile:
        raise DocError(f"{path.name} is not a valid Office (zip) file.")
    except (KeyError, ET.ParseError) as e:
        raise DocError(f"Could not parse {path.name}: {e}")
    if ext in (".doc", ".xls", ".ppt"):
        raise DocError("Legacy binary Office format; save it as .docx/.xlsx/.pptx first.")
    raise DocError(f"Unsupported document type {ext!r} (supported: .docx .xlsx .pptx .pdf).")
