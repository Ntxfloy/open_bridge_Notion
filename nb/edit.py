"""Edit engine: search/replace with safe fallbacks, line edits, unified / Codex-style patches.

Lessons applied from open-source coding agents:
- Claude Code / Desktop Commander: old_text must match exactly once unless a count is given;
  ambiguous matches are an error that lists the line numbers.
- Cline (diff.ts): exact -> line-trimmed -> ... fallbacks; Aider: restore missing leading indentation.
- Aider (lesson learned): never auto-apply a fuzzy Levenshtein match, it silently drops lines.
  We only *report* the closest region with a diff so the model can retry.
- Common model mistakes are repaired: smart quotes/nbsp, copied line-number prefixes,
  double-escaped "\\n", CRLF in arguments.
"""
import difflib
import re
from dataclasses import dataclass, field
from typing import List, Optional


class EditError(Exception):
    pass


# 1:1 character normalisation (keeps string length, so offsets stay valid)
_NORM = str.maketrans({
    "\u00a0": " ", "\u2007": " ", "\u202f": " ", "\u2009": " ", "\u200a": " ", "\u3000": " ",
    "\u2018": "'", "\u2019": "'", "\u201a": "'", "\u201b": "'", "\u2032": "'",
    "\u201c": '"', "\u201d": '"', "\u201e": '"', "\u201f": '"', "\u2033": '"', "\u00ab": '"', "\u00bb": '"',
    "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-", "\u2015": "-", "\u2212": "-",
    "\t": "\t",
})
_LINE_NO = re.compile(r"^\s*\d+(?:\t|\s?[│|:→]\s?)")


@dataclass
class Match:
    start: int
    end: int
    strategy: str
    reindent: Optional[tuple] = None   # (search_ws, file_ws)
    warn: str = ""


@dataclass
class EditResult:
    text: str
    notes: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def norm_newlines(s: str) -> str:
    return (s or "").replace("\r\n", "\n")


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _line_starts(lines):
    starts, pos = [], 0
    for ln in lines:
        starts.append(pos)
        pos += len(ln) + 1
    return starts


def _lead_ws(s: str) -> str:
    return s[: len(s) - len(s.lstrip(" \t"))]


def _find_all(hay: str, needle: str):
    out, i = [], hay.find(needle)
    while i != -1 and needle:
        out.append(i)
        i = hay.find(needle, i + len(needle))
    return out


def _line_based(text, search, mode, normalize_chars, require_uniform=True):
    flines = text.split("\n")
    ends_nl = search.endswith("\n")
    slines = search.split("\n")
    if ends_nl:
        slines = slines[:-1]
    if not slines or not any(s.strip() for s in slines):
        return []
    tr = (lambda s: s.translate(_NORM)) if normalize_chars else (lambda s: s)
    if mode == "rstrip":
        cmp = lambda s: tr(s).rstrip()
    else:
        cmp = lambda s: tr(s).strip()
    fc = [cmp(x) for x in flines]
    sc = [cmp(x) for x in slines]
    n = len(sc)
    starts = _line_starts(flines)
    out = []
    i = 0
    while i <= len(fc) - n:
        if fc[i] == sc[0] and fc[i:i + n] == sc:
            last = i + n - 1
            start = starts[i]
            end = starts[last] + len(flines[last])
            if ends_nl and end < len(text):
                end += 1
            m = Match(start, end, "")
            if mode == "strip":
                k = next(j for j, s in enumerate(slines) if s.strip())
                s_ws, f_ws = _lead_ws(slines[k]), _lead_ws(flines[i + k])
                uniform = True
                for j, s in enumerate(slines):
                    if not s.strip():
                        continue
                    sw, fw = _lead_ws(s), _lead_ws(flines[i + j])
                    if not sw.startswith(s_ws) or fw != f_ws + sw[len(s_ws):]:
                        uniform = False
                        break
                m.reindent = (s_ws, f_ws) if s_ws != f_ws else None
                if not uniform and require_uniform:
                    i += 1
                    continue  # relative indentation differs -> applying could break code (Python!)
            out.append(m)
            i += n
        else:
            i += 1
    return out


def find_matches(text: str, search: str):
    """Return (matches, strategy). Strategies are tried from strict to lenient; first hit wins."""
    exact = [Match(i, i + len(search), "exact") for i in _find_all(text, search)]
    if exact:
        return exact, "exact"
    nt, ns = text.translate(_NORM), search.translate(_NORM)
    if ns != search or nt != text:
        uni = [Match(i, i + len(ns), "unicode-normalized") for i in _find_all(nt, ns)]
        if uni:
            return uni, "unicode-normalized"
    for mode, label in (("rstrip", "trailing-whitespace-insensitive"), ("strip", "indentation-flexible")):
        for normc in (False, True):
            ms = _line_based(text, search, mode, normc)
            if ms:
                lab = label + (" + unicode-normalized" if normc else "")
                for m in ms:
                    m.strategy = lab
                return ms, lab
    return [], ""


def _reindent(repl: str, s_ws: str, f_ws: str) -> str:
    out = []
    for line in repl.split("\n"):
        if line.strip() and line.startswith(s_ws):
            out.append(f_ws + line[len(s_ws):])
        elif line.strip() and not s_ws:
            out.append(f_ws + line)
        else:
            out.append(line)
    return "\n".join(out)


def _strip_line_numbers(s: str):
    lines = s.split("\n")
    body = [l for l in lines if l.strip()]
    if body and all(_LINE_NO.match(l) for l in body):
        return "\n".join(_LINE_NO.sub("", l, count=1) for l in lines)
    return None


def closest_region(text: str, search: str, max_file_lines: int = 60000):
    """Best-effort diagnosis: (similarity, first_line, last_line, region_text) or None."""
    flines = text.split("\n")[:max_file_lines]
    slines = search.rstrip("\n").split("\n")
    n = len(slines)
    if not flines or not search.strip():
        return None
    n_eff = min(n, len(flines))
    sset = {l.strip() for l in slines if l.strip()}
    hits = [1 if (l.strip() and l.strip() in sset) else 0 for l in flines]
    pref = [0]
    for h in hits:
        pref.append(pref[-1] + h)
    scores = [(pref[i + n_eff] - pref[i], -i) for i in range(len(flines) - n_eff + 1)]
    cands = [-i for _, i in sorted(scores, reverse=True)[:6] if _ > 0]
    first = slines[0].strip() or (slines[1].strip() if n > 1 else "")
    if first:
        sims = []
        for i, l in enumerate(flines[: len(flines) - n_eff + 1]):
            sm = difflib.SequenceMatcher(None, l.strip(), first, autojunk=False)
            if sm.real_quick_ratio() > 0.5 and sm.quick_ratio() > 0.5:
                sims.append((sm.ratio(), i))
        cands += [i for _, i in sorted(sims, reverse=True)[:6]]
    if not cands:
        return None
    best = None
    for i in dict.fromkeys(cands):
        region = "\n".join(flines[i:i + n_eff])
        r = difflib.SequenceMatcher(None, region, search.rstrip("\n"), autojunk=False).ratio()
        if best is None or r > best[0]:
            best = (r, i + 1, i + n_eff, region)
    return best


def explain_no_match(text: str, search: str, label: str = "old_text") -> str:
    msg = [f"{label} was not found in the file (exact and whitespace/quote-tolerant matching failed)."]
    loose = _line_based(text, search, "strip", True, require_uniform=False)
    if loose:
        a = line_of(text, loose[0].start)
        b = line_of(text, loose[0].end - 1 if loose[0].end > loose[0].start else loose[0].start)
        msg.append(f"The same lines exist at {a}-{b} but with different relative indentation. "
                   "Copy the indentation exactly from read_file output (it matters in Python/YAML).")
        return "\n".join(msg)
    best = closest_region(text, search)
    if best and best[0] >= 0.5:
        r, a, b, region = best
        diff = difflib.unified_diff(search.rstrip("\n").split("\n"), region.split("\n"),
                                    f"your {label}", f"file lines {a}-{b}", n=1, lineterm="")
        d = list(diff)[2:]
        msg.append(f"Closest region: lines {a}-{b} ({r:.0%} similar). Differences (- yours, + file):")
        msg.extend(d[:40])
        if len(d) > 40:
            msg.append(f"... {len(d) - 40} more diff lines")
        msg.append("Re-read those lines with read_file and copy old_text exactly, or use edit_lines with line numbers.")
    else:
        msg.append("Nothing similar was found. Re-read the file (read_file) or search for a distinctive line (search_code).")
    return "\n".join(msg)


def apply_one(text: str, old: str, new: str, expected: int = 1, near_line: int = 0):
    """Apply a single replacement. Returns (new_text, note, warnings). expected=0 -> all occurrences."""
    old, new = norm_newlines(old), norm_newlines(new)
    if not old:
        raise EditError("old_text is empty. To create a file use write_file; to insert text use edit_lines.")
    if old == new:
        raise EditError("old_text and new_text are identical; nothing to change.")
    warnings = []
    matches, strategy = find_matches(text, old)
    repaired = ""
    if not matches:
        alt = _strip_line_numbers(old)
        if alt is not None:
            new_alt = _strip_line_numbers(new)
            matches, strategy = find_matches(text, alt)
            if matches:
                old, new, repaired = alt, (new_alt if new_alt is not None else new), "line-number prefixes removed"
    if not matches and "\n" not in old and ("\\n" in old):
        un = lambda s: s.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\t", "\t").replace('\\"', '"')
        matches, strategy = find_matches(text, un(old))
        if matches:
            old, new, repaired = un(old), un(new), "literal \\n sequences unescaped"
    if not matches:
        raise EditError(explain_no_match(text, old))

    count = len(matches)
    if expected and count != expected:
        if count > expected and expected == 1 and near_line:
            matches = [min(matches, key=lambda m: abs(line_of(text, m.start) - near_line))]
            warnings.append(f"{count} matches; used the one nearest to line {near_line}")
        else:
            where = ", ".join(str(line_of(text, m.start)) for m in matches[:15])
            if count > expected:
                raise EditError(
                    f"old_text matches {count} places (lines {where}) but expected_replacements={expected}. "
                    "Add surrounding lines to make it unique, or set expected_replacements to the exact count (0 = all).")
            raise EditError(f"Expected {expected} replacements but old_text matches only {count} (lines {where}).")

    out = text
    for m in sorted(matches, key=lambda m: m.start, reverse=True):
        repl = new
        if m.reindent:
            repl = _reindent(new, *m.reindent)
        # keep "no newline at end of file" state for whole-line matches at EOF
        if old.endswith("\n") and m.end == len(out) and not out.endswith("\n") and repl.endswith("\n"):
            repl = repl[:-1]
        out = out[:m.start] + repl + out[m.end:]
        if m.warn:
            warnings.append(m.warn)
    first_line = line_of(text, min(m.start for m in matches))
    note = f"{len(matches)} replacement(s) at line {first_line}" + (f" [{strategy}]" if strategy != "exact" else "")
    if repaired:
        note += f" ({repaired})"
    return out, note, sorted(set(warnings))


def apply_edits(text: str, edits) -> EditResult:
    """edits: list of dicts {old_text, new_text, expected_replacements, near_line}. All-or-nothing."""
    res = EditResult(text)
    for idx, e in enumerate(edits, 1):
        try:
            res.text, note, w = apply_one(res.text, e.get("old_text", ""), e.get("new_text", ""),
                                          int(e.get("expected_replacements", 1) if e.get("expected_replacements", 1) is not None else 1),
                                          int(e.get("near_line") or 0))
        except EditError as ex:
            prefix = f"Edit {idx}/{len(edits)} failed" + (f" (edits 1-{idx - 1} were OK but nothing was written)" if idx > 1 else " (nothing was written)")
            raise EditError(f"{prefix}: {ex}") from None
        res.notes.append(f"edit {idx}: {note}")
        res.warnings += w
    return res


def replace_lines(text: str, start: int, end: int, new: str) -> str:
    """Replace 1-based inclusive [start, end]; end == start-1 inserts before start; new == '' deletes."""
    lines = text.split("\n")
    trailing = text.endswith("\n")
    if trailing:
        lines = lines[:-1]
    n = len(lines)
    if start < 1 or start > n + 1:
        raise EditError(f"start_line {start} is out of range (file has {n} lines; use {n + 1} to append).")
    if end < start - 1 or end > n:
        raise EditError(f"end_line {end} is out of range (must be between {start - 1} and {n}).")
    new = norm_newlines(new)
    new_lines = [] if new == "" else (new[:-1] if new.endswith("\n") else new).split("\n")
    out = lines[:start - 1] + new_lines + lines[end:]
    result = "\n".join(out)
    if out and (trailing or (end >= n and new.endswith("\n"))):
        result += "\n"
    return result


# ---------------------------------------------------------------- diffs
def unified_diff(old: str, new: str, path: str, context: int = 2, max_lines: int = 80) -> str:
    d = list(difflib.unified_diff(old.split("\n"), new.split("\n"), f"a/{path}", f"b/{path}", n=context, lineterm=""))
    if not d:
        return "(no changes)"
    if len(d) > max_lines:
        extra = len(d) - max_lines
        d = d[:max_lines] + [f"... diff truncated ({extra} more lines)"]
    return "\n".join(d)


def diffstat(old: str, new: str):
    add = rem = 0
    for line in difflib.ndiff(old.split("\n"), new.split("\n")) if (len(old) + len(new)) < 400_000 else []:
        if line.startswith("+ "):
            add += 1
        elif line.startswith("- "):
            rem += 1
    if (len(old) + len(new)) >= 400_000:
        sm = difflib.SequenceMatcher(None, old.split("\n"), new.split("\n"), autojunk=False)
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag in ("replace", "delete"):
                rem += i2 - i1
            if tag in ("replace", "insert"):
                add += j2 - j1
    return add, rem


# ---------------------------------------------------------------- patches
@dataclass
class Hunk:
    old: List[str]
    new: List[str]
    hint: int = 0           # 1-based line hint (unified header old_start)
    anchor: str = ""        # Codex "@@ context" line
    no_eol_new: bool = False


@dataclass
class FilePatch:
    kind: str               # update | add | delete
    path: str
    new_path: str = ""
    hunks: List[Hunk] = field(default_factory=list)
    content: str = ""       # for add


_HUNK_RE = re.compile(r"^@@+ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@+(.*)$")


def _clean_path(p: str) -> str:
    p = p.strip()
    if "\t" in p:
        p = p.split("\t", 1)[0]
    if len(p) >= 2 and p[0] == p[-1] == '"':
        p = p[1:-1]
    return p.strip()


def parse_patch(patch: str) -> List[FilePatch]:
    text = norm_newlines(patch).strip("\n")
    if not text.strip():
        raise EditError("Patch is empty.")
    if "*** Begin Patch" in text or re.search(r"^\*\*\* (Update|Add|Delete) File:", text, re.M):
        return _parse_codex(text)
    if re.search(r"^--- ", text, re.M) and re.search(r"^\+\+\+ ", text, re.M):
        return _parse_unified(text)
    raise EditError("Unrecognized patch format. Use a unified diff (---/+++/@@) or '*** Begin Patch' format.")


def _parse_unified(text: str) -> List[FilePatch]:
    lines = text.split("\n")
    files, i, cur = [], 0, None
    rename_from = rename_to = None

    def header_at(k):
        return lines[k].startswith("--- ") and k + 1 < len(lines) and lines[k + 1].startswith("+++ ")

    while i < len(lines):
        ln = lines[i]
        if ln.startswith("diff --git"):
            rename_from = rename_to = None
            i += 1
            continue
        if ln.startswith("rename from "):
            rename_from = ln[12:].strip()
        if ln.startswith("rename to "):
            rename_to = ln[10:].strip()
            if rename_from and (i + 1 >= len(lines) or not header_at(i + 1)):
                files.append(FilePatch("update", rename_from, rename_to))
        if header_at(i):
            a, b = _clean_path(lines[i][4:]), _clean_path(lines[i + 1][4:])
            # git prefixes: "a/x" "b/x", also with one side /dev/null (new / deleted file)
            if (a.startswith("a/") or a == "/dev/null") and (b.startswith("b/") or b == "/dev/null"):
                a = a[2:] if a.startswith("a/") else a
                b = b[2:] if b.startswith("b/") else b
            if a == "/dev/null":
                cur = FilePatch("add", b)
            elif b == "/dev/null":
                cur = FilePatch("delete", a)
            else:
                cur = FilePatch("update", a, b if b != a else "")
            files.append(cur)
            i += 2
            continue
        if ln.startswith("@@") and cur is not None:
            m = _HUNK_RE.match(ln)
            h = Hunk([], [], hint=int(m.group(1)) if m else 0)
            i += 1
            while i < len(lines):
                b = lines[i]
                if b.startswith("@@") or b.startswith("diff --git") or header_at(i):
                    break
                if b.startswith("\\"):
                    if h.new and (i > 0 and not lines[i - 1].startswith("-")):
                        h.no_eol_new = True
                    i += 1
                    continue
                if b == "":
                    h.old.append("")
                    h.new.append("")
                elif b[0] == " ":
                    h.old.append(b[1:])
                    h.new.append(b[1:])
                elif b[0] == "-":
                    h.old.append(b[1:])
                elif b[0] == "+":
                    h.new.append(b[1:])
                else:
                    break
                i += 1
            if cur.kind == "add":
                cur.content += "\n".join(h.new) + ("" if h.no_eol_new else "\n")
            else:
                cur.hunks.append(h)
            continue
        i += 1
    if not files:
        raise EditError("No file sections found in the unified diff.")
    return files


def _parse_codex(text: str) -> List[FilePatch]:
    lines = text.split("\n")
    files, cur, h = [], None, None
    for ln in lines:
        if ln.startswith("*** Begin Patch") or ln.startswith("*** End Patch"):
            continue
        if ln.startswith("*** Add File:"):
            cur, h = FilePatch("add", ln.split(":", 1)[1].strip()), None
            files.append(cur)
            continue
        if ln.startswith("*** Delete File:"):
            cur, h = FilePatch("delete", ln.split(":", 1)[1].strip()), None
            files.append(cur)
            continue
        if ln.startswith("*** Update File:"):
            cur, h = FilePatch("update", ln.split(":", 1)[1].strip()), None
            files.append(cur)
            continue
        if ln.startswith("*** Move to:") and cur is not None:
            cur.new_path = ln.split(":", 1)[1].strip()
            continue
        if ln.startswith("*** End of File"):
            continue
        if cur is None:
            continue
        if cur.kind == "add":
            cur.content += (ln[1:] if ln.startswith("+") else ln) + "\n"
            continue
        if cur.kind == "delete":
            continue
        if ln.startswith("@@"):
            h = Hunk([], [], anchor=ln[2:].strip().strip("@").strip())
            cur.hunks.append(h)
            continue
        if h is None:
            h = Hunk([], [])
            cur.hunks.append(h)
        if ln == "":
            h.old.append("")
            h.new.append("")
        elif ln[0] == " ":
            h.old.append(ln[1:])
            h.new.append(ln[1:])
        elif ln[0] == "-":
            h.old.append(ln[1:])
        elif ln[0] == "+":
            h.new.append(ln[1:])
        else:  # tolerate context lines without the leading space
            h.old.append(ln)
            h.new.append(ln)
    if not files:
        raise EditError("No '*** Update/Add/Delete File:' sections found.")
    return files


def _trim_hunk(h: Hunk) -> Hunk:
    # drop trailing blank context lines models often append
    while h.old and h.new and h.old[-1] == "" and h.new[-1] == "" and len(h.old) > 1:
        h.old.pop()
        h.new.pop()
    return h


def apply_hunks(text: str, hunks: List[Hunk], path: str) -> EditResult:
    res = EditResult(text)
    shift = 0
    for idx, h in enumerate(hunks, 1):
        h = _trim_hunk(h)
        cur = res.text
        lines_now = cur.split("\n")
        near = (h.hint + shift) if h.hint else 0
        if h.anchor:
            target = h.anchor.strip()
            for k, l in enumerate(lines_now):
                if l.strip() == target or (target and target in l):
                    near = k + 2
                    break
        if not any(x.strip() for x in h.old):
            if not h.new:
                continue
            pos = near or (h.hint + shift + 1 if h.hint else 0)
            if not pos:
                raise EditError(f"{path}: hunk {idx} has no context lines and no line number; cannot place it.")
            ins = "\n".join(h.new) + "\n"
            body = cur if cur.endswith("\n") or not cur else cur + "\n"
            res.text = replace_lines(body, pos, pos - 1, ins)
            res.notes.append(f"hunk {idx}: inserted at line {pos}")
            shift += len(h.new)
            continue
        old = "\n".join(h.old) + "\n"
        new = "\n".join(h.new) + ("" if h.no_eol_new else "\n")
        if not h.new:
            new = ""
        if old == new:
            res.notes.append(f"hunk {idx}: context only, skipped")
            continue
        try:
            out, note, w = apply_one(cur, old, new, 1, near)
        except EditError as e:
            raise EditError(f"{path}: hunk {idx}/{len(hunks)} failed: {e}") from None
        res.text = out
        res.notes.append(f"hunk {idx}: {note}")
        res.warnings += w
        shift += len(h.new) - len(h.old)
    return res
