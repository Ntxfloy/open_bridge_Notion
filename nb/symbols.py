"""Lightweight symbol tools (Serena-style, no language server): Python via ast, LaTeX/Markdown outlines."""
import ast
import re
import textwrap

_cache = {}  # path -> (mtime_ns, size, symbols)


class SymbolError(Exception):
    pass


def _sig(node) -> str:
    if isinstance(node, ast.ClassDef):
        bases = ", ".join(ast.unparse(b) for b in node.bases)
        return f"class {node.name}({bases})" if bases else f"class {node.name}"
    pre = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    ret = f" -> {ast.unparse(node.returns)}" if node.returns is not None else ""
    return f"{pre} {node.name}({ast.unparse(node.args)}){ret}"


def python_symbols(text: str):
    """List of dicts: name (dotted), kind, start (incl. decorators), end, sig, col, depth."""
    tree = ast.parse(text)
    out = []

    def walk(body, prefix, depth):
        for n in body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                start = min([n.lineno] + [d.lineno for d in n.decorator_list])
                name = f"{prefix}{n.name}"
                kind = "class" if isinstance(n, ast.ClassDef) else ("method" if prefix else "function")
                out.append({"name": name, "kind": kind, "start": start, "end": n.end_lineno, "sig": _sig(n),
                            "col": n.col_offset, "depth": depth, "doc": (ast.get_docstring(n) or "").split("\n")[0][:100]})
                walk(n.body, name + ".", depth + 1)
            elif isinstance(n, (ast.Assign, ast.AnnAssign)) and depth == 0:
                targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                for t in targets:
                    if isinstance(t, ast.Name) and (t.id.isupper() or depth == 0):
                        out.append({"name": t.id, "kind": "variable", "start": n.lineno, "end": n.end_lineno,
                                    "sig": t.id, "col": 0, "depth": 0, "doc": ""})
    walk(tree.body, "", 0)
    return out


_TEX_SEC = re.compile(r"^\s*\\(part|chapter|section|subsection|subsubsection|paragraph)\*?\s*(?:\[[^\]]*\])?\s*\{((?:[^{}]|\{[^{}]*\})*)\}")
_TEX_LBL = re.compile(r"\\label\{([^}]*)\}")
_TEX_INC = re.compile(r"^\s*\\(input|include|subfile)\{([^}]*)\}")
_TEX_ENV = re.compile(r"\\begin\{(figure|table|equation|align)\*?\}")
_TEX_LEVEL = {"part": 0, "chapter": 1, "section": 2, "subsection": 3, "subsubsection": 4, "paragraph": 5}


def tex_outline(text: str) -> str:
    out = []
    for i, line in enumerate(text.split("\n"), 1):
        s = line.split("%", 1)[0] if "\\%" not in line else line
        m = _TEX_SEC.match(s)
        if m:
            out.append(f"L{i:<5} " + "  " * _TEX_LEVEL[m.group(1)] + f"\\{m.group(1)} {m.group(2).strip()}")
            for lb in _TEX_LBL.findall(s):
                out.append(f"L{i:<5}     label: {lb}")
            continue
        m = _TEX_INC.match(s)
        if m:
            out.append(f"L{i:<5}   \\{m.group(1)}{{{m.group(2)}}}")
        m = _TEX_ENV.search(s)
        if m:
            out.append(f"L{i:<5}   [{m.group(1)}]")
        for lb in _TEX_LBL.findall(s):
            out.append(f"L{i:<5}     label: {lb}")
    return "\n".join(out) or "(no sections found)"


def md_outline(text: str) -> str:
    out, fence = [], False
    for i, line in enumerate(text.split("\n"), 1):
        if line.lstrip().startswith(("```", "~~~")):
            fence = not fence
        m = re.match(r"^(#{1,6})\s+(.*)", line)
        if m and not fence:
            out.append(f"L{i:<5} " + "  " * (len(m.group(1)) - 1) + m.group(2).strip())
    return "\n".join(out) or "(no headings found)"


def python_outline(text: str) -> str:
    try:
        syms = python_symbols(text)
    except SyntaxError as e:
        raise SymbolError(f"Python syntax error at line {e.lineno}: {e.msg}")
    lines = []
    for s in syms:
        rng = f"L{s['start']}-{s['end']}"
        doc = f"  # {s['doc']}" if s["doc"] else ""
        lines.append(f"{rng:<12}" + "  " * s["depth"] + s["sig"] + doc)
    return "\n".join(lines) or "(no top-level symbols)"


def find_in_text(text: str, name: str):
    syms = python_symbols(text)
    exact = [s for s in syms if s["name"] == name]
    if exact:
        return exact
    return [s for s in syms if s["name"].split(".")[-1] == name.split(".")[-1] and s["name"].endswith(name)]


def replace_symbol_text(text: str, name: str, new_code: str) -> tuple:
    try:
        matches = find_in_text(text, name)
    except SyntaxError as e:
        raise SymbolError(f"File does not parse (line {e.lineno}: {e.msg}); use edit_file instead.")
    matches = [m for m in matches if m["kind"] != "variable"]
    if not matches:
        raise SymbolError(f"Symbol {name!r} not found. Use get_outline to list symbols.")
    if len(matches) > 1:
        raise SymbolError(f"{name!r} is ambiguous: " + ", ".join(f"{m['name']} (L{m['start']})" for m in matches) + ". Use the dotted name, e.g. Class.method.")
    m = matches[0]
    lines = text.split("\n")
    indent = re.match(r"[ \t]*", lines[m["start"] - 1]).group(0)
    body = textwrap.dedent(new_code.replace("\r\n", "\n")).strip("\n")
    body = "\n".join((indent + l) if l.strip() else "" for l in body.split("\n"))
    new_lines = lines[: m["start"] - 1] + body.split("\n") + lines[m["end"]:]
    new_text = "\n".join(new_lines)
    try:
        ast.parse(new_text)
    except SyntaxError as e:
        raise SymbolError(f"Refused: the result would not parse (line {e.lineno}: {e.msg}). Nothing was written.")
    return new_text, m


def syntax_warning(path_suffix: str, old: str, new: str) -> str:
    """Return a warning if an edit broke the syntax of a previously valid .py/.json file."""
    suf = path_suffix.lower()
    try:
        if suf in (".py", ".pyw"):
            try:
                ast.parse(old)
            except SyntaxError:
                return ""
            try:
                ast.parse(new)
            except SyntaxError as e:
                return f"WARNING: Python syntax error after edit at line {e.lineno}: {e.msg}"
        elif suf in (".json", ".ipynb"):
            import json
            try:
                json.loads(old)
            except ValueError:
                return ""
            try:
                json.loads(new)
            except ValueError as e:
                return f"WARNING: invalid JSON after edit: {e}"
    except Exception:
        return ""
    return ""
