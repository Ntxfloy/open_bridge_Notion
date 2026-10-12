"""Lossless text I/O: encoding + BOM + newline detection, atomic writes.

Guarantee: read -> edit -> write keeps every untouched byte identical
(same encoding, same BOM, same line-ending style). Internally text uses "\n".
"""
import hashlib
import os
import stat
import re
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from nb import runtime

BINARY_SNIFF = 8192
MAX_TEXT_BYTES = 64 * 1024 * 1024
_SURROGATES = re.compile(r"[\ud800-\udfff]")
CRLF_EXTS = {".bat", ".cmd"}

BOMS = [
    (b"\xef\xbb\xbf", "utf-8"),
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
]


class TextDecodeError(Exception):
    pass


@dataclass
class TextDoc:
    text: str          # "\n" newlines
    encoding: str      # codec used for the body (without BOM)
    bom: bytes
    newline: str       # "\n" or "\r\n"
    mixed: bool        # file had mixed line endings
    trailing_nl: bool
    raw: bytes

    @property
    def version(self) -> str:
        return version_of(self.raw)

    @property
    def label(self) -> str:
        enc = self.encoding + ("+BOM" if self.bom else "")
        nl = "CRLF" if self.newline == "\r\n" else "LF"
        return f"{enc}, {nl}{' (mixed)' if self.mixed else ''}"


def version_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_binary(data: bytes) -> bool:
    head = data[:BINARY_SNIFF]
    for bom, _ in BOMS:
        if head.startswith(bom):
            return False
    if b"\x00" in head:
        return True
    if not head:
        return False
    ctrl = sum(1 for b in head if b < 32 and b not in (9, 10, 12, 13, 27, 8))
    return ctrl / len(head) > 0.10


def _codec_ok(name: str) -> bool:
    import codecs
    try:
        codecs.lookup(name)
        return True
    except LookupError:
        return False


def decode(data: bytes, prefer: str = ""):
    """Return (text, encoding, bom). Text may contain lone surrogates for undecodable bytes (utf-8 only)."""
    for bom, enc in BOMS:
        if data.startswith(bom):
            body = data[len(bom):]
            try:
                return body.decode(enc), enc, bom
            except UnicodeDecodeError:
                return body.decode(enc, errors="surrogatepass" if enc.startswith("utf-16") else "replace"), enc, bom
    if prefer and _codec_ok(prefer):
        try:
            return data.decode(prefer), prefer, b""
        except UnicodeDecodeError:
            pass
    try:
        return data.decode("utf-8"), "utf-8", b""
    except UnicodeDecodeError:
        pass
    # Mostly-UTF-8 with a few broken bytes: keep UTF-8, lossless via surrogateescape.
    loose = data.decode("utf-8", errors="surrogateescape")
    bad = len(_SURROGATES.findall(loose))
    good_non_ascii = sum(1 for ch in loose if ord(ch) > 127) - bad
    if good_non_ascii > 0 and bad <= max(2, good_non_ascii // 100):
        return loose, "utf-8", b""
    for enc in runtime.config.get("fallback_encodings") or ["cp1251"]:
        if not _codec_ok(enc):
            continue
        try:
            return data.decode(enc), enc, b""
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1"), "latin-1", b""  # always lossless


def detect_newline(text: str):
    crlf = text.count("\r\n")
    lf = text.count("\n") - crlf
    if crlf and not lf:
        return "\r\n", False
    if lf and not crlf:
        return "\n", False
    if not crlf and not lf:
        return None, False
    return ("\r\n" if crlf > lf else "\n"), True


def read_doc(path: Path, max_bytes: int = MAX_TEXT_BYTES) -> TextDoc:
    size = path.stat().st_size
    if size > max_bytes:
        raise TextDecodeError(f"File is too large for text operations ({size} bytes > {max_bytes}).")
    data = path.read_bytes()
    return doc_from_bytes(data, path)


def doc_from_bytes(data: bytes, path: Path = None) -> TextDoc:
    if is_binary(data):
        raise TextDecodeError("Binary file (contains NUL/control bytes); text operations are not possible.")
    text, enc, bom = decode(data)
    nl, mixed = detect_newline(text)
    if nl is None:
        nl = "\r\n" if (path is not None and path.suffix.lower() in CRLF_EXTS) else "\n"
    norm = text.replace("\r\n", "\n")
    return TextDoc(norm, enc, bom, nl, mixed, norm.endswith("\n"), data)


def new_doc(path: Path, encoding: str = "") -> TextDoc:
    enc = (encoding or "utf-8").lower()
    bom = b""
    if enc in ("utf-8-sig", "utf-8-bom"):
        enc, bom = "utf-8", b"\xef\xbb\xbf"
    nl = "\r\n" if path.suffix.lower() in CRLF_EXTS else "\n"
    return TextDoc("", enc, bom, nl, False, False, b"")


def encode(doc: TextDoc, text: str, encoding: str = "") -> bytes:
    """Encode normalized text using the doc's (or an overriding) encoding/BOM/newline."""
    enc, bom = doc.encoding, doc.bom
    if encoding:
        e = encoding.lower()
        if e in ("utf-8-sig", "utf-8-bom"):
            enc, bom = "utf-8", b"\xef\xbb\xbf"
        elif e in ("utf-8", "utf8"):
            enc, bom = "utf-8", b""
        else:
            if not _codec_ok(e):
                raise ValueError(f"Unknown encoding {encoding!r}")
            enc, bom = e, b""
    body = text.replace("\r\n", "\n")
    if doc.newline == "\r\n":
        body = body.replace("\n", "\r\n")
    errors = "surrogateescape" if enc == "utf-8" else ("surrogatepass" if enc.startswith("utf-16") else "strict")
    try:
        return bom + body.encode(enc, errors=errors)
    except UnicodeEncodeError as e:
        bad = sorted({ch for ch in body if not _encodable(ch, enc)})[:10]
        raise ValueError(
            f"The file is {enc}; these characters cannot be stored in it: {' '.join(repr(c) for c in bad)}. "
            f"Replace them, or pass encoding='utf-8' to convert the file to UTF-8.") from e


def _encodable(ch, enc):
    try:
        ch.encode(enc)
        return True
    except UnicodeEncodeError:
        return False


def for_display(text: str) -> str:
    """Make text JSON-safe (lone surrogates from undecodable bytes -> U+FFFD)."""
    return _SURROGATES.sub("\ufffd", text)


def atomic_write(path: Path, data: bytes) -> None:
    """Write via temp file + os.replace (retries for Windows sharing violations)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not os.access(str(path), os.W_OK):
        raise PermissionError(f"File is read-only: {path.name}")
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name[:40]}.", suffix=".nbtmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if path.exists():
            try:
                import shutil
                shutil.copymode(str(path), tmp)
            except OSError:
                pass
        last = None
        for attempt in range(7):
            try:
                os.replace(tmp, str(path))
                return
            except PermissionError as e:  # file opened by another program (antivirus, editor indexer)
                last = e
                time.sleep(0.05 * (2 ** attempt))
        # Last resort: in-place overwrite (a backup was already taken by the caller).
        try:
            with open(path, "r+b") as f:
                f.write(data)
                f.truncate()
            os.unlink(tmp)
            return
        except OSError:
            raise PermissionError(f"Cannot replace {path.name}: it is locked by another program ({last}).")
    except BaseException:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------- deleting on Windows
# RemoveDirectory/DeleteFile fail with "Access is denied" (WinError 5) when the item has the ReadOnly
# attribute (common for folders copied from Program Files) or while an antivirus / indexer briefly holds it.
def is_link_like(p) -> bool:
    """Symlink, junction or other reparse point - never descend into it."""
    try:
        st = os.lstat(str(p))
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    return bool(getattr(st, "st_file_attributes", 0) & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT


def _retry(fn, p):
    last = None
    for attempt in range(6):
        try:
            return fn(str(p))
        except FileNotFoundError:
            return None
        except PermissionError as e:
            last = e
            try:
                os.chmod(str(p), stat.S_IWRITE | stat.S_IREAD)  # clears the ReadOnly attribute on Windows
            except OSError:
                pass
            time.sleep(0.05 * (attempt + 1))
    raise last


def remove_file(p):
    _retry(os.unlink, p)


def remove_dir(p):
    """Remove an EMPTY folder (or a directory symlink/junction itself, never its target)."""
    _retry(os.rmdir, p)
