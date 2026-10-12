"""Configuration for Open Notion Bridge: defaults, validation, migration, atomic save.

Design rules
- Fail closed: unknown mode -> "safe"; empty/weak token -> a fresh strong token is generated.
- Unknown keys are preserved (forward compatibility), known keys are type-checked.
- config.json is written atomically (temp file + os.replace) so a crash never leaves half a file.
"""
import copy
import json
import os
import re
import secrets
import tempfile
import threading
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = Path(os.environ.get("NB_CONFIG_FILE", str(BASE_DIR / "config.json")))
STATE_DIR = Path(os.environ.get("NB_STATE_DIR", str(BASE_DIR / "state")))

VALID_MODES = ("safe", "developer", "agent")
VALID_TUNNEL_MODES = ("auto", "cloudflared", "pinggy", "named", "external", "none")
VALID_CONFIRM = ("never", "dangerous", "always")
VALID_SHELLS = ("auto", "pwsh", "powershell", "cmd", "bash", "sh")

MIN_TOKEN_LEN = 32
_WEAK_MARKERS = ("CHANGE-ME", "CHANGEME", "CHANGE_ME", "EXAMPLE", "YOUR_TOKEN", "TOKEN_HERE", "PASTE")

# Secrets that file tools must never read or write (gitignore-like globs, case-insensitive).
# A pattern without "/" matches any path component; with "/" it matches the relative path.
DEFAULT_DENY_GLOBS = [
    ".env", ".env.*", "*.env",
    ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker",
    "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*",
    "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.kdbx", "*.ovpn",
    ".git-credentials", ".netrc", "_netrc", ".npmrc", ".pypirc", ".pgpass",
    "credentials.json", "client_secret*.json", "service-account*.json", "*.tfstate",
    ".git/config",
]
DEFAULT_DENY_ALLOW = [".env.example", ".env.sample", ".env.template", ".env.dist", "*.pub"]

_lock = threading.RLock()


def new_token() -> str:
    return "nb_" + secrets.token_urlsafe(32)


def token_is_weak(token) -> bool:
    if not isinstance(token, str):
        return True
    t = token.strip()
    if len(t) < MIN_TOKEN_LEN:
        return True
    up = t.upper()
    if any(m in up for m in _WEAK_MARKERS):
        return True
    if len(set(t)) < 10:  # "aaaaaaaa..." style
        return True
    return False


def default_config() -> dict:
    return {
        "dashboard_port": 8766,      # local web UI, loopback only, never tunneled
        "mcp_port": 8767,            # MCP endpoint (/mcp, legacy /sse); the tunnel points here
        "token": "",                 # generated on first start
        "mode": "developer",         # safe | developer | agent
        "workspaces": {},            # alias -> absolute folder path
        "default_workspace": "",
        "tunnel_mode": "auto",       # auto | cloudflared | pinggy | named | external | none
        "cloudflare_tunnel_token": "",
        "public_url": "",            # for named/external tunnels, e.g. https://pc.example.com
        "allowed_hosts": [],         # extra Host headers accepted on the MCP port
        "allowed_origins": [],       # browser Origins accepted on the MCP port (normally none)
        "stateless_http": True,
        "json_response": False,
        "shell": "auto",
        "confirm_commands": "dangerous",
        "approval_timeout_sec": 50,   # MCP clients (Notion) time out a call after ~60 s
        "scrub_env": True,
        "deny_globs": list(DEFAULT_DENY_GLOBS),
        "deny_allow": list(DEFAULT_DENY_ALLOW),
        "extra_deny_globs": [],
        "fallback_encodings": ["cp1251"],
        "backups": {"enabled": True, "max_total_mb": 1024, "max_age_days": 30, "max_file_mb": 50},
        "disabled_tools": [],
        "open_dashboard_on_start": False,
    }


def _as_int(v, default, lo, hi):
    try:
        v = int(v)
    except (TypeError, ValueError):
        return default
    return v if lo <= v <= hi else default


def _as_str_list(v, default):
    if not isinstance(v, list):
        return list(default)
    return [str(x) for x in v if isinstance(x, (str, int, float)) and str(x).strip()]


_ALIAS_RE = re.compile(r"[^\w.-]+", re.UNICODE)


def folder_name(path: str) -> str:
    parts = [x for x in re.split(r"[\\/]+", str(path)) if x and not x.endswith(":")]
    return parts[-1] if parts else "ws"


def make_alias(name: str, taken) -> str:
    base = _ALIAS_RE.sub("-", (name or "ws").strip()).strip("-.").lower() or "ws"
    base = base[:32]
    alias, i = base, 2
    while alias in taken:
        alias = f"{base}-{i}"
        i += 1
    return alias


def validate(raw: dict):
    """Return (config, warnings, changed). Never raises on bad input."""
    warnings = []
    d = default_config()
    cfg = copy.deepcopy(raw) if isinstance(raw, dict) else {}
    changed = False

    # --- migration from v1 ("port" + "workspace" + "cors_origins") ---
    if "port" in cfg and "dashboard_port" not in cfg:
        cfg["dashboard_port"] = cfg.get("port")
        changed = True
    cfg.pop("port", None)
    if "cors_origins" in cfg:
        cfg.pop("cors_origins", None)
        warnings.append("cors_origins removed: the dashboard no longer allows cross-origin requests.")
        changed = True
    if "workspace" in cfg:
        old_ws = cfg.pop("workspace")
        wss = cfg.get("workspaces") if isinstance(cfg.get("workspaces"), dict) else {}
        if old_ws and str(old_ws) not in [str(p) for p in wss.values()]:
            alias = make_alias(folder_name(str(old_ws)), wss.keys())
            wss[alias] = str(old_ws)
            cfg.setdefault("default_workspace", alias)
        cfg["workspaces"] = wss
        changed = True

    out = {k: v for k, v in cfg.items() if k not in d}  # keep unknown keys
    out["dashboard_port"] = _as_int(cfg.get("dashboard_port"), d["dashboard_port"], 1024, 65535)
    out["mcp_port"] = _as_int(cfg.get("mcp_port"), d["mcp_port"], 1024, 65535)
    if out["mcp_port"] == out["dashboard_port"]:
        out["mcp_port"] = out["dashboard_port"] + 1
        warnings.append("mcp_port must differ from dashboard_port; using %d." % out["mcp_port"])

    token = cfg.get("token")
    if token_is_weak(token):
        if token:
            warnings.append("Token was empty, too short or an example value: a new token was generated. Update it in Notion.")
        out["token"] = new_token()
        changed = True
    else:
        out["token"] = token.strip()

    mode = cfg.get("mode", d["mode"])
    if mode not in VALID_MODES:
        warnings.append(f"Unknown mode {mode!r}: falling back to 'safe' (read-only).")
        mode = "safe"
        changed = True
    out["mode"] = mode

    wss = cfg.get("workspaces")
    clean = {}
    if isinstance(wss, dict):
        for alias, p in wss.items():
            if not isinstance(p, str) or not p.strip():
                continue
            a = make_alias(str(alias), clean.keys()) if _ALIAS_RE.search(str(alias)) or not str(alias) else str(alias)
            clean[a] = p.strip()
    if not clean:
        home_docs = Path.home() / "Documents"
        clean["main"] = str(home_docs if home_docs.is_dir() else Path.home() / "OpenBridgeWorkspace")
        warnings.append(f"No workspace configured: using {clean['main']}. Choose a project folder in the dashboard.")
        changed = True
    out["workspaces"] = clean
    dw = cfg.get("default_workspace")
    out["default_workspace"] = dw if dw in clean else next(iter(clean))

    tm = str(cfg.get("tunnel_mode", d["tunnel_mode"])).lower()
    out["tunnel_mode"] = tm if tm in VALID_TUNNEL_MODES else "auto"
    out.pop("auto_fallback_pinggy", None)  # 2.0.0 had it opt-in by mistake; fallback is always on in auto
    out["cloudflare_tunnel_token"] = str(cfg.get("cloudflare_tunnel_token") or "")
    out["public_url"] = str(cfg.get("public_url") or "").rstrip("/")
    out["allowed_hosts"] = _as_str_list(cfg.get("allowed_hosts"), [])
    out["allowed_origins"] = _as_str_list(cfg.get("allowed_origins"), [])
    out["stateless_http"] = bool(cfg.get("stateless_http", d["stateless_http"]))
    out["json_response"] = bool(cfg.get("json_response", d["json_response"]))
    sh = str(cfg.get("shell", "auto")).lower()
    out["shell"] = sh if sh in VALID_SHELLS else "auto"
    cc = str(cfg.get("confirm_commands", d["confirm_commands"])).lower()
    out["confirm_commands"] = cc if cc in VALID_CONFIRM else "dangerous"
    ats = cfg.get("approval_timeout_sec")
    if ats == 180:  # 2.0.0 default was longer than the client's own timeout -> the call failed with "Request timed out"
        ats = d["approval_timeout_sec"]
    out["approval_timeout_sec"] = _as_int(ats, d["approval_timeout_sec"], 10, 3600)
    out["scrub_env"] = bool(cfg.get("scrub_env", True))
    out["deny_globs"] = _as_str_list(cfg.get("deny_globs"), d["deny_globs"])
    out["deny_allow"] = _as_str_list(cfg.get("deny_allow"), d["deny_allow"])
    out["extra_deny_globs"] = _as_str_list(cfg.get("extra_deny_globs"), [])
    out["fallback_encodings"] = _as_str_list(cfg.get("fallback_encodings"), d["fallback_encodings"])
    b = cfg.get("backups") if isinstance(cfg.get("backups"), dict) else {}
    out["backups"] = {
        "enabled": bool(b.get("enabled", True)),
        "max_total_mb": _as_int(b.get("max_total_mb"), 1024, 10, 1_000_000),
        "max_age_days": _as_int(b.get("max_age_days"), 30, 1, 3650),
        "max_file_mb": _as_int(b.get("max_file_mb"), 50, 1, 4096),
    }
    out["disabled_tools"] = _as_str_list(cfg.get("disabled_tools"), [])
    out["open_dashboard_on_start"] = bool(cfg.get("open_dashboard_on_start", False))
    if out != raw:
        changed = changed or any(k not in raw for k in d)
    return out, warnings, changed


def load_config():
    """Return (config, warnings). Creates/repairs config.json when needed."""
    with _lock:
        raw, warnings = {}, []
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8-sig") as f:
                    raw = json.load(f)
            except Exception as e:  # corrupted file: keep a copy, start from defaults
                bad = CONFIG_FILE.with_suffix(".json.corrupt")
                try:
                    os.replace(CONFIG_FILE, bad)
                except OSError:
                    pass
                warnings.append(f"config.json was unreadable ({e}); saved as {bad.name} and recreated.")
                raw = {}
        cfg, w2, changed = validate(raw)
        warnings += w2
        if changed or not CONFIG_FILE.exists():
            save_config(cfg)
        return cfg, warnings


def save_config(cfg: dict) -> None:
    with _lock:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".config.", suffix=".tmp", dir=str(CONFIG_FILE.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, CONFIG_FILE)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
