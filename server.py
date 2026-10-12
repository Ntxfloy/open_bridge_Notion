"""Open Notion Bridge 2.0 - local MCP server for Notion AI (custom MCP connection).

Two HTTP servers run in one event loop:
  * MCP endpoint   127.0.0.1:<mcp_port>  (/mcp = Streamable HTTP, /sse = legacy SSE).
    The tunnel (cloudflared / pinggy / ngrok / named) forwards the public URL here. Every request needs
    "Authorization: Bearer <token>"; Host and Origin are validated (DNS-rebinding protection).
  * Dashboard      127.0.0.1:<dashboard_port>  - local UI, never tunneled, guarded by a per-start key.
"""
import sys

if sys.version_info < (3, 10):
    sys.stderr.write("Open Notion Bridge needs Python 3.10 or newer (found %s).\n" % sys.version.split()[0])
    sys.exit(1)

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(errors="replace")
    except Exception:
        pass


def _check_mcp():
    try:
        from importlib.metadata import version
        v = version("mcp")
    except Exception:
        v = None
    msg = None
    if v is None:
        msg = "Python package 'mcp' is not installed."
    else:
        try:
            parts = tuple(int(x) for x in v.split(".")[:2])
        except ValueError:
            parts = (1, 99)
        if parts >= (2, 0):
            msg = "mcp %s is installed, but this bridge needs mcp 1.x (in 2.x FastMCP was removed/renamed)." % v
        elif parts < (1, 22):
            msg = "mcp %s is too old, need >= 1.22." % v
    if msg:
        sys.stderr.write(msg + "\nFix:  python -m pip install -r requirements.txt --upgrade\n"
                         "      (requirements.txt pins mcp>=1.22,<2)\n")
        sys.exit(1)


_check_mcp()

import asyncio
import contextlib
import os
import hmac
import shutil
import signal
import socket
import time
from collections import defaultdict, deque
from pathlib import Path

import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

import config_manager
from nb import __version__, activity, approvals, history, procs, runtime, tools
from nb.dashboard import build as build_dashboard
from nb.tunnel import TunnelManager

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
STATIC_DIR = BASE_DIR / "static"
# bundled cloudflared.exe / rg.exe: next to the app folder (Notion PC layout) or inside it (git clone layout)
BIN_DIR = next((d for d in (ROOT_DIR / "resources" / "bin", BASE_DIR / "resources" / "bin", BASE_DIR / "bin") if d.is_dir()),
               ROOT_DIR / "resources" / "bin")
os.environ["NB_BIN_DIR"] = str(BIN_DIR)
IS_WIN = sys.platform == "win32"

INSTRUCTIONS = """\
Open Notion Bridge gives you access to folders on the user's computer (workspaces).
- Call get_status first: it shows the workspaces (aliases), the security mode and the available tools.
- Paths are relative to the default workspace, or "@alias/path" for another workspace.
- Read before editing. Prefer edit_file (exact old_text -> new_text, unique match) or apply_patch for
  multi-file changes; use write_file only for new files or full rewrites. Never put placeholders such as
  "... rest of code ..." into files.
- Every change is backed up: list_changes shows them, undo_change reverts them.
- run_command runs in the real shell of the user's computer (not a sandbox). Long-running servers/watchers:
  start_process + read_process_output. Dangerous commands may wait for the user's approval in the dashboard.
- Secret files (.env, keys, credentials) are hidden on purpose; do not try to work around it.
"""

LOOPBACK = {"127.0.0.1", "::1", "localhost"}


# ============================================================== MCP guard
class McpGuard:
    """Pure ASGI (never buffers bodies, so SSE/streaming keeps working).

    - Host allowlist (DNS rebinding): loopback:<port>, tunnel hostname, public_url host, allowed_hosts.
    - Origin: absent (server-to-server, Notion) or in allowed_origins / own public origin.
    - Bearer token only via the Authorization header, constant-time compare. No ?token= in URLs (they leak
      into logs / history).
    - Rate limit of failed auth per client IP -> 429.
    - Drops late/duplicate ASGI messages (FastMCP SSE sends an extra Response after the stream ends).
    """
    MAX_FAILS = 10
    WINDOW = 300

    def __init__(self, app, port: int, tunnel):
        self.app, self.port, self.tunnel = app, port, tunnel
        self.fails = defaultdict(deque)

    def _hosts(self):
        h = {f"127.0.0.1:{self.port}", f"localhost:{self.port}", f"[::1]:{self.port}"}
        cfg = runtime.config
        for name in [self.tunnel.hostname] + list(cfg.get("allowed_hosts") or []):
            name = (name or "").strip().lower()
            if name:
                h.add(name)
                if ":" not in name:
                    h.add(name + ":443")
        return h

    def _origins(self):
        o = {f"http://127.0.0.1:{self.port}", f"http://localhost:{self.port}"}
        if self.tunnel.hostname:
            o.add("https://" + self.tunnel.hostname)
        o.update((x or "").rstrip("/").lower() for x in (runtime.config.get("allowed_origins") or []))
        return o

    def _limited(self, ip):
        q = self.fails[ip]
        now = time.time()
        while q and now - q[0] > self.WINDOW:
            q.popleft()
        return len(q) >= self.MAX_FAILS

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            return await self.app(scope, receive, send)
        if scope["type"] != "http":
            return
        state = {"started": False, "finished": False}

        async def guarded_send(message):
            t = message["type"]
            if t == "http.response.start":
                if state["started"]:
                    return
                state["started"] = True
            elif t == "http.response.body":
                if state["finished"] or not state["started"]:
                    return
                if not message.get("more_body", False):
                    state["finished"] = True
            await send(message)

        hdrs = {}
        for k, v in scope.get("headers") or []:
            hdrs[k.lower()] = v.decode("latin-1")
        peer = (scope.get("client") or ("",))[0]
        ip = peer
        if peer in LOOPBACK:  # behind our own tunnel: real client address comes from the proxy
            ip = hdrs.get(b"cf-connecting-ip") or (hdrs.get(b"x-forwarded-for", "").split(",")[0].strip()) or peer
        path = scope.get("path", "")

        def reply(code, text, extra=None):
            resp = PlainTextResponse(text, status_code=code, headers=extra or {})
            return resp(scope, receive, guarded_send)

        if path == "/healthz":
            return await reply(200, "ok")

        host = hdrs.get(b"host", "").lower()
        if host not in self._hosts():
            activity.log("Blocked", f"Invalid Host header {host[:80]!r} on {path}", status="blocked", client=ip)
            return await reply(421, "Invalid Host header")
        origin = hdrs.get(b"origin")
        if origin and origin.rstrip("/").lower() not in self._origins():
            activity.log("Blocked", f"Origin {origin[:80]!r} not allowed", status="blocked", client=ip)
            return await reply(403, "Origin not allowed")
        if scope.get("method") == "OPTIONS":
            return await reply(204, "")
        if self._limited(ip):
            return await reply(429, "Too many failed authentication attempts. Try again later.", {"Retry-After": "300"})

        token = (runtime.config.get("token") or "").strip()
        auth = hdrs.get(b"authorization", "").strip()
        given = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
        if not token or not given or not hmac.compare_digest(given.encode(), token.encode()):
            self.fails[ip].append(time.time())
            why = "no Authorization header" if not auth else "wrong token"
            activity.log("Auth failed", f"{why} on {path}", status="blocked", client=ip)
            return await reply(401, "Unauthorized", {"WWW-Authenticate": 'Bearer realm="open-notion-bridge"'})
        self.fails.pop(ip, None)

        tok = runtime.client_ip.set(ip)
        try:
            await self.app(scope, receive, guarded_send)
        except RuntimeError as e:
            if "ASGI message" not in str(e):
                raise
        finally:
            runtime.client_ip.reset(tok)


# ============================================================== app assembly
def build_mcp(hist, tunnel, rg_path):
    cfg = runtime.config
    mcp = FastMCP(
        name="OpenNotionBridge",
        instructions=INSTRUCTIONS,
        host="127.0.0.1",
        port=cfg["mcp_port"],
        stateless_http=bool(cfg.get("stateless_http", True)),
        json_response=bool(cfg.get("json_response", False)),
        streamable_http_path="/mcp",
        sse_path="/sse",
        message_path="/messages/",
        log_level="WARNING",
        # Host/Origin checks are done by McpGuard (it knows the dynamic tunnel hostname).
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    n = tools.register(mcp, hist, tunnel, rg_path)
    return mcp, n


def build_mcp_app(mcp, tunnel):
    http_app = mcp.streamable_http_app()
    sse_app = mcp.sse_app()

    async def health(request):
        return JSONResponse({"ok": True, "version": __version__})

    routes = list(http_app.routes) + list(sse_app.routes) + [Route("/healthz", health)]

    @contextlib.asynccontextmanager
    async def lifespan(app):
        async with mcp.session_manager.run():
            yield

    app = Starlette(routes=routes, lifespan=lifespan)
    return McpGuard(app, runtime.config["mcp_port"], tunnel)


def port_busy(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def find_rg() -> str:
    c = BIN_DIR / ("rg.exe" if IS_WIN else "rg")
    if c.exists():
        return str(c)
    return shutil.which("rg") or ""


def banner(cfg, n_tools, dash_url, tunnel):
    line = "=" * 64
    tok = cfg.get("token", "")
    print(line)
    print(f"  OPEN NOTION BRIDGE {__version__}  -  local MCP server for Notion AI")
    print(f"  Dashboard : {dash_url}   (token, URL and approvals are there)")
    print(f"  MCP local : http://127.0.0.1:{cfg['mcp_port']}/mcp   (legacy SSE: /sse)")
    print(f"  Mode      : {runtime.mode()}   tools: {n_tools}   tunnel: {cfg.get('tunnel_mode')}")
    print(f"  Token     : {tok[:3]}...{tok[-4:]}  (full value: dashboard -> Copy token)")
    for a, p in (cfg.get("workspaces") or {}).items():
        mark = "*" if a == cfg.get("default_workspace") else " "
        print(f"  Workspace{mark}: @{a} = {p}")
    if not cfg.get("workspaces"):
        print("  Workspace : not set - choose a folder in the dashboard")
    for w in runtime.startup_warnings:
        print("  ! " + w)
    print(line)
    sys.stdout.flush()


async def amain():
    cfg = runtime.init()
    config_manager.STATE_DIR.mkdir(parents=True, exist_ok=True)
    activity.init(config_manager.STATE_DIR)
    hist = history.History(config_manager.STATE_DIR)
    try:
        history.prune(hist)
    except Exception as e:  # never block start-up because of backups
        runtime.startup_warnings.append(f"Backup cleanup failed: {e}")

    mcp_port, dash_port = int(cfg["mcp_port"]), int(cfg["dashboard_port"])
    for p, what in ((mcp_port, "mcp_port"), (dash_port, "dashboard_port")):
        if port_busy(p):
            sys.stderr.write(f"Port {p} ({what}) is already in use - is the bridge already running? "
                             f"Close it or change {what} in config.json.\n")
            return 2

    tunnel = TunnelManager(mcp_port, BIN_DIR, BASE_DIR / "tunnel.log")
    rg = find_rg()
    mcp, n_tools = build_mcp(hist, tunnel, rg)
    mcp_app = build_mcp_app(mcp, tunnel)
    dash_app, _key = build_dashboard(tunnel, hist, mcp_port, dash_port, STATIC_DIR)
    dash_url = f"http://127.0.0.1:{dash_port}"
    approvals.dashboard_url = dash_url

    common = dict(log_level="warning", proxy_headers=False, server_header=False, date_header=False,
                  timeout_graceful_shutdown=3)
    s_mcp = uvicorn.Server(uvicorn.Config(mcp_app, host="127.0.0.1", port=mcp_port, **common))
    s_dash = uvicorn.Server(uvicorn.Config(dash_app, host="127.0.0.1", port=dash_port, **common))
    # Our own signal handling: uvicorn's would re-raise SIGINT/SIGTERM after serve() and kill the process
    # before the cleanup below (tunnel / background processes) runs.
    for srv in (s_mcp, s_dash):
        srv.install_signal_handlers = lambda: None
        if hasattr(srv, "capture_signals"):
            srv.capture_signals = contextlib.nullcontext

    def _request_stop(*_):
        if s_mcp.should_exit:          # second Ctrl+C: stop right now
            s_mcp.force_exit = s_dash.force_exit = True
        s_mcp.should_exit = s_dash.should_exit = True

    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is not None:
            with contextlib.suppress(Exception):
                signal.signal(sig, _request_stop)

    banner(cfg, n_tools, dash_url, tunnel)
    activity.log("Bridge started", f"v{__version__}, mode {runtime.mode()}, {n_tools} tools")
    tunnel.start()
    if cfg.get("open_dashboard_on_start"):
        try:
            import webbrowser
            asyncio.get_running_loop().call_later(1.5, webbrowser.open, dash_url)
        except Exception:
            pass

    t_dash = asyncio.create_task(s_dash.serve())
    try:
        await s_mcp.serve()
    finally:
        s_dash.should_exit = True
        with contextlib.suppress(Exception):
            await asyncio.wait_for(t_dash, 5)
        with contextlib.suppress(Exception):
            tunnel.stop()
        with contextlib.suppress(Exception):
            procs.stop_all()
        activity.log("Bridge stopped", "tunnel and background processes stopped")
    return 0


def main():
    try:
        code = asyncio.run(amain())
    except KeyboardInterrupt:
        code = 0
    sys.exit(code or 0)


if __name__ == "__main__":
    main()
