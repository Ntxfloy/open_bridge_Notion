"""Local dashboard: separate port, loopback only, never tunneled.

Protection against "any web page can steal the token":
- Host header must be 127.0.0.1/localhost:<port>  -> blocks DNS rebinding;
- every /api call needs X-Bridge-Key (random per start, injected into the HTML). A custom header forces a CORS
  preflight that we never answer, and other origins cannot read the HTML to learn the key;
- Origin / Sec-Fetch-Site must be same-origin; requests carrying proxy headers (cf-connecting-ip,
  x-forwarded-for) are rejected, so even an accidental tunnel to this port is useless;
- CSP + X-Frame-Options against XSS/clickjacking; no CORS headers at all.
"""
import asyncio
import hmac
import os
import secrets
import shutil
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

import config_manager
from nb import __version__, activity, approvals, gitops, history, paths, procs, runtime

LOOPBACK = {"127.0.0.1", "::1", "localhost"}
PROXY_HEADERS = (b"cf-connecting-ip", b"x-forwarded-for", b"x-forwarded-host", b"forwarded", b"cf-ray", b"x-real-ip")
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
       "base-uri 'none'; form-action 'none'")
SEC_HEADERS = [(b"x-frame-options", b"DENY"), (b"x-content-type-options", b"nosniff"), (b"referrer-policy", b"no-referrer"),
               (b"content-security-policy", CSP.encode()), (b"cache-control", b"no-store"),
               (b"cross-origin-resource-policy", b"same-origin"), (b"cross-origin-opener-policy", b"same-origin")]


class LocalGuard:
    def __init__(self, app, key: str, port: int):
        self.app, self.key, self.port = app, key, port
        self.hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
        self.origins = {f"http://127.0.0.1:{port}", f"http://localhost:{port}", f"http://[::1]:{port}"}

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            return await self.app(scope, receive, send)
        if scope["type"] != "http":
            return
        hdrs = {}
        for k, v in scope.get("headers") or []:
            hdrs[k.lower()] = v.decode("latin-1")
        hdrs = {k: v for k, v in hdrs.items()}

        async def send_sec(msg):
            if msg["type"] == "http.response.start":
                msg = dict(msg)
                msg["headers"] = list(msg.get("headers") or []) + SEC_HEADERS
            await send(msg)

        def deny(code, text):
            return PlainTextResponse(text, status_code=code)(scope, receive, send_sec)

        peer = (scope.get("client") or ("",))[0]
        if peer not in LOOPBACK:
            return await deny(403, "Dashboard is local-only.")
        if any(p in hdrs for p in PROXY_HEADERS):
            return await deny(403, "Proxied requests are not allowed on the dashboard.")
        if hdrs.get(b"host", "").lower() not in self.hosts:
            return await deny(421, "Invalid Host header (DNS-rebinding protection). Open http://127.0.0.1:%d" % self.port)
        path = scope.get("path", "")
        if path.startswith("/api/"):
            origin = hdrs.get(b"origin")
            if origin and origin not in self.origins:
                return await deny(403, "Cross-origin request rejected.")
            sfs = hdrs.get(b"sec-fetch-site")
            if sfs and sfs not in ("same-origin", "none"):
                return await deny(403, "Cross-site request rejected.")
            if not hmac.compare_digest(hdrs.get(b"x-bridge-key", "").encode(), self.key.encode()):
                return await deny(401, "Missing dashboard key. Reload the page.")
            approvals.touch()
        return await self.app(scope, receive, send_sec)


def build(tunnel, hist: history.History, mcp_port: int, dash_port: int, static_dir: Path):
    key = secrets.token_urlsafe(32)

    def endpoints():
        base = tunnel.public_url
        return {
            "mcp": f"{base}/mcp" if base else None,
            "sse": f"{base}/sse" if base else None,
            "local_mcp": f"http://127.0.0.1:{mcp_port}/mcp",
            "local_sse": f"http://127.0.0.1:{mcp_port}/sse",
        }

    async def status(request: Request):
        cfg = runtime.config
        tok = cfg.get("token", "")
        warns = list(runtime.startup_warnings)
        if not tools_rg():
            warns.append("ripgrep (rg.exe) not found: search works but is slower. Put rg.exe into resources/bin.")
        if not gitops.git_exe():
            warns.append("git not found in PATH: git tools are unavailable.")
        if cfg.get("mode") == "agent":
            warns.append("Agent mode: screenshots are allowed.")
        return JSONResponse({
            "version": __version__, "mode": runtime.mode(), "caps": sorted(runtime.caps()),
            "tunnel": {"status": tunnel.status, "provider": tunnel.provider, "public_url": tunnel.public_url,
                       "last_error": tunnel.last_error, "mode": cfg.get("tunnel_mode"),
                       "has_ssh": bool(shutil.which("ssh")), "has_cloudflared": bool(tunnel.cloudflared())},
            "endpoints": endpoints(),
            "token_hint": (tok[:3] + "…" + tok[-4:]) if tok else "",
            "workspaces": [{"alias": a, "path": p, "default": a == cfg.get("default_workspace"), "exists": os.path.isdir(p)}
                           for a, p in (cfg.get("workspaces") or {}).items()],
            "confirm_commands": cfg.get("confirm_commands"),
            "shell": procs.detect_shell()[0],
            "warnings": warns,
            "pending_approvals": len(approvals.pending),
            "processes": [p.info() for p in procs.registry.values()],
        })

    async def token(request: Request):
        return JSONResponse({"token": runtime.config.get("token", "")})

    async def set_config(request: Request):
        data = await request.json()
        with runtime.lock:
            if "mode" in data:
                if data["mode"] not in config_manager.VALID_MODES:
                    return JSONResponse({"error": "invalid mode"}, status_code=400)
                runtime.config["mode"] = data["mode"]
                activity.log("Mode changed", data["mode"])
            if "confirm_commands" in data:
                if data["confirm_commands"] not in config_manager.VALID_CONFIRM:
                    return JSONResponse({"error": "invalid confirm_commands"}, status_code=400)
                runtime.config["confirm_commands"] = data["confirm_commands"]
                activity.log("Confirmation policy", data["confirm_commands"])
            restart = False
            if "tunnel_mode" in data:
                if data["tunnel_mode"] not in config_manager.VALID_TUNNEL_MODES:
                    return JSONResponse({"error": "invalid tunnel_mode"}, status_code=400)
                restart = data["tunnel_mode"] != runtime.config.get("tunnel_mode")
                runtime.config["tunnel_mode"] = data["tunnel_mode"]
                activity.log("Tunnel mode", data["tunnel_mode"])
            runtime.save()
        if restart:
            await asyncio.to_thread(tunnel.restart)
        return JSONResponse({"ok": True})

    def _pick_folder(initial):
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        sel = filedialog.askdirectory(initialdir=initial or str(Path.home()), title="Выберите папку проекта для ИИ")
        root.destroy()
        return sel

    async def workspaces(request: Request):
        data = await request.json()
        action = data.get("action")
        cfg = runtime.config
        with runtime.lock:
            wss = dict(cfg.get("workspaces") or {})
            if action in ("add", "replace_default"):
                folder = data.get("path")
                if not folder:
                    try:
                        folder = await asyncio.to_thread(_pick_folder, wss.get(cfg.get("default_workspace"), ""))
                    except Exception as e:
                        return JSONResponse({"error": f"Folder dialog failed: {e}. Enter the path manually."}, status_code=500)
                    if not folder:
                        return JSONResponse({"cancelled": True})
                try:
                    root = paths.check_workspace_root(folder)
                except paths.PathError as e:
                    return JSONResponse({"error": str(e)}, status_code=400)
                if action == "replace_default":
                    alias = cfg.get("default_workspace") or "main"
                    wss[alias] = str(root)
                else:
                    if str(root) in wss.values():
                        return JSONResponse({"error": "This folder is already a workspace."}, status_code=400)
                    alias = config_manager.make_alias(data.get("alias") or config_manager.folder_name(str(root)), wss.keys())
                    wss[alias] = str(root)
                cfg["workspaces"] = wss
                if not cfg.get("default_workspace") or cfg["default_workspace"] not in wss:
                    cfg["default_workspace"] = alias
                activity.log("Workspace", f"@{alias} = {root}")
            elif action == "remove":
                alias = data.get("alias")
                if alias not in wss:
                    return JSONResponse({"error": "unknown workspace"}, status_code=400)
                if len(wss) == 1:
                    return JSONResponse({"error": "At least one workspace is required."}, status_code=400)
                wss.pop(alias)
                cfg["workspaces"] = wss
                if cfg.get("default_workspace") == alias:
                    cfg["default_workspace"] = next(iter(wss))
                activity.log("Workspace removed", f"@{alias}")
            elif action == "default":
                alias = data.get("alias")
                if alias not in wss:
                    return JSONResponse({"error": "unknown workspace"}, status_code=400)
                cfg["default_workspace"] = alias
                activity.log("Default workspace", f"@{alias}")
            else:
                return JSONResponse({"error": "unknown action"}, status_code=400)
            runtime.save()
        return JSONResponse({"ok": True})

    async def activity_feed(request: Request):
        try:
            since = int(request.query_params.get("since", "0"))
        except ValueError:
            since = 0
        return JSONResponse({"items": activity.since(since)})

    async def approvals_list(request: Request):
        return JSONResponse({"items": approvals.listing()})

    async def approvals_decide(request: Request):
        data = await request.json()
        ok = approvals.decide(int(request.path_params["pid"]), bool(data.get("approve")))
        return JSONResponse({"ok": ok}, status_code=200 if ok else 404)

    async def changes(request: Request):
        items = []
        for b in hist.list(40):
            items.append({"id": b["id"], "ts": b["ts"], "tool": b["tool"], "summary": b["summary"],
                          "files": sorted({e["display"] for e in b["entries"]})[:8], "count": len(b["entries"]),
                          "undone_by": b.get("undone_by"), "undo_of": b.get("undo_of")})
        return JSONResponse({"items": items, "stats": hist.stats()})

    async def undo(request: Request):
        data = await request.json()
        try:
            b, nid, done, conflicts = await asyncio.to_thread(hist.undo, int(data.get("id") or 0) or None, bool(data.get("force")))
        except history.HistoryError as e:
            return JSONResponse({"error": str(e)}, status_code=409)
        activity.log("Undo (dashboard)", f"#{b['id']} -> #{nid}")
        return JSONResponse({"ok": True, "new_id": nid, "done": done})

    async def revoke(request: Request):
        with runtime.lock:
            runtime.config["token"] = config_manager.new_token()
            runtime.save()
        activity.log("Token revoked", "new Bearer token generated; update it in Notion")
        return JSONResponse({"ok": True})

    async def restart_tunnel(request: Request):
        await asyncio.to_thread(tunnel.restart)
        return JSONResponse({"ok": True, "status": tunnel.status})

    async def kill_process(request: Request):
        try:
            p = procs.bg_get(request.path_params["pid"])
        except KeyError as e:
            return JSONResponse({"error": str(e)}, status_code=404)
        await asyncio.to_thread(p.stop)
        activity.log("Process stopped (dashboard)", p.id)
        return JSONResponse({"ok": True})

    async def index(request: Request):
        f = static_dir / "index.html"
        html = f.read_text(encoding="utf-8") if f.exists() else "<h1>Open Notion Bridge</h1>"
        return HTMLResponse(html.replace("{{BRIDGE_KEY}}", key))

    async def favicon(request: Request):
        return Response(status_code=204)

    routes = [
        Route("/", index), Route("/favicon.ico", favicon),
        Route("/api/status", status), Route("/api/token", token),
        Route("/api/config", set_config, methods=["POST"]),
        Route("/api/workspaces", workspaces, methods=["POST"]),
        Route("/api/activity", activity_feed),
        Route("/api/approvals", approvals_list),
        Route("/api/approvals/{pid:int}", approvals_decide, methods=["POST"]),
        Route("/api/changes", changes),
        Route("/api/undo", undo, methods=["POST"]),
        Route("/api/revoke_token", revoke, methods=["POST"]),
        Route("/api/restart_tunnel", restart_tunnel, methods=["POST"]),
        Route("/api/processes/{pid}/kill", kill_process, methods=["POST"]),
    ]
    if static_dir.exists():
        routes.append(Mount("/static", StaticFiles(directory=str(static_dir)), name="static"))
    app = Starlette(routes=routes)
    return LocalGuard(app, key, dash_port), key


def tools_rg():
    from nb import tools
    return tools.RG
