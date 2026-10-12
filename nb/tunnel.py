"""Public tunnel to the MCP port.

Modes (config "tunnel_mode"):
  auto        - Cloudflare quick tunnel; if Cloudflare is unreachable (DNS/VPN/ISP, 429) -> SSH tunnels over port 443
                (Pinggy, then localhost.run). The provider that worked last time is tried first on the next start.
  cloudflared - quick tunnel only
  pinggy      - SSH tunnels only (Pinggy <-> localhost.run rotation)
  ngrok       - ngrok agent with your free static domain (public_url), authtoken from `ngrok config add-authtoken`
  named       - your own Cloudflare tunnel: stable URL (`cloudflared tunnel run --token ...`), set public_url
  external    - you run the tunnel yourself (Tailscale Funnel, ngrok static domain...), set public_url
  none        - local only
Online == the edge connection is registered (not merely "URL printed"), see notes in _run_once.
"""
import json
import os
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from nb import activity, procs, runtime

IS_WIN = os.name == "nt"


class TunnelManager:
    REGISTERED_RE = re.compile(r"Registered tunnel connection|Connection [0-9a-f-]+ registered", re.I)
    CF_URL_RE = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")
    SSH_URL_RE = re.compile(r"https://(?!dashboard\.|www\.)[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.(?:free\.pinggy\.net|pinggy-free\.link|pinggy\.link)", re.I)
    NGROK_READY_RE = re.compile(r'msg="?started tunnel|url=https://', re.I)
    ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
    # Lines that must never reach the log in clear text
    SECRET_RE = re.compile(r"(--token\s+|token=)[A-Za-z0-9._-]+")

    def __init__(self, port: int, bin_dir: Path, log_path: Path):
        self.port = port
        self.bin_dir = bin_dir
        self.proc: Optional[subprocess.Popen] = None
        self.tree = None
        self.public_url: Optional[str] = None
        self.status = "stopped"
        self.last_error = ""
        self.provider = ""
        self._thread = None
        self.rate_limited = False
        self._gen = 0
        self.log_path = log_path

    @property
    def hostname(self) -> str:
        u = self.public_url or runtime.config.get("public_url") or ""
        return (urlparse(u).hostname or "").lower() if u else ""

    def cloudflared(self) -> str:
        for c in (self.bin_dir / ("cloudflared.exe" if IS_WIN else "cloudflared"),):
            if c.exists():
                return str(c)
        return shutil.which("cloudflared") or ""

    def ngrok(self) -> str:
        name = "ngrok.exe" if IS_WIN else "ngrok"
        custom = (runtime.config.get("ngrok_path") or "").strip().strip('"')
        app_dir = Path(__file__).resolve().parent.parent
        cands = [Path(custom)] if custom else []
        cands += [self.bin_dir / name, app_dir / name, app_dir.parent / name, Path.home() / "ngrok" / name]
        for c in cands:
            if c.is_file():
                return str(c)
        return shutil.which("ngrok") or ""

    def _tlog(self, line: str):
        try:
            if self.log_path.exists() and self.log_path.stat().st_size > 5 * 1024 * 1024:
                os.replace(self.log_path, self.log_path.with_suffix(".log.1"))
            safe = self.SECRET_RE.sub(r"\1***", line)
            stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(self.log_path, "a", encoding="utf-8", errors="replace") as f:
                f.write(stamp + " " + safe + "\n")
        except Exception:
            pass

    def _spawn(self, cmd, stdin_pipe=False):
        kw = {"creationflags": procs.CREATE_NO_WINDOW} if IS_WIN else {"start_new_session": True}
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE if stdin_pipe else subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                             errors="replace", bufsize=1, **kw)
        self.tree = procs.ProcessTree(p, kill_on_close=True)
        return p

    def _kill_proc(self):
        p, t = self.proc, self.tree
        self.proc = None
        if p and p.poll() is None:
            try:
                p.terminate()
                p.wait(timeout=3)
            except Exception:
                pass
        if t:
            try:
                t.kill()   # whole tree (Job Object / process group): no orphaned helpers
            except Exception:
                pass
            t.close()

    def _run_once(self, gen, cmd, label, url_re, ready_re, ready_timeout, fixed_url=None) -> bool:
        """cloudflared prints the trycloudflare URL *before* it reaches the edge (port 7844). If 7844 is
        blocked it retries and exits after ~30s, so "online" means "Registered tunnel connection"."""
        self._tlog(f"=== START {label}: {' '.join(cmd)}")
        try:
            self.proc = self._spawn(cmd, stdin_pipe=label.startswith("ssh"))
        except Exception as e:
            self.last_error = f"Failed to launch {label}: {e}"
            activity.log("Tunnel", self.last_error, status="error")
            return False
        proc, started, state = self.proc, time.time(), {"online": False}
        found_url = fixed_url

        def watchdog():
            while proc.poll() is None and self._gen == gen:
                if not state["online"] and time.time() - started > ready_timeout:
                    self.last_error = f"{label}: no edge connection in {ready_timeout}s"
                    activity.log("Tunnel", self.last_error, status="error")
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    return
                time.sleep(1)
        threading.Thread(target=watchdog, daemon=True).start()

        for line in proc.stdout:
            if self._gen != gen:
                break
            line = self.ANSI_RE.sub("", line).rstrip()
            if not line:
                continue
            self._tlog(line)
            if "GetConsoleMode" in line:
                continue
            m = url_re.search(line) if url_re else None
            if m and not found_url:
                found_url = m.group(0)
            if "429" in line or "error code: 1015" in line:
                self.rate_limited = True
            if (ready_re.search(line) or (label.startswith("ssh") and found_url)) and not state["online"] and found_url:
                state["online"] = True
                self.public_url = found_url.rstrip("/")
                self.status = "online"
                self.last_error = ""
                activity.log("Tunnel", f"Online at {self.public_url} ({label})")
                if label != "ngrok":
                    self._save_pref(label.split("/", 1)[1] if label.startswith("ssh/") else "cloudflare")
            low = line.lower()
            if not state["online"] and (" err " in low or "error" in low or "failed" in low or "lvl=eror" in low or "err_ngrok" in low):
                self.last_error = self.SECRET_RE.sub(r"\1***", line[-220:])
        try:
            proc.wait(timeout=3)
        except Exception:
            pass
        if self.proc is proc:
            self.proc = None
        return state["online"]

    def _sleep(self, gen, sec) -> bool:
        for _ in range(int(sec)):
            if self._gen != gen:
                return False
            time.sleep(1)
        return True

    def _ssh_providers(self):
        null = "NUL" if IS_WIN else "/dev/null"
        common = ["ssh", "-T", "-p", "443", "-o", "StrictHostKeyChecking=no", "-o", f"UserKnownHostsFile={null}",
                  "-o", "RequestTTY=no", "-o", "LogLevel=ERROR", "-o", "ServerAliveInterval=20",
                  "-o", "ServerAliveCountMax=3", "-o", "ExitOnForwardFailure=yes"]
        return [
            ("pinggy", common + [f"-R0:127.0.0.1:{self.port}", "free.pinggy.io"]),
            ("localhost.run", common + ["-R", f"80:127.0.0.1:{self.port}", "nokey@localhost.run"]),
        ]

    # remembers which provider worked last time, so a PC where Cloudflare is blocked
    # does not wait for cloudflared to fail on every start
    def _state_file(self):
        return self.log_path.with_name("tunnel_state.json")

    def _load_pref(self):
        try:
            return json.loads(self._state_file().read_text(encoding="utf-8")).get("last_ok", "")
        except Exception:
            return ""

    def _save_pref(self, provider):
        try:
            self._state_file().write_text(json.dumps({"last_ok": provider, "ts": time.time()}), encoding="utf-8")
        except Exception:
            pass

    def _loop(self, gen):
        cfg = runtime.config
        mode = cfg.get("tunnel_mode", "auto")
        have_ssh = bool(shutil.which("ssh"))
        ssh_idx = 0
        ssh_fails = 0
        # auto: start with SSH if that is what worked last time
        cf_cooldown_until = time.time() + 1800 if (mode == "auto" and have_ssh and self._load_pref() in ("pinggy", "localhost.run")) else 0.0
        if mode == "pinggy" and not have_ssh:
            self.status, self.last_error = "error", "ssh.exe not found (Windows: Settings -> Optional features -> OpenSSH Client)"
            activity.log("Tunnel", self.last_error, status="error")
            return
        while self._gen == gen:
            self.public_url = None
            self.status = "connecting"
            delay = 10
            if mode == "ngrok":
                exe, url = self.ngrok(), (cfg.get("public_url") or "").rstrip("/")
                if not (exe and url):
                    self.status, self.last_error = "error", ("ngrok mode needs ngrok.exe (next to server.py, resources/bin, "
                                                             "PATH or ngrok_path) and public_url = your static domain in config.json")
                    activity.log("Tunnel", self.last_error, status="error")
                    return
                if not url.startswith("http"):
                    url = "https://" + url
                self.provider = "ngrok"
                activity.log("Tunnel", f"Starting ngrok tunnel {url} -> 127.0.0.1:{self.port}...")
                cmd = [exe, "http", f"127.0.0.1:{self.port}", "--url", url, "--log", "stdout", "--log-format", "logfmt"]
                ok = self._run_once(gen, cmd, "ngrok", None, self.NGROK_READY_RE, 45, fixed_url=url)
                if not ok and ("authtoken" in self.last_error.lower() or "ERR_NGROK_4018" in self.last_error or "ERR_NGROK_105" in self.last_error):
                    self.last_error = "ngrok: no authtoken. Run once: ngrok config add-authtoken <token from dashboard.ngrok.com>"
                elif not ok and ("ERR_NGROK_334" in self.last_error or "already online" in self.last_error):
                    self.last_error = "ngrok: this domain is already used by another ngrok process (close it)"
                delay = 5 if ok else 20
            elif mode == "named":
                exe, tok, url = self.cloudflared(), cfg.get("cloudflare_tunnel_token"), cfg.get("public_url")
                if not (exe and tok and url):
                    self.status, self.last_error = "error", "named mode needs cloudflared, cloudflare_tunnel_token and public_url in config.json"
                    activity.log("Tunnel", self.last_error, status="error")
                    return
                self.provider = "cloudflare-named"
                ok = self._run_once(gen, [exe, "tunnel", "--no-autoupdate", "run", "--token", tok], "cloudflared/named",
                                    None, self.REGISTERED_RE, 60, fixed_url=url)
                delay = 5 if ok else 20
            elif have_ssh and (mode == "pinggy" or (mode == "auto" and time.time() < cf_cooldown_until)):
                providers = self._ssh_providers()
                pname, cmd = providers[ssh_idx % len(providers)]
                self.provider = pname
                activity.log("Tunnel", f"Starting {pname} tunnel (SSH over port 443)...")
                ok = self._run_once(gen, cmd, f"ssh/{pname}", self.SSH_URL_RE, self.SSH_URL_RE, 45)
                if ok:
                    self._save_pref(pname)
                    ssh_fails = 0
                    delay = 3     # free SSH tunnels expire (Pinggy ~60 min): reconnect quickly
                else:
                    ssh_idx += 1  # rotate provider
                    ssh_fails += 1
                    delay = 10
                    if mode == "auto" and ssh_fails >= 2 * len(providers):
                        cf_cooldown_until = 0.0  # all SSH providers failed: try Cloudflare again
                        ssh_fails = 0
            else:
                exe = self.cloudflared()
                if not exe:
                    self.status, self.last_error = "error", "cloudflared not found (resources/bin/cloudflared.exe or PATH)"
                    activity.log("Tunnel", self.last_error, status="error")
                    if mode == "auto" and have_ssh:
                        cf_cooldown_until = time.time() + 3600
                        continue
                    return
                self.provider = "cloudflare-quick"
                self.rate_limited = False
                activity.log("Tunnel", f"Starting Cloudflare quick tunnel for 127.0.0.1:{self.port}...")
                cmd = [exe, "tunnel", "--url", f"http://127.0.0.1:{self.port}", "--protocol", "http2",
                       "--edge-ip-version", "4", "--no-autoupdate"]
                ok = self._run_once(gen, cmd, "cloudflared/http2", self.CF_URL_RE, self.REGISTERED_RE, 45)
                if ok:
                    self._save_pref("cloudflare")
                    delay = 5
                elif mode == "auto" and have_ssh:
                    cf_cooldown_until = time.time() + (900 if self.rate_limited else 1800)
                    why = "rate-limited (429/1015)" if self.rate_limited else "unreachable (DNS / VPN / provider blocks it)"
                    activity.log("Tunnel", f"Cloudflare {why} -> switching to SSH tunnels (Pinggy / localhost.run)", status="error")
                    delay = 1
                else:
                    delay = 120 if self.rate_limited else 30
                    if self.rate_limited:
                        self.last_error = "trycloudflare rate limit (429/1015): wait a few minutes, do not restart repeatedly"
                    elif mode == "auto" and not have_ssh:
                        self.last_error += " | no ssh.exe for the fallback: install Windows 'OpenSSH Client'"
            if self._gen != gen:
                return
            self.status = "reconnecting"
            activity.log("Tunnel", f"Reconnecting in {delay}s...", status="error")
            if not self._sleep(gen, delay):
                return

    def start(self):
        mode = runtime.config.get("tunnel_mode", "auto")
        if mode == "none":
            self.status = "disabled"
            return
        if mode == "external":
            self.public_url = (runtime.config.get("public_url") or "").rstrip("/") or None
            self.status = "external" if self.public_url else "error"
            self.last_error = "" if self.public_url else "external mode needs public_url in config.json"
            self.provider = "external"
            return
        if self._thread and self._thread.is_alive() and self.status not in ("stopped", "error"):
            return
        self._gen += 1
        self.status = "connecting"
        self._thread = threading.Thread(target=self._loop, args=(self._gen,), daemon=True)
        self._thread.start()

    def restart(self):
        self.stop()
        time.sleep(1)
        self.start()

    def stop(self):
        self._gen += 1
        self.status = "stopped"
        self._kill_proc()
        self.public_url = None
        activity.log("Tunnel", "Tunnel stopped.")
