"""Process-wide runtime state shared by the MCP server, the tools and the dashboard."""
import contextvars
import threading

import config_manager

config: dict = {}
startup_warnings: list = []
lock = threading.RLock()

# Set per HTTP request by the MCP guard middleware (used for the activity log).
client_ip: contextvars.ContextVar = contextvars.ContextVar("client_ip", default="")

CAPABILITIES = {
    "safe": frozenset({"read"}),
    "developer": frozenset({"read", "write", "exec", "git_write"}),
    "agent": frozenset({"read", "write", "exec", "git_write", "screen"}),
}


def init():
    global config, startup_warnings
    cfg, warnings = config_manager.load_config()
    config.clear()
    config.update(cfg)
    startup_warnings[:] = warnings
    return config


def save():
    with lock:
        config_manager.save_config(config)


def mode() -> str:
    m = config.get("mode")
    return m if m in CAPABILITIES else "safe"  # fail closed


def caps() -> frozenset:
    return CAPABILITIES[mode()]


def has_cap(cap: str) -> bool:
    return cap in caps()
