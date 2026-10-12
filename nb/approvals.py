"""Human-in-the-loop approvals shown in the dashboard (dangerous commands)."""
import asyncio
import itertools
import time
import webbrowser

from nb import activity

_ids = itertools.count(1)
pending = {}            # id -> dict
last_dashboard_poll = 0.0
dashboard_url = ""


def touch():
    global last_dashboard_poll
    last_dashboard_poll = time.time()


def listing():
    return [{k: v for k, v in p.items() if k not in ("event",)} for p in pending.values()]


async def request(tool: str, summary: str, reasons, timeout: int):
    """Wait for the user to approve in the dashboard. Returns (approved, note)."""
    pid = next(_ids)
    ev = asyncio.Event()
    item = {"id": pid, "tool": tool, "summary": summary[:2000], "reasons": list(reasons), "ts": time.strftime("%H:%M:%S"),
            "expires_in": timeout, "created": time.time(), "decision": None, "event": ev}
    pending[pid] = item
    activity.log("Approval needed", f"#{pid} {tool}: {summary[:120]} ({'; '.join(reasons)})", status="pending")
    print("\a", end="", flush=True)
    if dashboard_url and time.time() - last_dashboard_poll > 10:
        try:
            webbrowser.open(dashboard_url)  # nobody is looking at the dashboard: bring it up
        except Exception:
            pass
    try:
        await asyncio.wait_for(ev.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        pass
    finally:
        pending.pop(pid, None)
    d = item["decision"]
    if d is True:
        activity.log("Approved", f"#{pid} {tool}", status="ok")
        return True, "approved by user"
    if d is False:
        activity.log("Denied", f"#{pid} {tool}", status="blocked")
        return False, "denied by the user in the dashboard"
    activity.log("Approval timeout", f"#{pid} {tool}", status="blocked")
    return False, f"no answer in the dashboard within {timeout}s"


def decide(pid: int, approve: bool) -> bool:
    item = pending.get(pid)
    if not item:
        return False
    item["decision"] = bool(approve)
    item["event"].set()
    return True
