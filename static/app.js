"use strict";
(() => {
  const KEY = document.querySelector('meta[name="bridge-key"]').content;
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  let lastActivity = 0, tokenShown = false, lastStatus = null, offline = false;

  async function api(path, body) {
    const opt = { headers: { "X-Bridge-Key": KEY }, cache: "no-store" };
    if (body !== undefined) { opt.method = "POST"; opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
    const r = await fetch(path, opt);
    let data = {};
    try { data = await r.json(); } catch (_) { /* not JSON */ }
    if (r.status === 401) { toast("Ключ панели устарел — перезагрузите страницу", true); throw new Error("401"); }
    if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
    return data;
  }

  let toastTimer;
  function toast(msg, bad) {
    const t = $("toast"); t.textContent = msg; t.classList.toggle("bad", !!bad); t.classList.add("show");
    clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove("show"), 2600);
  }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); }
    catch (_) { const ta = document.createElement("textarea"); ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove(); }
    toast("Скопировано");
  }
  function pill(el, cls, text) { el.className = "status-pill " + cls; el.querySelector("span:last-child").textContent = text; }

  const TUNNEL_TEXT = { online: "Туннель онлайн", connecting: "Туннель подключается…", error: "Ошибка туннеля", stopped: "Туннель остановлен", disabled: "Туннель выключен", external: "Внешний URL" };

  function renderStatus(s) {
    lastStatus = s;
    $("versionText").textContent = "v" + s.version;
    pill($("serverStatusBadge"), "online", "Сервер работает");
    const ts = s.tunnel.status;
    pill($("tunnelStatusBadge"), ts === "online" || ts === "external" ? "online" : ts === "connecting" ? "connecting" : "offline", TUNNEL_TEXT[ts] || ts);
    const e = s.endpoints;
    $("endpointInput").value = e.mcp || (ts === "disabled" ? "Туннель выключен (tunnel_mode = none)" : "Ожидание туннеля…");
    $("sseEndpointText").textContent = e.sse || "—";
    $("localEndpointText").textContent = e.local_mcp;
    $("tunnelInfo").textContent = [s.tunnel.provider ? "провайдер: " + s.tunnel.provider : "", s.tunnel.last_error ? "ошибка: " + s.tunnel.last_error : "",
      s.tunnel.has_ssh ? "" : "нет ssh.exe — запасные туннели недоступны (установите «Клиент OpenSSH»)"].filter(Boolean).join(" · ");
    if (!tokenShown) $("tokenInput").value = s.token_hint ? s.token_hint : "";
    document.querySelectorAll(".mode-option").forEach((l) => {
      const on = l.dataset.mode === s.mode; l.classList.toggle("active", on); l.querySelector("input").checked = on;
    });
    $("confirmSelect").value = s.confirm_commands;
    if (document.activeElement !== $("tunnelSelect")) $("tunnelSelect").value = s.tunnel.mode;

    const w = $("warnings"), warns = s.warnings || [];
    w.innerHTML = warns.map((x) => "<div>⚠ " + esc(x) + "</div>").join("");
    w.classList.toggle("hidden", !warns.length);

    const ws = s.workspaces || [];
    $("workspaceList").innerHTML = ws.length ? ws.map((x) =>
      '<div class="ws-item' + (x.default ? " default" : "") + '">' +
        '<div class="ws-main"><span class="ws-alias">@' + esc(x.alias) + "</span>" + (x.default ? '<span class="badge ok">по умолчанию</span>' : "") +
        (x.exists ? "" : '<span class="badge bad">папка не найдена</span>') +
        '<div class="path-display">' + esc(x.path) + "</div></div>" +
        '<div class="ws-actions">' +
          (x.default ? '<button class="btn-link" data-ws="replace_default">Сменить папку</button>'
                     : '<button class="btn-link" data-ws="default" data-alias="' + esc(x.alias) + '">Сделать основной</button>') +
          (ws.length > 1 ? '<button class="btn-link text-danger" data-ws="remove" data-alias="' + esc(x.alias) + '">Убрать</button>' : "") +
        "</div></div>").join("")
      : '<div class="empty-state">Папка не выбрана — добавьте папку проекта</div>';

    const pr = s.processes || [];
    $("processList").innerHTML = pr.length ? pr.map((p) =>
      '<div class="list-row"><div><b>' + esc(p.id) + "</b> " + esc(p.name || "") + ' <span class="badge' + (p.status === "running" ? " ok" : "") + '">' + esc(p.status) + "</span>" +
      '<div class="mono small">' + esc(p.command) + '</div><div class="muted small">' + esc(p.cwd) + " · " + Math.round(p.seconds) + " с</div></div>" +
      (p.status === "running" ? '<button class="btn btn-outline small" data-kill="' + esc(p.id) + '">Остановить</button>' : "") + "</div>").join("")
      : '<div class="empty-state">Нет процессов</div>';
  }

  async function pollStatus() {
    try { renderStatus(await api("/api/status")); offline = false; }
    catch (e) {
      if (e.message === "401") return;
      offline = true;
      pill($("serverStatusBadge"), "offline", "Сервер недоступен");
      pill($("tunnelStatusBadge"), "offline", "—");
    }
  }

  async function pollApprovals() {
    if (offline) return;
    try {
      const items = (await api("/api/approvals")).items || [];
      $("approvalsCard").classList.toggle("hidden", !items.length);
      document.title = (items.length ? "(" + items.length + ") ⚠ " : "") + "Open Notion Bridge";
      const now = Date.now() / 1000;
      $("approvalsList").innerHTML = items.map((a) => {
        const left = Math.max(0, Math.round(a.expires_in - (now - a.created)));
        return '<div class="approval-item"><div class="approval-head"><b>#' + a.id + " " + esc(a.tool) + '</b><span class="muted">осталось ' + left + " с</span></div>" +
          '<pre class="approval-cmd">' + esc(a.summary) + "</pre>" +
          '<div class="approval-reasons">' + (a.reasons || []).map((r) => '<span class="badge bad">' + esc(r) + "</span>").join(" ") + "</div>" +
          '<div class="approval-actions"><button class="btn btn-primary" data-approve="' + a.id + '">Разрешить</button>' +
          '<button class="btn btn-outline text-danger" data-deny="' + a.id + '">Отклонить</button></div></div>';
      }).join("");
    } catch (_) { /* ignore */ }
  }

  async function pollActivity() {
    if (offline) return;
    try {
      const items = (await api("/api/activity?since=" + lastActivity)).items || [];
      if (!items.length) return;
      const list = $("activityList");
      const empty = list.querySelector(".empty-state"); if (empty) empty.remove();
      for (const a of items) {
        lastActivity = Math.max(lastActivity, a.id);
        const st = a.status === "ok" ? "ok" : a.status === "error" ? "error" : "blocked";
        const row = document.createElement("div");
        row.className = "activity-row";
        row.innerHTML = '<span class="activity-time">' + esc(a.ts) + '</span><span class="activity-tag ' + st + '">' + esc(a.status) + "</span>" +
          '<span class="activity-action">' + esc(a.action) + '</span><span class="activity-detail">' + esc(a.detail) +
          (a.ms != null ? ' <span class="muted">' + a.ms + " мс</span>" : "") + (a.client ? ' <span class="muted">' + esc(a.client) + "</span>" : "") + "</span>";
        list.prepend(row);
      }
      while (list.children.length > 300) list.lastChild.remove();
    } catch (_) { /* ignore */ }
  }

  async function loadChanges() {
    try {
      const d = await api("/api/changes"), st = d.stats || {}, items = d.items || [];
      $("changesStats").textContent = "История: " + (st.batches || 0) + " изменений, " + (st.size_mb || 0) + " МБ резервных копий";
      $("changesList").innerHTML = items.length ? items.map((c) =>
        '<div class="list-row"><div><b>#' + c.id + "</b> " + esc(c.tool) + ' <span class="muted small">' + esc(String(c.ts).replace("T", " ")) + "</span>" +
        (c.undone_by ? ' <span class="badge">отменено (#' + c.undone_by + ")</span>" : "") + (c.undo_of ? ' <span class="badge">откат #' + c.undo_of + "</span>" : "") +
        '<div class="small">' + esc(c.summary) + '</div><div class="mono small muted">' + c.files.map(esc).join(", ") + (c.count > c.files.length ? " …" : "") + "</div></div>" +
        (c.undone_by ? "" : '<button class="btn btn-outline small" data-undo="' + c.id + '">Откатить</button>') + "</div>").join("")
        : '<div class="empty-state">Пока изменений нет</div>';
    } catch (e) { if (e.message !== "401") toast("Изменения: " + e.message, true); }
  }

  // ---------- actions
  $("copyEndpointBtn").onclick = () => { const v = lastStatus && lastStatus.endpoints.mcp; v ? copy(v) : toast("Публичного URL пока нет", true); };
  $("toggleTokenBtn").onclick = async () => {
    if (tokenShown) { tokenShown = false; $("tokenInput").type = "password"; pollStatus(); return; }
    try { const t = (await api("/api/token")).token; tokenShown = true; $("tokenInput").type = "text"; $("tokenInput").value = t; } catch (e) { toast(e.message, true); }
  };
  $("copyTokenBtn").onclick = async () => { try { copy((await api("/api/token")).token); } catch (e) { toast(e.message, true); } };
  $("revokeTokenBtn").onclick = async () => {
    if (!confirm("Сгенерировать новый токен? Старый перестанет работать сразу — замените его в Notion.")) return;
    try { await api("/api/revoke_token", {}); tokenShown = false; $("tokenInput").type = "password"; toast("Новый токен создан — обновите его в Notion"); pollStatus(); }
    catch (e) { toast(e.message, true); }
  };
  $("tunnelSelect").onchange = async (ev) => {
    try { await api("/api/config", { tunnel_mode: ev.target.value }); toast("Туннель перезапускается…"); } catch (e) { toast(e.message, true); }
    pollStatus();
  };
  $("restartTunnelBtn").onclick = async () => { try { await api("/api/restart_tunnel", {}); toast("Туннель перезапускается…"); pollStatus(); } catch (e) { toast(e.message, true); } };

  document.querySelectorAll('input[name="permMode"]').forEach((r) => r.addEventListener("change", async () => {
    if (r.value === "agent" && !confirm("Режим «Агент» разрешает ИИ делать скриншоты экрана. Включить?")) { pollStatus(); return; }
    try { await api("/api/config", { mode: r.value }); toast("Режим: " + r.value); } catch (e) { toast(e.message, true); }
    pollStatus();
  }));
  $("confirmSelect").onchange = async (ev) => {
    if (ev.target.value === "never" && !confirm("Все команды, включая опасные, будут выполняться без подтверждения. Уверены?")) { pollStatus(); return; }
    try { await api("/api/config", { confirm_commands: ev.target.value }); toast("Сохранено"); } catch (e) { toast(e.message, true); }
  };

  async function wsAction(body) {
    try {
      const d = await api("/api/workspaces", body);
      if (d.cancelled) return;
      toast("Сохранено"); $("wsPathInput").value = ""; pollStatus();
    } catch (e) { toast(e.message, true); }
  }
  $("addWsBtn").onclick = () => { const p = $("wsPathInput").value.trim(); wsAction(p ? { action: "add", path: p } : { action: "add" }); };
  $("workspaceList").onclick = (ev) => {
    const b = ev.target.closest("[data-ws]"); if (!b) return;
    const act = b.dataset.ws;
    if (act === "remove" && !confirm("Убрать @" + b.dataset.alias + " из доступа ИИ? Файлы не удаляются.")) return;
    if (act === "replace_default") { const p = $("wsPathInput").value.trim(); wsAction(p ? { action: act, path: p } : { action: act }); return; }
    wsAction({ action: act, alias: b.dataset.alias });
  };

  $("approvalsList").onclick = async (ev) => {
    const a = ev.target.closest("[data-approve],[data-deny]"); if (!a) return;
    const approve = a.hasAttribute("data-approve");
    try { await api("/api/approvals/" + (a.dataset.approve || a.dataset.deny), { approve }); toast(approve ? "Разрешено" : "Отклонено"); } catch (e) { toast(e.message, true); }
    pollApprovals();
  };
  $("changesList").onclick = async (ev) => {
    const b = ev.target.closest("[data-undo]"); if (!b) return;
    const id = +b.dataset.undo;
    if (!confirm("Откатить изменение #" + id + "? Файлы вернутся к состоянию до правки.")) return;
    try { await api("/api/undo", { id }); toast("Откат выполнен"); }
    catch (e) {
      if (confirm("Не удалось: " + e.message + "\n\nОткатить принудительно? Более новые правки этих файлов тоже сохранятся в истории.")) {
        try { await api("/api/undo", { id, force: true }); toast("Откат выполнен"); } catch (e2) { toast(e2.message, true); }
      }
    }
    loadChanges();
  };
  $("processList").onclick = async (ev) => {
    const b = ev.target.closest("[data-kill]"); if (!b) return;
    try { await api("/api/processes/" + encodeURIComponent(b.dataset.kill) + "/kill", {}); toast("Остановлен"); } catch (e) { toast(e.message, true); }
    pollStatus();
  };
  $("refreshChangesBtn").onclick = loadChanges;
  $("clearActivityBtn").onclick = () => { $("activityList").innerHTML = '<div class="empty-state">Очищено</div>'; };

  pollStatus(); pollActivity(); pollApprovals(); loadChanges();
  setInterval(pollStatus, 3000);
  setInterval(pollActivity, 1500);
  setInterval(pollApprovals, 1500);
  setInterval(loadChanges, 15000);
})();