# Open Notion Bridge 2.0

Локальный MCP-сервер, который даёт Notion AI (Custom MCP connection) доступ к папкам проекта на вашем
Windows-ПК: чтение/поиск, правка файлов с откатом, терминал, git, документы, LaTeX. Наружу сервер
выставляется через туннель (Cloudflare quick tunnel по умолчанию).

## Быстрый старт

```bat
git clone https://github.com/Ntxfloy/open_bridge_Notion.git
cd open_bridge_Notion
python -m pip install -r requirements.txt --upgrade
python server.py
```

1. Откройте панель: **http://127.0.0.1:8766** (только локально, в туннель не попадает).
2. Добавьте рабочую папку (кнопка «Добавить» или путь вручную).
3. Notion → Settings → Connections → **Custom MCP**:
   - URL: публичный адрес из панели, **оканчивается на `/mcp`** (Streamable HTTP);
   - заголовок `Authorization` = `Bearer <токен>` (кнопка «Скопировать» в панели).
4. Проверка: попросите ИИ «вызови get_status».

Нужен Python ≥ 3.10. Внешние программы (в репозиторий не входят):

- `cloudflared.exe` — [github.com/cloudflare/cloudflared/releases](https://github.com/cloudflare/cloudflared/releases)
  (для Pinggy/localhost.run достаточно встроенного в Windows «Клиента OpenSSH»);
- `rg.exe` (ripgrep, быстрый поиск) — [github.com/BurntSushi/ripgrep/releases](https://github.com/BurntSushi/ripgrep/releases);
- для `latex_build`: TeX Live / MiKTeX или [Tectonic](https://tectonic-typesetting.github.io).

Положите `cloudflared.exe` и `rg.exe` в `resources\bin` (рядом с `server.py` или уровнем выше) или в `PATH`.

## Обновление с 1.x — что изменилось для вас

| Было | Стало |
|---|---|
| Один порт 8766 для всего, `0.0.0.0` | Панель `127.0.0.1:8766`, MCP `127.0.0.1:8767`, туннель → 8767 |
| URL `…/sse` | Основной `…/mcp` (старый `…/sse` работает для совместимости) |
| `?token=` в URL, токен в `/api/status` | Только заголовок `Authorization: Bearer`, токен не отдаётся наружу |
| `requirements.txt` без версий | `mcp>=1.22,<2` — **mcp 2.x удалил `mcp.server.fastmcp`**, бридж бы не стартовал |

`config.json` мигрирует сам: `port`→`dashboard_port`, `workspace`→`workspaces`, `cors_origins` удаляется,
неизвестный режим → `safe`. Пустой/слабый/примерный токен заменяется новым — тогда обновите его в Notion.
Quick tunnel даёт новый URL при каждом запуске; для постоянного адреса см. «Туннели».

## Модель безопасности (честно)

- **MCP-порт**: Bearer-токен (сравнение за постоянное время), проверка `Host` (защита от DNS rebinding) и
  `Origin`, лимит неудачных попыток (10 за 5 минут → 429). Токен в логи не пишется.
- **Панель**: только loopback, проверка `Host`, ключ панели в каждом запросе `/api` (выдаётся только
  самой странице), запрет cross-origin и проксированных запросов, CSP. Сторонний сайт не может прочитать токен.
- **Файловые инструменты** заперты в рабочих папках: realpath + проверка вхождения (симлинки/junction,
  `..`, UNC, `C:file`, ADS `:stream`, зарезервированные имена). Секреты (`.env`, ключи, `.ssh`, credentials…)
  скрыты deny-листом (`deny_globs`, `extra_deny_globs`). Папка бриджа и `config.json` защищены. Запись в `.git/` запрещена.
- **Терминал — НЕ песочница.** `run_command`/`start_process` работают с правами вашего пользователя.
  Опасные команды (удаление, format, реестр, сеть+выполнение, пути вне рабочих папок…) ждут вашего
  «Разрешить» в панели (`confirm_commands`: `dangerous` | `always` | `never`). Для реальной изоляции —
  отдельный пользователь Windows, Windows Sandbox или Docker.
- Режимы: `safe` — только чтение; `developer` — + запись, команды, git commit; `agent` — + скриншоты.
  Неизвестный режим = `safe` (fail-closed).

## Инструменты (37)

- **Чтение**: `get_status`, `read_file` (страницы, хвост, картинки, docx/xlsx/pptx/pdf), `read_multiple_files`,
  `read_document`, `get_file_info`, `list_directory` (дерево), `find_files`, `search_code` (ripgrep).
- **Правка** (всё с резервной копией): `write_file`, `edit_file` (точная замена; уникальность или
  `expected_replacements`; мягкие фолбэки по пробелам/отступам/кавычкам, без «нечёткого» угадывания),
  `edit_lines`, `apply_patch` (unified diff или формат `*** Begin Patch`, атомарно на несколько файлов),
  `create_directory`, `move_path`, `copy_path`, `delete_path`.
- **Откат**: `list_changes`, `undo_change` (с проверкой конфликтов); то же в панели.
- **Терминал**: `run_command` (таймаут убивает всё дерево процессов), `start_process`, `read_process_output`,
  `send_process_input`, `list_processes`, `stop_process`.
- **Git**: `git_status`, `git_diff`, `git_log`, `git_show`, `git_add`, `git_commit`, `git_restore`, `git_branch`.
- **Код/документы**: `get_outline` (py/tex/md), `find_symbol`, `replace_symbol`, `latex_build` (latexmk, ручные
  проходы или Tectonic, без shell-escape, ошибки с файлом и строкой).
- **Экран**: `take_screenshot` (режим agent).

Кодировки сохраняются: UTF-8/BOM/UTF-16, cp1251, CRLF/LF, финальный перевод строки. Запись атомарная.
Пути: относительно папки по умолчанию или `@алиас/путь`.

## Туннели (`tunnel_mode`)

- `auto` (по умолчанию) — Cloudflare quick tunnel `*.trycloudflare.com`; если Cloudflare недоступен (DNS, VPN,
  провайдер, 429) — автоматически SSH-туннели через порт 443: Pinggy, затем localhost.run. Сработавший провайдер
  запоминается (`tunnel_state.json`) и при следующем запуске пробуется первым. Нужен `ssh.exe` (встроенный «Клиент OpenSSH»).
- `pinggy` — сразу только SSH-туннели; `cloudflared` — только Cloudflare. Режим можно переключить в панели.
- URL бесплатных туннелей меняется при переподключении (Pinggy — примерно раз в час) — обновляйте его в Notion.
- `ngrok` — постоянный бесплатный адрес ngrok: один раз `ngrok config add-authtoken <токен>`, положите `ngrok.exe`
  рядом с `server.py` (или в `resources\bin` / PATH / `ngrok_path`), `public_url` = ваш статический домен
  (`https://xxx.ngrok-free.dev`). Ссылка не меняется при перезапуске.
- `named` — постоянный Cloudflare Tunnel: `cloudflare_tunnel_token` + `public_url` (ваш домен → `http://127.0.0.1:8767`).
- `external` — свой туннель (Tailscale Funnel, ngrok…), укажите `public_url`; Host добавится в разрешённые.
- `none` — без туннеля.

## Файлы

- `config.json` — настройки и токен (не публикуйте). Пример: `config.example.json`.
- `state/` — история изменений (`history/`), журнал `activity.jsonl`, `errors.log`.
- `tunnel.log` — вывод туннеля (токены маскируются).
- Переменные окружения: `NB_CONFIG_FILE`, `NB_STATE_DIR`.

## CHANGELOG

2.0.4 — режим туннеля `ngrok` (постоянный адрес на бесплатном статическом домене ngrok).

2.0.3 — `latex_build` поддерживает Tectonic (`engine="tectonic"`, в `auto` — если нет TeX Live/MiKTeX; режим
`--untrusted`), подсказка про кириллицу без шрифта; `resources\bin` ищется и внутри папки (раскладка git clone).

2.0.2 — по итогам живого теста на Windows: токен бриджа вырезается из любого вывода инструментов (копия config.json в
рабочей папке больше не утекает); apply_patch с `/dev/null` больше не создаёт папку `b/`; удаление папок с атрибутом
ReadOnly (WinError 5) и частичные удаления попадают в историю; `Format-Table/-List` не считаются «опасными»;
подтверждение ждёт 50 с (раньше 180 с > таймаута Notion); git: юникодные ветки, `git_show repo_path`, `stat_only`;
outline LaTeX показывает метки; rg.exe доступен в терминале.

2.0.1 — вернул автоматический запасной туннель (Pinggy / localhost.run) в режиме `auto`, как в 1.x; запоминание рабочего провайдера; выбор туннеля в панели.

### 2.0.0

- Безопасность: закрыт публичный `/api/*` с токеном, убран CORS `*`, привязка к 127.0.0.1, проверка Host/Origin,
  нет `?token=`, constant-time сравнение, rate limit, fail-closed режимы, честное описание вместо `safe_sandbox: true`.
- Транспорт: Streamable HTTP `/mcp` + legacy SSE; все инструменты асинхронные (не блокируют сервер).
- Правка: multi-edit, apply_patch, правка по строкам, сохранение кодировки/переводов строк, атомарная запись,
  история и undo, защита от плейсхолдеров «… rest of code …».
- Терминал: Job Object (убивается всё дерево), UTF-8 вывод, фоновые процессы, подтверждение опасных команд.
- Git без shell (сообщение коммита через stdin), несколько рабочих папок, docx/xlsx/pptx/pdf, LaTeX, outline/symbols,
  аннотации инструментов (readOnly/destructive), журнал на диске.
