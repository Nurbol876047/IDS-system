"""
dashboard/app.py — живой дашборд для демонстрации проекта.

Показывает два потока данных рядом:
  1. "Кто заходил на сайт" — прикладной лог demo/logs/target_requests.log
     (пишет target_server/app.py на каждый HTTP-запрос).
  2. "Вердикты сетевого IDS" — лог ids-project/ids_events.log, который теперь
     пишет live_capture_engine.py в формате JSONL: КАЖДЫЙ сетевой поток
     (не только атаки), с протоколом/портами/счётчиками и вердиктом модели.
     Старый текстовый формат (predict_once.py / live_ids_watcher.py,
     построчно "[время] сообщение") тоже поддержан для совместимости.

Плюс статус живого движка (ids-project/live_engine.status) — работает ли
сейчас захват трафика, с какого момента, сколько потоков/атак обработано.

Страница каждые 1.5 сек опрашивает /api/* и перерисовывает таблицы —
никакого WebSocket, просто чтобы было просто и надёжно для демо.
"""

import json
import os
import re

from flask import Flask, jsonify

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REQUESTS_LOG = os.path.join(BASE_DIR, "..", "logs", "target_requests.log")
IDS_DIR = os.path.join(BASE_DIR, "..", "..", "ids-project")
IDS_LOG = os.path.join(IDS_DIR, "ids_events.log")
ENGINE_STATUS_FILE = os.path.join(IDS_DIR, "live_engine.status")

app = Flask(__name__)

PAGE = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Digital Detective — дашборд</title>
<style>
  :root {
    --bg: #0a0e16;
    --panel: #121826;
    --panel-2: #0d1220;
    --border: #212b42;
    --text: #e8ecf4;
    --muted: #7c8aa8;
    --accent: #5b8cff;
    --accent-dim: #2a3a66;
    --good: #35d08e;
    --good-dim: #0f3b2a;
    --bad: #ff5d7a;
    --bad-dim: #3a1420;
    --warn: #ffb648;
    --warn-dim: #3a2a10;
  }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, "Segoe UI", Roboto, system-ui, sans-serif;
    margin: 0; padding: 28px 32px 40px;
    background: radial-gradient(1200px 600px at 10% -10%, #10182c 0%, var(--bg) 55%);
    color: var(--text);
    min-height: 100vh;
  }
  header { display: flex; align-items: flex-start; justify-content: space-between; flex-wrap: wrap; gap: 16px; margin-bottom: 22px; }
  h1 { font-size: 21px; margin: 0 0 6px; font-weight: 600; letter-spacing: .2px; }
  .muted { color: var(--muted); font-size: 13px; max-width: 640px; line-height: 1.5; }

  .status-pill {
    display: inline-flex; align-items: center; gap: 8px;
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 999px; padding: 7px 14px 7px 10px;
    font-size: 12.5px; color: var(--muted);
    box-shadow: 0 6px 18px -8px rgba(0,0,0,.6);
  }
  .status-pill b { color: var(--text); font-weight: 600; }
  .dot { display:inline-block; width:9px; height:9px; border-radius:50%; flex: none; }
  .dot.on { background: var(--good); box-shadow: 0 0 0 3px var(--good-dim), 0 0 10px var(--good); animation: pulse 1.8s ease-in-out infinite; }
  .dot.off { background: #5a6478; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .45; } }

  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 22px; }
  .stat { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 14px 16px; }
  .stat .k { font-size: 11.5px; color: var(--muted); text-transform: uppercase; letter-spacing: .6px; margin-bottom: 6px; }
  .stat .v { font-size: 24px; font-weight: 700; font-variant-numeric: tabular-nums; }
  .stat.attacks .v { color: var(--bad); }
  .stat.ok .v { color: var(--good); }

  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }
  @media (max-width: 920px) { .grid { grid-template-columns: 1fr; } .stats { grid-template-columns: repeat(2,1fr); } }

  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 14px; padding: 16px; box-shadow: 0 10px 30px -14px rgba(0,0,0,.7); display: flex; flex-direction: column; min-height: 0; }
  .panel-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
  .panel h2 { font-size: 14px; margin: 0; color: var(--text); font-weight: 600; }
  .panel .count { font-size: 11.5px; color: var(--muted); background: var(--panel-2); border: 1px solid var(--border); border-radius: 999px; padding: 2px 9px; }

  .table-scroll { overflow: auto; max-height: 520px; border-radius: 8px; }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  thead th { position: sticky; top: 0; background: var(--panel-2); color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 10.5px; letter-spacing: .5px; }
  th, td { text-align: left; padding: 7px 9px; border-bottom: 1px solid var(--border); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 240px; }
  tbody tr:hover { background: rgba(255,255,255,.03); }
  .ip, .mono { font-family: "SF Mono", "Cascadia Code", Consolas, monospace; font-size: 12px; }

  .badge { display: inline-block; font-size: 11px; font-weight: 600; padding: 2px 9px; border-radius: 999px; letter-spacing: .2px; }
  .badge.benign { background: var(--good-dim); color: var(--good); }
  .badge.attack { background: var(--bad-dim); color: var(--bad); }
  .badge.flood  { background: var(--warn-dim); color: var(--warn); }
  .badge.neutral{ background: var(--panel-2); color: var(--muted); border: 1px solid var(--border); }

  tr.row-attack { background: linear-gradient(90deg, rgba(255,93,122,.10), transparent 60%); }

  .empty { color: var(--muted); font-style: italic; font-size: 12.5px; padding: 18px 4px; }
  footer { margin-top: 22px; color: var(--muted); font-size: 11.5px; }
  footer code { background: var(--panel-2); border: 1px solid var(--border); border-radius: 5px; padding: 1px 6px; }
</style>
</head>
<body>
<header>
  <div>
    <h1>Digital Detective — живой дашборд</h1>
    <p class="muted">Слева — кто и как заходил на мок-сайт по HTTP. Справа — вердикт сетевого IDS по каждому
      TCP/UDP-потоку на интерфейсе (захват + расчёт признаков + ML-модель — всё в <code>live_capture_engine.py</code>,
      без CICFlowMeter/Java). Обновление каждые 1.5 сек.</p>
  </div>
  <div class="status-pill" id="statusPill">
    <span class="dot off" id="statusDot"></span>
    <span id="statusText">проверка движка…</span>
  </div>
</header>

<div class="stats">
  <div class="stat"><div class="k">HTTP-запросов</div><div class="v" id="statReq">0</div></div>
  <div class="stat"><div class="k">Потоков проанализировано</div><div class="v" id="statFlows">0</div></div>
  <div class="stat attacks"><div class="k">Атак обнаружено</div><div class="v" id="statAttacks">0</div></div>
  <div class="stat ok"><div class="k">Мониторинг с</div><div class="v" id="statSince" style="font-size:16px">—</div></div>
</div>

<div class="panel" id="alertsPanel" style="margin-bottom:18px">
  <div class="panel-head">
    <h2>Алерты правил — PortScan / DDoS (межпотоковые паттерны, не видны ML построчно)</h2>
    <span class="count" id="alertsCount">0</span>
  </div>
  <div class="table-scroll" style="max-height:220px">
    <table id="alertsTable"><thead><tr>
      <th>Время</th><th>Источник</th><th>Назначение</th><th>Вердикт</th>
    </tr></thead><tbody></tbody></table>
  </div>
  <div id="alertsEmpty" class="empty">Пока нет алертов — например, запусти <code>nmap -p 1-2000 127.0.0.1</code> или кнопку «Симулировать DDoS» на мок-сайте.</div>
</div>

<div class="grid">
  <div class="panel">
    <div class="panel-head">
      <h2>Лог веб-сервера (прикладной уровень)</h2>
      <span class="count" id="reqCount">0</span>
    </div>
    <div class="table-scroll">
      <table id="reqTable"><thead><tr><th>Время</th><th>IP</th><th>Метод</th><th>Путь</th><th>Тег</th></tr></thead><tbody></tbody></table>
    </div>
    <div id="reqEmpty" class="empty" style="display:none">Пока нет запросов — открой мок-сайт: <code>http://127.0.0.1:5000</code></div>
  </div>
  <div class="panel">
    <div class="panel-head">
      <h2>Сетевой IDS — вердикты по потокам</h2>
      <span class="count" id="idsCount">0</span>
    </div>
    <div class="table-scroll">
      <table id="idsTable"><thead><tr>
        <th>Время</th><th>Proto</th><th>Источник</th><th>Назначение</th>
        <th>Пак.</th><th>Байт</th><th>Длит., мс</th><th>Вердикт</th>
      </tr></thead><tbody></tbody></table>
    </div>
    <div id="idsEmpty" class="empty" style="display:none">Пока нет событий — запусти <code>live_capture_engine.py</code> (см. README).</div>
  </div>
</div>

<footer>Источники: <code>demo/logs/target_requests.log</code> · <code>ids-project/ids_events.log</code> · <code>ids-project/live_engine.status</code></footer>

<script>
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function verdictBadge(v) {
  if (!v) return '<span class="badge neutral">?</span>';
  if (v === 'BENIGN') return '<span class="badge benign">BENIGN</span>';
  if (/ddos|dos|flood/i.test(v)) return `<span class="badge flood">${esc(v)}</span>`;
  return `<span class="badge attack">${esc(v)}</span>`;
}

async function refreshRequests() {
  const reqs = await (await fetch('/api/requests')).json();
  const reqBody = document.querySelector('#reqTable tbody');
  reqBody.innerHTML = '';
  document.querySelector('#reqEmpty').style.display = reqs.length ? 'none' : 'block';
  document.querySelector('#reqCount').textContent = reqs.length;
  for (const r of reqs.slice().reverse()) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="mono">${esc(r.ts)}</td><td class="ip">${esc(r.ip)}</td>` +
      `<td>${esc(r.method)}</td><td>${esc(r.path)}</td><td>${esc(r.tag)}</td>`;
    reqBody.appendChild(tr);
  }
}

async function refreshIds() {
  const events = await (await fetch('/api/ids_events')).json();
  const idsBody = document.querySelector('#idsTable tbody');
  idsBody.innerHTML = '';
  document.querySelector('#idsEmpty').style.display = events.length ? 'none' : 'block';
  document.querySelector('#idsCount').textContent = events.length;
  for (const e of events.slice().reverse()) {
    const tr = document.createElement('tr');
    if (e.verdict && e.verdict !== 'BENIGN') tr.className = 'row-attack';
    if (e.raw) {
      tr.innerHTML = `<td class="mono">${esc(e.ts)}</td><td colspan="7">${esc(e.raw)}</td>`;
    } else {
      const src = `${esc(e.src_ip)}<span class="mono" style="color:var(--muted)">:${esc(e.src_port)}</span>`;
      const dst = `${esc(e.dst_ip)}<span class="mono" style="color:var(--muted)">:${esc(e.dst_port)}</span>`;
      tr.innerHTML = `<td class="mono">${esc(e.ts)}</td><td class="mono">${esc(e.proto)}</td>` +
        `<td class="ip">${src}</td><td class="ip">${dst}</td>` +
        `<td class="mono">${esc(e.packets)}</td><td class="mono">${esc(e.bytes)}</td>` +
        `<td class="mono">${esc(e.duration_ms)}</td><td>${verdictBadge(e.verdict)}</td>`;
    }
    idsBody.appendChild(tr);
  }
}

async function refreshAlerts() {
  const alerts = await (await fetch('/api/rule_alerts')).json();
  const body = document.querySelector('#alertsTable tbody');
  body.innerHTML = '';
  document.querySelector('#alertsEmpty').style.display = alerts.length ? 'none' : 'block';
  document.querySelector('#alertsCount').textContent = alerts.length;
  for (const a of alerts.slice().reverse()) {
    const tr = document.createElement('tr');
    tr.className = 'row-attack';
    tr.innerHTML = `<td class="mono">${esc(a.ts)}</td><td class="ip">${esc(a.src_ip)}</td>` +
      `<td class="ip">${esc(a.dst_ip)}</td><td>${verdictBadge(a.verdict)}</td>`;
    body.appendChild(tr);
  }
}

async function refreshStatus() {
  const dot = document.querySelector('#statusDot');
  const text = document.querySelector('#statusText');
  try {
    const s = await (await fetch('/api/engine_status')).json();
    if (s.running) {
      dot.className = 'dot on';
      text.innerHTML = `живой захват активен на <b>${esc(s.iface)}</b>`;
      document.querySelector('#statSince').textContent = (s.started_at ?? '—').replace('T', ' ');
    } else if (s.known) {
      dot.className = 'dot off';
      text.textContent = 'движок остановлен';
      document.querySelector('#statSince').textContent = '—';
    } else {
      dot.className = 'dot off';
      text.textContent = 'движок не запущен';
      document.querySelector('#statSince').textContent = '—';
    }
    document.querySelector('#statFlows').textContent = s.flows_total ?? 0;
    document.querySelector('#statAttacks').textContent = s.attacks_total ?? 0;
  } catch (e) {
    dot.className = 'dot off';
    text.textContent = 'нет связи с движком';
  }
}

async function refresh() {
  document.querySelector('#statReq').textContent =
    document.querySelector('#reqCount').textContent || '0';
  await Promise.allSettled([refreshRequests(), refreshIds(), refreshAlerts(), refreshStatus()]);
  document.querySelector('#statReq').textContent = document.querySelector('#reqCount').textContent;
}
refresh();
setInterval(refresh, 1500);
</script>
</body>
</html>
"""


def _tail_jsonl(path: str, limit: int = 200):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()[-limit:]
    rows = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


_LEGACY_LINE_RE = re.compile(r"^\[(.*?)\]\s*(.*)$")


def _tail_ids_events(path: str, limit: int = 300):
    """Читает ids_events.log: новый формат (JSONL от live_capture_engine.py)
    и старый текстовый ("[время] сообщение" от live_ids_watcher.py/predict_once.py)
    в одном списке, новый — как структурированный dict, старый — как {"raw": ...}."""
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()[-limit:]
    rows = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
            continue
        except json.JSONDecodeError:
            pass
        m = _LEGACY_LINE_RE.match(line)
        if m:
            rows.append({"ts": m.group(1), "raw": m.group(2)})
        else:
            rows.append({"ts": "", "raw": line})
    return rows


def _engine_status():
    if not os.path.exists(ENGINE_STATUS_FILE):
        return {"known": False, "running": False}
    try:
        with open(ENGINE_STATUS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["known"] = True
        return data
    except (json.JSONDecodeError, OSError):
        return {"known": False, "running": False}


@app.route("/")
def index():
    return PAGE


@app.route("/api/requests")
def api_requests():
    return jsonify(_tail_jsonl(REQUESTS_LOG))


@app.route("/api/ids_events")
def api_ids_events():
    return jsonify(_tail_ids_events(IDS_LOG))


@app.route("/api/rule_alerts")
def api_rule_alerts():
    events = _tail_ids_events(IDS_LOG, limit=2000)
    alerts = [e for e in events if e.get("type") == "alert"]
    return jsonify(alerts[-100:])


@app.route("/api/engine_status")
def api_engine_status():
    return jsonify(_engine_status())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False)
