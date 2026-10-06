"""
dashboard/app.py — живой дашборд для демонстрации проекта.

Показывает два потока данных рядом:
  1. "Кто заходил на сайт" — прикладной лог demo/logs/target_requests.log
     (пишет target_server/app.py на каждый HTTP-запрос).
  2. "Вердикты сетевого IDS" — лог ids-project/ids_events.log
     (пишет live_ids_watcher.py / predict_once.py по результатам анализа
     сетевых потоков через CICFlowMeter + ML-модель).

Страница каждые 1.5 сек опрашивает /api/* и перерисовывает таблицы —
никакого WebSocket, просто чтобы было просто и надёжно для демо.
"""

import json
import os

from flask import Flask, jsonify

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REQUESTS_LOG = os.path.join(BASE_DIR, "..", "logs", "target_requests.log")
IDS_LOG = os.path.join(BASE_DIR, "..", "..", "ids-project", "ids_events.log")

app = Flask(__name__)

PAGE = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Digital Detective — дашборд</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 0; padding: 20px; background: #0b0f14; color: #e6e6e6; }
  h1 { font-size: 20px; margin-bottom: 4px; }
  .muted { color: #8a93a0; font-size: 13px; margin-bottom: 20px; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  .panel { background: #121826; border: 1px solid #22304a; border-radius: 10px; padding: 14px; }
  .panel h2 { font-size: 15px; margin: 0 0 10px; color: #9fb4d9; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th, td { text-align: left; padding: 4px 6px; border-bottom: 1px solid #1d2636; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 220px; }
  tr.attack { background: #2a1217; color: #ff8a8a; }
  tr.flood { background: #2a2312; color: #ffd37a; }
  .empty { color: #555; font-style: italic; }
  .dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px; }
  .dot.live { background:#2ecc71; box-shadow: 0 0 6px #2ecc71; }
</style>
</head>
<body>
<h1><span class="dot live"></span>Digital Detective — живой дашборд</h1>
<p class="muted">Обновляется каждые 1.5 сек. Слева — кто и как заходил на мок-сайт (HTTP). Справа — вердикты сетевого IDS по потокам трафика (CICFlowMeter + ML).</p>
<div class="grid">
  <div class="panel">
    <h2>🌐 Лог веб-сервера (прикладной уровень)</h2>
    <table id="reqTable"><thead><tr><th>Время</th><th>IP</th><th>Метод</th><th>Путь</th><th>Тег</th></tr></thead><tbody></tbody></table>
    <div id="reqEmpty" class="empty" style="display:none">Пока нет запросов — открой мок-сайт.</div>
  </div>
  <div class="panel">
    <h2>🛰️ Сетевой IDS (CICFlowMeter + ML)</h2>
    <table id="idsTable"><thead><tr><th>Время</th><th>Событие</th></tr></thead><tbody></tbody></table>
    <div id="idsEmpty" class="empty" style="display:none">Пока нет событий — запусти capture_and_test.sh.</div>
  </div>
</div>

<script>
async function refresh() {
  try {
    const reqs = await (await fetch('/api/requests')).json();
    const reqBody = document.querySelector('#reqTable tbody');
    reqBody.innerHTML = '';
    document.querySelector('#reqEmpty').style.display = reqs.length ? 'none' : 'block';
    for (const r of reqs.slice().reverse()) {
      const tr = document.createElement('tr');
      if (r.tag === 'flood_triggered') tr.className = 'flood';
      tr.innerHTML = `<td>${r.ts ?? ''}</td><td>${r.ip ?? ''}</td><td>${r.method ?? ''}</td><td>${r.path ?? ''}</td><td>${r.tag ?? ''}</td>`;
      reqBody.appendChild(tr);
    }
  } catch (e) {}

  try {
    const events = await (await fetch('/api/ids_events')).json();
    const idsBody = document.querySelector('#idsTable tbody');
    idsBody.innerHTML = '';
    document.querySelector('#idsEmpty').style.display = events.length ? 'none' : 'block';
    for (const line of events.slice().reverse()) {
      const tr = document.createElement('tr');
      if (line.includes('АТАКА') || line.includes('ЗАБЛОКИРОВАН')) tr.className = 'attack';
      const m = line.match(/^\\[(.*?)\\]\\s*(.*)$/);
      tr.innerHTML = m ? `<td>${m[1]}</td><td>${m[2]}</td>` : `<td></td><td>${line}</td>`;
      idsBody.appendChild(tr);
    }
  } catch (e) {}
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


def _tail_lines(path: str, limit: int = 200):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()[-limit:]
    return [l.rstrip("\n") for l in lines if l.strip()]


@app.route("/")
def index():
    return PAGE


@app.route("/api/requests")
def api_requests():
    return jsonify(_tail_jsonl(REQUESTS_LOG))


@app.route("/api/ids_events")
def api_ids_events():
    return jsonify(_tail_lines(IDS_LOG))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=False)
