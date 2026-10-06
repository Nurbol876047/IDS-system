"""
target_server/app.py — мок веб-сайт "жертва" для демонстрации IDS-проекта.

Логирует каждый HTTP-запрос (кто зашёл, когда, на какой адрес) в JSONL-файл
../logs/target_requests.log — этот лог показывается на дашборде как
"прикладной" уровень (кто как заходил на сайт).

Отдельно от этого работает сетевой IDS (CICFlowMeter + ML-модель из
ids-project) — он смотрит на уровень TCP/IP пакетов, а не на HTTP, поэтому
у него свой лог (ids-project/ids_events.log), который дашборд показывает
вторым блоком.

Эндпоинт /simulate/flood запускает короткий управляемый всплеск запросов
САМ К СЕБЕ (127.0.0.1), чтобы дать сетевому IDS сигнал, похожий на
DDoS/бот-наплыв, — без выхода за пределы localhost.
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime

from flask import Flask, request, redirect, url_for

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "..", "logs", "target_requests.log")
ATTACK_SIM_DIR = os.path.join(BASE_DIR, "..", "attack_sim")

app = Flask(__name__)

# Сайт может быть временно открыт наружу (туннель) для демонстрации проекта
# удалённым людям — защищаем кнопку "запустить флуд" от повторного нажатия
# кем угодно чаще, чем раз в COOLDOWN секунд, чтобы случайный посетитель не
# мог бесконечно грузить машину.
FLOOD_COOLDOWN_SEC = 30
_last_flood_at = 0.0

PAGE = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Digital Detective — мок-сайт жертвы</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 720px; margin: 40px auto; padding: 0 16px; }}
  h1 {{ font-size: 20px; }}
  .card {{ border: 1px solid #ddd; border-radius: 10px; padding: 16px; margin-bottom: 16px; }}
  button, input[type=submit] {{ padding: 8px 14px; border-radius: 6px; border: 1px solid #ccc; background: #f6f6f6; cursor: pointer; }}
  button:hover {{ background: #eee; }}
  .danger {{ background: #ffecec; border-color: #ff8a8a; }}
  .ok {{ color: #1a7f37; }}
  input[type=text] {{ padding: 6px; width: 60%; }}
  .muted {{ color: #777; font-size: 13px; }}
</style>
</head>
<body>
<h1>🔎 Digital Detective — учебная «жертва»</h1>
<p class="muted">Простой сайт для демонстрации работы IDS. Каждый запрос пишется в лог
  <code>demo/logs/target_requests.log</code>. Параллельно сетевой IDS (CICFlowMeter + ML)
  следит за трафиком на уровне пакетов — его вердикты смотри на дашборде.</p>

<div class="card">
  <h3>Обычный визит</h3>
  <form action="/visit" method="get"><button>Зайти на страницу (как обычный пользователь)</button></form>
</div>

<div class="card">
  <h3>Поиск (вход для демонстрации XSS)</h3>
  <form action="/search" method="get">
    <input type="text" name="q" placeholder="введите запрос, например <script>alert(1)</script>">
    <input type="submit" value="Искать">
  </form>
  <p class="muted">Поле специально не экранирует ввод — учебный пример отражённой XSS.</p>
</div>

<div class="card danger">
  <h3>⚡ Симулировать DDoS / бот-наплыв</h3>
  <form action="/simulate/flood" method="post">
    <input type="submit" value="Запустить всплеск запросов (10 сек, localhost)">
  </form>
  <p class="muted">Шлёт короткую серию запросов сам себе на 127.0.0.1, чтобы сетевой IDS увидел
     аномальный трафик. Не выходит за пределы этой машины.</p>
</div>

{status}

</body>
</html>
"""


def log_request(tag: str, extra: dict | None = None):
    entry = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "ip": request.remote_addr,
        "method": request.method,
        "path": request.full_path if request.query_string else request.path,
        "ua": request.headers.get("User-Agent", "?"),
        "tag": tag,
    }
    if extra:
        entry.update(extra)
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


@app.route("/")
def home():
    log_request("home")
    return PAGE.format(status="")


@app.route("/visit")
def visit():
    log_request("visit")
    return PAGE.format(status='<p class="ok">✅ Зашёл как обычный пользователь.</p>')


@app.route("/search")
def search():
    q = request.args.get("q", "")
    log_request("search", {"query": q})
    # Намеренно НЕ экранируем q — учебная демонстрация отражённой XSS.
    return PAGE.format(status=f'<p>Результаты поиска по запросу: {q}</p>')


@app.route("/api/ping")
def ping():
    # Лёгкий эндпоинт-цель для флуд-симуляции, не пишет в основной лог,
    # чтобы не раздувать его тысячами строк при каждом тесте.
    return "pong", 200


@app.route("/simulate/flood", methods=["POST"])
def simulate_flood():
    global _last_flood_at
    now = time.time()
    if now - _last_flood_at < FLOOD_COOLDOWN_SEC:
        wait_left = int(FLOOD_COOLDOWN_SEC - (now - _last_flood_at))
        log_request("flood_rejected_cooldown")
        return PAGE.format(
            status=f'<p>⏳ Уже запускали недавно, подожди ещё {wait_left} сек '
                   f'(защита от злоупотреблений, сайт может быть открыт наружу).</p>'
        )
    _last_flood_at = now

    log_request("flood_triggered")
    # Длительность и concurrency фиксированы (не берём из формы/запроса), чтобы
    # удалённый посетитель не мог запросить произвольно большой всплеск.
    duration = "10"
    concurrency = "20"
    script = os.path.join(ATTACK_SIM_DIR, "flood.py")
    subprocess.Popen(
        [sys.executable, script,
         "--url", "http://127.0.0.1:5000/api/ping",
         "--duration", duration,
         "--concurrency", concurrency],
    )
    return PAGE.format(
        status=f'<p class="ok">⚡ Запущен всплеск запросов на {duration} сек '
               f'({concurrency} параллельных потоков). Смотри дашборд.</p>'
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
