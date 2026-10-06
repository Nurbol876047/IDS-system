"""
flood.py — короткий управляемый всплеск HTTP-запросов против localhost.

Нужен для демонстрации: генерирует трафик с высокой частотой запросов,
похожий по характеру на (H)TTP-флуд/бот-наплыв, чтобы сетевой IDS
(CICFlowMeter + ML-модель) увидел аномальные значения Flow Packets/s и т.д.

Жёстко ограничен: только localhost, фиксированная длительность, разумный
потолок на concurrency. Это НЕ инструмент для атаки на внешние адреса.

Запуск:
    python3 flood.py --url http://127.0.0.1:5000/api/ping --duration 10 --concurrency 20
"""

import argparse
import threading
import time
import urllib.request

MAX_DURATION = 60
MAX_CONCURRENCY = 50


def worker(url: str, stop_at: float, counter: list, lock: threading.Lock):
    local_count = 0
    while time.time() < stop_at:
        try:
            urllib.request.urlopen(url, timeout=1)
            local_count += 1
        except Exception:
            pass
    with lock:
        counter[0] += local_count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="Куда слать запросы (только localhost!)")
    parser.add_argument("--duration", type=float, default=10.0)
    parser.add_argument("--concurrency", type=int, default=20)
    args = parser.parse_args()

    if "127.0.0.1" not in args.url and "localhost" not in args.url:
        raise SystemExit("Разрешены только запросы на localhost/127.0.0.1")

    duration = min(args.duration, MAX_DURATION)
    concurrency = min(args.concurrency, MAX_CONCURRENCY)

    print(f"[flood] старт: {args.url}, {duration:.0f} сек, {concurrency} потоков")
    stop_at = time.time() + duration
    counter = [0]
    lock = threading.Lock()
    threads = [
        threading.Thread(target=worker, args=(args.url, stop_at, counter, lock))
        for _ in range(concurrency)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    elapsed = duration
    print(f"[flood] готово: {counter[0]} запросов за {elapsed:.0f} сек "
          f"(~{counter[0] / elapsed:.0f} req/s)")


if __name__ == "__main__":
    main()
