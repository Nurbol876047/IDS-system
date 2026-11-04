#!/bin/bash
# start_live_engine.sh — запускает живой сетевой IDS (live_capture_engine.py).
#
# Не нужен ни sudo, ни CICFlowMeter/Java: движок сам поднимает короткие
# циклы tcpdump (без прав root — если tcpdump/dumpcap в системе имеют
# capability cap_net_raw, см. README) и сам считает признаки потоков.
#
# Использование:
#   ./demo/start_live_engine.sh [интерфейс]   # по умолчанию lo

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IDS_DIR="$(cd "$SCRIPT_DIR/../ids-project" && pwd)"
IFACE="${1:-lo}"

mkdir -p "$SCRIPT_DIR/logs"

echo ">>> Запускаю live_capture_engine.py на интерфейсе '$IFACE'"
cd "$IDS_DIR"
nohup ./venv/bin/python3 live_capture_engine.py --iface "$IFACE" \
    > "$SCRIPT_DIR/logs/live_engine.log" 2>&1 &
PID=$!
echo "    PID: $PID"
echo ">>> Лог процесса: demo/logs/live_engine.log"
echo ">>> События и вердикты: ids-project/ids_events.log — сразу видно на дашборде http://127.0.0.1:5050"
echo ">>> Остановить: kill $PID"
