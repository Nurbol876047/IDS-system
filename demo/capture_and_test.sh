#!/bin/bash
# capture_and_test.sh <benign|flood> [duration_seconds]
#
# Один тестовый прогон "вживую": захватывает трафик на loopback во время
# теста, прогоняет pcap через CICFlowMeter (извлечение признаков потока),
# затем через обученную ML-модель IDS (ids-project) и пишет вердикт в
# ids_events.log — он сразу появится на дашборде (http://127.0.0.1:5050).
#
# benign — несколько обычных запросов к мок-сайту (ожидаем BENIGN)
# flood  — короткий управляемый всплеск запросов через attack_sim/flood.py
#          (ожидаем, что IDS отметит аномалию)
# scan   — nmap SYN-скан портов на 127.0.0.1 (ожидаем класс PortScan)
#
# Перед запуском должен работать мок-сайт: python3 target_server/app.py
#
# Для tcpdump (и nmap -sS) нужны root-права — пароль спросится один раз в начале.

set -e

MODE="${1:-benign}"
DURATION="${2:-15}"

if [[ "$MODE" != "benign" && "$MODE" != "flood" && "$MODE" != "scan" ]]; then
    echo "Использование: $0 <benign|flood|scan> [duration_seconds]"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CICFM_DIR="$(cd "$SCRIPT_DIR/../CICFlowMeter" && pwd)"
IDS_DIR="$(cd "$SCRIPT_DIR/../ids-project" && pwd)"

TS=$(date +%Y%m%d_%H%M%S)
PCAP_NAME="${MODE}_${TS}.pcap"
PCAP_PATH="$CICFM_DIR/data/in/$PCAP_NAME"

mkdir -p "$CICFM_DIR/data/in" "$CICFM_DIR/data/out"

# На этой машине профиль AppArmor /etc/apparmor.d/usr.bin.tcpdump не содержит
# правил "signal" — из-за этого ядро блокирует ЛЮБОЙ сигнал (SIGTERM, даже
# SIGKILL) процессу tcpdump, включая от root. `timeout`/`kill -9` поэтому
# бессильны и процесс зависает навсегда. Обходим это без сигналов вообще:
# просим tcpdump самостоятельно завершиться после N пакетов (-c), а не по
# таймеру. Длительность (DURATION) по-прежнему определяет, сколько времени
# генерируется тестовый трафик.
case "$MODE" in
    benign) PACKET_COUNT=50 ;;
    flood)  PACKET_COUNT=1500 ;;
    scan)   PACKET_COUNT=600 ;;
esac

echo ">>> Режим: $MODE, длительность трафика: ${DURATION}s, захват: $PACKET_COUNT пакетов"
echo ">>> Нужен sudo для захвата трафика (tcpdump) — введи пароль:"
sudo -v

echo ">>> Захват трафика на lo -> $PCAP_PATH (до $PACKET_COUNT пакетов)"
sudo tcpdump -i lo -c "$PACKET_COUNT" -w "$PCAP_PATH" -U >/dev/null 2>&1 &
TCPDUMP_PID=$!

sleep 1  # дать tcpdump подняться перед тем как генерировать трафик

if [ "$MODE" = "flood" ]; then
    FLOOD_DURATION=$((DURATION > 3 ? DURATION - 2 : 1))
    echo ">>> Запускаю flood.py на ${FLOOD_DURATION}s против http://127.0.0.1:5000/api/ping"
    python3 "$SCRIPT_DIR/attack_sim/flood.py" \
        --url http://127.0.0.1:5000/api/ping \
        --duration "$FLOOD_DURATION" \
        --concurrency 20
elif [ "$MODE" = "scan" ]; then
    echo ">>> Запускаю nmap SYN-скан портов 1-1000 на 127.0.0.1"
    sudo nmap -sS -T4 -p 1-1000 127.0.0.1 >/dev/null
else
    echo ">>> Имитирую обычный трафик (несколько запросов раз в секунду)"
    for i in $(seq 1 "$((DURATION > 5 ? 5 : DURATION))"); do
        curl -s http://127.0.0.1:5000/visit > /dev/null || true
        sleep 1
    done
fi

echo ">>> Трафик сгенерирован, жду пока tcpdump наберёт $PACKET_COUNT пакетов и сам завершится..."
echo "    (если зависнет надолго — держите открытым дашборд, его опрос тоже даёт пакеты)"
wait "$TCPDUMP_PID" 2>/dev/null || true

sudo chown "$(whoami)" "$PCAP_PATH"

echo ">>> Прогоняю захват через CICFlowMeter"
cd "$CICFM_DIR"
JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 ./gradlew exeCMD

CSV_PATH="$CICFM_DIR/data/out/${PCAP_NAME}_Flow.csv"

if [ ! -f "$CSV_PATH" ]; then
    echo "!!! CSV не создан — в захвате, похоже, не было ни одного завершённого потока."
    exit 1
fi

echo ">>> Прогоняю через ML-модель IDS"
cd "$IDS_DIR"
./venv/bin/python3 predict_once.py --csv "$CSV_PATH" --note "$MODE"

echo ">>> Готово. Результат: $IDS_DIR/ids_events.log или дашборд http://127.0.0.1:5050"
