#!/bin/bash
# start_pipeline_watcher.sh — несудошная половина живого конвейера.
#
# Параллельно с этим должен уже крутиться:
#   sudo tcpdump -i lo -w CICFlowMeter/data/in/live_%Y%m%d_%H%M%S.pcap -G 20 -W 100
# (его нужно запускать отдельно, вручную, см. README в чате — требует root).
#
# Этот скрипт раз в 10 сек прогоняет накопленные в data/in pcap-файлы через
# CICFlowMeter (process_pcap.sh) и держит запущенным live_ids_watcher.py,
# который подхватывает получившиеся CSV и классифицирует их моделью —
# результат падает в ids_events.log и сразу виден на дашборде.
#
# Ничего из этого не требует sudo.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CICFM_DIR="$(cd "$SCRIPT_DIR/../CICFlowMeter" && pwd)"
IDS_DIR="$(cd "$SCRIPT_DIR/../ids-project" && pwd)"

mkdir -p "$CICFM_DIR/data/in" "$CICFM_DIR/data/out" "$CICFM_DIR/data/processed"
mkdir -p "$SCRIPT_DIR/logs"

echo ">>> Запускаю фоновый обработчик pcap -> CICFlowMeter (каждые 10 сек)"
(
    cd "$CICFM_DIR"
    while true; do
        ./process_pcap.sh
        sleep 10
    done
) > "$SCRIPT_DIR/logs/pipeline_processor.log" 2>&1 &
echo "    PID обработчика: $!"

echo ">>> Запускаю live_ids_watcher.py (слежение за data/out, классификация)"
cd "$IDS_DIR"
nohup ./venv/bin/python3 live_ids_watcher.py \
    --flows_dir "$CICFM_DIR/data/out" \
    --model_dir ./model_out \
    --poll_interval 5 \
    > "$SCRIPT_DIR/logs/live_watcher.log" 2>&1 &
echo "    PID watcher'а: $!"

echo ">>> Готово. Логи: demo/logs/pipeline_processor.log и demo/logs/live_watcher.log"
echo ">>> Убедись, что sudo tcpdump с -G 20 уже запущен отдельно (см. инструкцию)."
