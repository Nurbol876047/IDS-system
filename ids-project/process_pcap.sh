#!/bin/bash
# process_pcap.sh — вызывается автоматически tcpdump'ом (через флаг -z) каждый
# раз, когда закрывается очередной нарезанный pcap-файл. Прогоняет весь
# накопленный data/in через CICFlowMeter (exeCMD) и убирает обработанные
# pcap-файлы в архив, чтобы не пересчитывать их повторно на следующей итерации.
#
# Использование напрямую руками не требуется — просто положи этот файл
# рядом с build.gradle (внутри папки CICFlowMeter) и укажи путь к нему
# в команде tcpdump через -z (см. инструкцию в чате).

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

LOCK_FILE="$PROJECT_DIR/.process_pcap.lock"
LOG_FILE="$PROJECT_DIR/pipeline.log"

# flock не даёт двум запускам работать одновременно, если ротация файлов
# произойдёт чаще, чем успевает отработать обработка
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    echo "$(date): предыдущая обработка ещё не завершилась, пропускаю" >> "$LOG_FILE"
    exit 0
fi

mkdir -p data/in data/out data/processed

# Ничего обрабатывать не нужно, если data/in пуста
if [ -z "$(ls -A data/in 2>/dev/null)" ]; then
    exit 0
fi

echo "$(date): запускаю CICFlowMeter на $(ls data/in | wc -l) файле(ах)" >> "$LOG_FILE"

JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64/jre ./gradlew exeCMD >> "$LOG_FILE" 2>&1

# Убираем обработанные pcap, чтобы при следующем запуске не считать их снова
mv data/in/*.pcap data/processed/ 2>/dev/null || true

echo "$(date): готово" >> "$LOG_FILE"
