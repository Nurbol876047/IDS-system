"""
live_ids_watcher.py — модуль реального времени: детекция + блокировка атак
=============================================================================

Идея работы:
  1. Отдельно запущенный CICFlowMeter (тот же инструмент, которым изначально
     собирался CICIDS2017) слушает сетевой интерфейс и каждые ~2 минуты
     (таймаут потока) дописывает завершённые потоки в CSV-файл в указанной
     папке. Названия колонок у него ТЕ ЖЕ, что и в датасете, на котором
     обучалась модель — это критично для точности.
  2. Этот скрипт следит за папкой как `tail -f`: подхватывает новые строки,
     выравнивает их под feature_columns.joblib, прогоняет через модель.
  3. Если предсказан не-BENIGN класс — логирует и (если включён --enforce)
     блокирует Source IP через iptables.

--------------------------------------------------------------------------
ШАГ 0. Установка CICFlowMeter (делается один раз, отдельно от этого скрипта)
--------------------------------------------------------------------------
  1) Нужен JDK 8+:      sudo apt install openjdk-11-jdk
  2) Клонируй репозиторий:
         git clone https://github.com/ahlashkari/CICFlowMeter.git
         cd CICFlowMeter
  3) Собери и запусти live-захват на нужном интерфейсе (например eth0),
     с выводом CSV в папку ./flows_live (создай её заранее: mkdir flows_live):
         sudo ./gradlew execute -PmainClass=cic.cs.unb.ca.jnetpcap.app.CICFlowMeter
     Либо через готовый jar/CLI, если использовался релиз — команда захвата
     обычно выглядит как:
         sudo bin/CICFlowMeter -i eth0 -o ./flows_live
     Точный синтаксис зависит от версии сборки — см. README в репозитории,
     он периодически меняется между релизами.
  4) Убедись, что в ./flows_live начали появляться и расти *.csv файлы.

--------------------------------------------------------------------------
ШАГ 1. Запуск этого скрипта (в другом терминале, пока CICFlowMeter работает)
--------------------------------------------------------------------------
  Сначала в режиме наблюдения, БЕЗ реальной блокировки (безопасно, только лог):
      python3 live_ids_watcher.py --flows_dir ./flows_live --model_dir ./model_out

  Когда убедишься, что детекция работает адекватно (посмотри лог несколько
  минут, проверь, что не блокирует легитимный трафик по ошибке) — включи
  реальную блокировку через iptables:
      sudo python3 live_ids_watcher.py --flows_dir ./flows_live --model_dir ./model_out --enforce

  ВАЖНО: --enforce требует root (iptables), и без него скрипт ничего не
  блокирует — только печатает и пишет в лог, что заблокировал бы.
"""

import argparse
import glob
import os
import subprocess
import time
from datetime import datetime

import joblib
import numpy as np
import pandas as pd

LOG_FILE = "ids_events.log"

# IP, которые никогда не блокируем, даже если модель сочтёт их атакой —
# подставь сюда свой собственный IP / шлюз / IP, с которого сам администрируешь сервер,
# чтобы случайно не заблокировать самого себя.
NEVER_BLOCK = {"127.0.0.1"}


def log_event(msg: str):
    line = f"[{datetime.now().isoformat(timespec='seconds')}] {msg}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def block_ip(ip: str, enforce: bool, already_blocked: set):
    if ip in NEVER_BLOCK:
        log_event(f"IP {ip} в списке NEVER_BLOCK — пропускаю блокировку")
        return
    if ip in already_blocked:
        return  # уже заблокирован в этом запуске, не дублируем команду

    if enforce:
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
            )
            log_event(f"ЗАБЛОКИРОВАН {ip} (iptables DROP)")
        except subprocess.CalledProcessError as e:
            log_event(f"ОШИБКА при блокировке {ip}: {e}")
        except FileNotFoundError:
            log_event("iptables не найден в системе — блокировка невозможна")
    else:
        log_event(f"[DRY-RUN] заблокировал бы {ip} (запусти с --enforce и от root, чтобы применить)")

    already_blocked.add(ip)


class FlowFileWatcher:
    """Следит за CSV-файлами в папке, отдаёт только новые строки (как tail -f)."""

    def __init__(self, flows_dir: str):
        self.flows_dir = flows_dir
        self.positions = {}  # путь к файлу -> байтовая позиция, до которой уже прочитано
        self.headers = {}  # путь к файлу -> список колонок (из первой строки)

    def poll_new_rows(self):
        rows = []
        for path in glob.glob(os.path.join(self.flows_dir, "*.csv")):
            size = os.path.getsize(path)
            last_pos = self.positions.get(path, 0)
            if size <= last_pos:
                continue  # ничего нового не дописано

            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(last_pos)
                new_lines = f.read()
                self.positions[path] = f.tell()

            if path not in self.headers:
                # первая порция чтения этого файла — первая строка это заголовок
                lines = new_lines.splitlines()
                if not lines:
                    continue
                self.headers[path] = [c.strip() for c in lines[0].split(",")]
                data_lines = lines[1:]
            else:
                data_lines = new_lines.splitlines()

            header = self.headers[path]
            for line in data_lines:
                if not line.strip():
                    continue
                values = line.split(",")
                if len(values) != len(header):
                    continue  # битая/неполная строка, пропускаем
                rows.append(dict(zip(header, values)))

        return rows


# Модель обучена на оригинальных колонках CICIDS2017 (CICFlowMeter старой версии),
# а живой захват идёт через ahlashkari/CICFlowMeter V4, который часть колонок
# называет иначе. Соответствие: имя признака модели -> имя колонки в живом CSV.
COLUMN_ALIASES = {
    "Destination Port": "Dst Port",
    "Total Fwd Packets": "Total Fwd Packet",
    "Total Backward Packets": "Total Bwd packets",
    "Total Length of Fwd Packets": "Total Length of Fwd Packet",
    "Total Length of Bwd Packets": "Total Length of Bwd Packet",
    "Min Packet Length": "Packet Length Min",
    "Max Packet Length": "Packet Length Max",
    "CWE Flag Count": "CWR Flag Count",
    "Avg Fwd Segment Size": "Fwd Segment Size Avg",
    "Avg Bwd Segment Size": "Bwd Segment Size Avg",
    "Fwd Header Length.1": "Fwd Header Length",
    "Init_Win_bytes_forward": "FWD Init Win Bytes",
    "Init_Win_bytes_backward": "Bwd Init Win Bytes",
    "act_data_pkt_fwd": "Fwd Act Data Pkts",
    "min_seg_size_forward": "Fwd Seg Size Min",
}


def align_features(row: dict, feature_cols: list) -> pd.DataFrame:
    """
    Приводит сырую строку от CICFlowMeter к точному набору и порядку колонок,
    на которых обучалась модель. Недостающие признаки заполняются нулём,
    лишние (Flow ID, IP-адреса, порты, Timestamp) отбрасываются — модель
    их не видела при обучении.
    """
    numeric_row = {}
    for col in feature_cols:
        raw = row.get(col) or row.get(col.strip())
        if raw is None:
            alias = COLUMN_ALIASES.get(col)
            if alias:
                raw = row.get(alias)
        try:
            val = float(raw)
            if not np.isfinite(val):
                val = 0.0
        except (TypeError, ValueError):
            val = 0.0
        numeric_row[col] = val

    return pd.DataFrame([numeric_row], columns=feature_cols)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--flows_dir", required=True, help="Папка, куда CICFlowMeter пишет CSV с потоками")
    parser.add_argument("--model_dir", required=True, help="Папка с ids_model.joblib и др. (из train_ids_model.py)")
    parser.add_argument("--poll_interval", type=float, default=5.0, help="Как часто проверять новые данные, сек")
    parser.add_argument("--enforce", action="store_true", help="Реально блокировать через iptables (нужен root). Без флага — только лог, dry-run.")
    args = parser.parse_args()

    model = joblib.load(os.path.join(args.model_dir, "ids_model.joblib"))
    scaler = joblib.load(os.path.join(args.model_dir, "scaler.joblib"))
    label_encoder = joblib.load(os.path.join(args.model_dir, "label_encoder.joblib"))
    feature_cols = joblib.load(os.path.join(args.model_dir, "feature_columns.joblib"))

    log_event(f"Модель загружена. Классы: {list(label_encoder.classes_)}")
    log_event(f"Слежу за {args.flows_dir}, режим: {'ENFORCE (реальная блокировка)' if args.enforce else 'DRY-RUN (только лог)'}")

    watcher = FlowFileWatcher(args.flows_dir)
    already_blocked = set()

    try:
        while True:
            new_rows = watcher.poll_new_rows()
            for row in new_rows:
                # CICFlowMeter обычно называет эти колонки 'Src IP' и 'Dst Port'
                src_ip = row.get("Src IP") or row.get("Source IP") or "unknown"
                dst_port = row.get("Dst Port") or row.get("Destination Port") or "?"

                X_row = align_features(row, feature_cols)
                X_scaled = scaler.transform(X_row.values)

                pred_idx = model.predict(X_scaled)[0]
                pred_label = label_encoder.inverse_transform([pred_idx])[0]

                if pred_label != "BENIGN":
                    confidence = ""
                    if hasattr(model, "predict_proba"):
                        proba = model.predict_proba(X_scaled)[0][pred_idx]
                        confidence = f", уверенность {proba:.2f}"
                    log_event(
                        f"АТАКА: {pred_label}{confidence} | src={src_ip} -> dst_port={dst_port}"
                    )
                    block_ip(src_ip, args.enforce, already_blocked)

            time.sleep(args.poll_interval)

    except KeyboardInterrupt:
        log_event("Остановлено пользователем (Ctrl+C)")


if __name__ == "__main__":
    main()
