"""
predict_once.py — прогоняет один уже готовый CSV с потоками (из CICFlowMeter)
через обученную модель и пишет вердикт в ids_events.log (тот же файл и формат,
что использует live_ids_watcher.py, — чтобы дашборд видел оба источника одинаково).

Используется из capture_and_test.sh после каждого тестового захвата трафика:
нормального или смоделированного флуда.

Запуск:
    python3 predict_once.py --csv data/out/test.pcap_Flow.csv --model_dir ./model_out --note "benign-test"
"""

import argparse
import os

import joblib
import pandas as pd

from live_ids_watcher import align_features, log_event


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True, help="CSV с потоками от CICFlowMeter")
    parser.add_argument("--model_dir", default="./model_out")
    parser.add_argument("--note", default="", help="Метка теста для лога, например 'benign' или 'flood'")
    args = parser.parse_args()

    model = joblib.load(os.path.join(args.model_dir, "ids_model.joblib"))
    scaler = joblib.load(os.path.join(args.model_dir, "scaler.joblib"))
    label_encoder = joblib.load(os.path.join(args.model_dir, "label_encoder.joblib"))
    feature_cols = joblib.load(os.path.join(args.model_dir, "feature_columns.joblib"))

    df = pd.read_csv(args.csv, encoding="latin1", low_memory=False)
    df.columns = [c.strip() for c in df.columns]

    prefix = f"[{args.note}] " if args.note else ""
    log_event(f"{prefix}Тест: {len(df)} поток(ов) из {os.path.basename(args.csv)}")

    if len(df) == 0:
        log_event(f"{prefix}Нет потоков для анализа (слишком короткий захват?)")
        return

    for _, row in df.iterrows():
        row_dict = row.to_dict()
        X_row = align_features(row_dict, feature_cols)
        X_scaled = scaler.transform(X_row.values)

        pred_idx = model.predict(X_scaled)[0]
        pred_label = label_encoder.inverse_transform([pred_idx])[0]

        src_ip = row_dict.get("Src IP", "?")
        dst_port = row_dict.get("Dst Port", "?")

        confidence = ""
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(X_scaled)[0][pred_idx]
            confidence = f", уверенность {proba:.2f}"

        if pred_label == "BENIGN":
            log_event(f"{prefix}BENIGN{confidence} | src={src_ip} -> dst_port={dst_port}")
        else:
            log_event(f"{prefix}АТАКА: {pred_label}{confidence} | src={src_ip} -> dst_port={dst_port}")


if __name__ == "__main__":
    main()
