"""
CICIDS2017 — обучение модели детектора сетевых атак
=====================================================

Что делает скрипт:
  1. Загружает все CSV-файлы CICIDS2017 из указанной папки и объединяет их
  2. Чистит данные: убирает Inf/NaN, дубликаты, лишние пробелы в названиях колонок
  3. Нормализует метки классов (в датасете встречаются опечатки типа
     "Web Attack \xe2\x80\x93 Brute Force" с разными тире/пробелами)
  4. Кодирует метки для МНОГОКЛАССОВОЙ классификации (тип атаки, а не просто "атака/не атака")
  5. Делит на train/test со стратификацией
  6. Балансирует редкие классы (SMOTE) с ограничением, чтобы не взорвать память
  7. Обучает RandomForest и XGBoost, сравнивает по F1 (macro)
  8. Печатает classification_report и confusion matrix для лучшей модели
  9. Сохраняет модель, scaler, list фичей и энкодер меток — они понадобятся
     для live-детекции трафика на сервере (следующий шаг)

Запуск:
    python train_ids_model.py --data_dir /path/to/cicids2017_csvs --out_dir ./model_out

Требования:
    pip install -r requirements.txt
"""

import argparse
import glob
import os
import re
import time
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

warnings.filterwarnings("ignore")


# ---------------------------------------------------------------------------
# 1. Загрузка и объединение CSV
# ---------------------------------------------------------------------------
def load_dataset(data_dir: str) -> pd.DataFrame:
    csv_files = glob.glob(os.path.join(data_dir, "*.csv"))
    if not csv_files:
        raise FileNotFoundError(
            f"В папке {data_dir} не найдено ни одного .csv. "
            "Проверь, что скачал и распаковал CICIDS2017 (MachineLearningCSV)."
        )

    print(f"Найдено файлов: {len(csv_files)}")
    frames = []
    for f in csv_files:
        print(f"  читаю {os.path.basename(f)} ...")
        # encoding='latin1' — в некоторых файлах CICIDS2017 попадаются не-UTF8 байты
        df = pd.read_csv(f, encoding="latin1", low_memory=False)
        frames.append(df)

    full_df = pd.concat(frames, ignore_index=True)
    print(f"Всего строк после объединения: {len(full_df)}")

    # В CICIDS2017 у колонок часто есть ведущие/замыкающие пробелы, например " Label"
    full_df.columns = [c.strip() for c in full_df.columns]
    return full_df


# ---------------------------------------------------------------------------
# 2. Очистка данных
# ---------------------------------------------------------------------------
def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    label_col = "Label"
    if label_col not in df.columns:
        raise KeyError(
            f"Не нашёл колонку '{label_col}'. Доступные колонки: {list(df.columns)[:10]}..."
        )

    # Нормализация меток: разные виды тире/дефисов и лишние пробелы к единому виду
    def normalize_label(x: str) -> str:
        x = str(x).strip()
        x = re.sub(r"[\u2010-\u2015\u2212]", "-", x)  # разные виды тире -> "-"
        x = re.sub(r"\s+", " ", x)
        return x

    df[label_col] = df[label_col].apply(normalize_label)

    # Числовые колонки: приводим к float, заменяем Inf на NaN
    feature_cols = [c for c in df.columns if c != label_col]
    for c in feature_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce")

    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    before = len(df)
    df.dropna(inplace=True)
    print(f"Удалено строк с NaN/Inf: {before - len(df)}")

    before = len(df)
    df.drop_duplicates(inplace=True)
    print(f"Удалено дубликатов: {before - len(df)}")

    # Колонки без вариативности (константы) бесполезны для модели
    nunique = df[feature_cols].nunique()
    constant_cols = nunique[nunique <= 1].index.tolist()
    if constant_cols:
        print(f"Удаляю константные признаки: {constant_cols}")
        df.drop(columns=constant_cols, inplace=True)

    return df


# ---------------------------------------------------------------------------
# 3. Отбор редких классов (опционально объединяем очень редкие атаки, чтобы
#    SMOTE/модель не ломались на классах из 5-10 примеров)
# ---------------------------------------------------------------------------
def report_class_counts(df: pd.DataFrame, label_col="Label"):
    counts = df[label_col].value_counts()
    print("\nРаспределение классов:")
    print(counts)
    return counts


# ---------------------------------------------------------------------------
# 4. Балансировка через SMOTE (с разумным cap на размер, чтобы не взорвать RAM)
# ---------------------------------------------------------------------------
def balance_classes(X_train, y_train, min_samples=2000, cap=None):
    """
    Подтягивает малочисленные классы до min_samples через SMOTE.
    Классы, у которых и так больше min_samples, не трогаем (и, если задан cap,
    можно дополнительно урезать доминирующий класс BENIGN через downsampling).
    """
    from collections import Counter

    from imblearn.over_sampling import SMOTE
    from imblearn.under_sampling import RandomUnderSampler

    counts = Counter(y_train)
    print("\nКлассы до балансировки:", counts)

    # SMOTE не может создавать примеры для класса из <2 сэмплов -> отфильтруем такие отдельно
    too_rare = [cls for cls, n in counts.items() if n < 2]
    if too_rare:
        print(f"Внимание: классы с <2 примерами будут исключены из балансировки: {too_rare}")

    sampling_strategy = {
        cls: max(n, min_samples) for cls, n in counts.items() if cls not in too_rare
    }

    smote = SMOTE(sampling_strategy=sampling_strategy, random_state=42, k_neighbors=3)
    X_res, y_res = smote.fit_resample(X_train, y_train)

    if cap is not None:
        under_strategy = {
            cls: min(n, cap) for cls, n in Counter(y_res).items()
        }
        rus = RandomUnderSampler(sampling_strategy=under_strategy, random_state=42)
        X_res, y_res = rus.fit_resample(X_res, y_res)

    print("Классы после балансировки:", Counter(y_res))
    return X_res, y_res


# ---------------------------------------------------------------------------
# 5. Обучение и сравнение моделей
# ---------------------------------------------------------------------------
def train_random_forest(X_train, y_train):
    print("\n--- Обучаю Random Forest ---")
    t0 = time.time()
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        n_jobs=-1,
        class_weight="balanced_subsample",
        random_state=42,
    )
    model.fit(X_train, y_train)
    print(f"RandomForest обучен за {time.time() - t0:.1f} сек")
    return model


def train_xgboost(X_train, y_train, num_classes):
    print("\n--- Обучаю XGBoost ---")
    from xgboost import XGBClassifier

    t0 = time.time()
    model = XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="multi:softmax",
        num_class=num_classes,
        tree_method="hist",
        n_jobs=-1,
        random_state=42,
        eval_metric="mlogloss",
    )
    model.fit(X_train, y_train)
    print(f"XGBoost обучен за {time.time() - t0:.1f} сек")
    return model


def evaluate(model, X_test, y_test, label_encoder, name):
    print(f"\n=== Оценка модели: {name} ===")
    y_pred = model.predict(X_test)
    f1_macro = f1_score(y_test, y_pred, average="macro")
    print(f"F1 (macro): {f1_macro:.4f}")
    print(
        classification_report(
            y_test, y_pred, target_names=label_encoder.classes_, zero_division=0
        )
    )
    cm = confusion_matrix(y_test, y_pred)
    return f1_macro, cm


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data_dir", required=True, help="Папка с CSV-файлами CICIDS2017")
    parser.add_argument("--out_dir", default="./model_out", help="Куда сохранить модель")
    parser.add_argument(
        "--min_samples", type=int, default=2000, help="Минимум сэмплов на класс после SMOTE"
    )
    parser.add_argument(
        "--cap", type=int, default=50000, help="Максимум сэмплов на класс (downsampling BENIGN)"
    )
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    # 1-2. Загрузка и очистка
    df = load_dataset(args.data_dir)
    df = clean_dataset(df)
    report_class_counts(df)

    label_col = "Label"
    feature_cols = [c for c in df.columns if c != label_col]

    # 3. Кодирование меток (многоклассовая классификация — тип атаки)
    le = LabelEncoder()
    y = le.fit_transform(df[label_col])
    X = df[feature_cols].values

    print(f"\nКлассы ({len(le.classes_)}): {list(le.classes_)}")

    # 4. Train/test split со стратификацией
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 5. Масштабирование признаков (важно для стабильности, особенно для будущих
    #    нейросетевых экспериментов; для деревьев не критично, но не мешает)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 6. Балансировка только train-части (test должен остаться "естественным")
    X_train_bal, y_train_bal = balance_classes(
        X_train_scaled, y_train, min_samples=args.min_samples, cap=args.cap
    )

    # 7. Обучение и сравнение моделей
    results = {}

    rf_model = train_random_forest(X_train_bal, y_train_bal)
    f1_rf, cm_rf = evaluate(rf_model, X_test_scaled, y_test, le, "RandomForest")
    results["random_forest"] = (rf_model, f1_rf, cm_rf)

    try:
        xgb_model = train_xgboost(X_train_bal, y_train_bal, num_classes=len(le.classes_))
        f1_xgb, cm_xgb = evaluate(xgb_model, X_test_scaled, y_test, le, "XGBoost")
        results["xgboost"] = (xgb_model, f1_xgb, cm_xgb)
    except ImportError:
        print("\nxgboost не установлен (pip install xgboost) — пропускаю сравнение с ним.")

    # 8. Выбор лучшей модели по F1 macro
    best_name = max(results, key=lambda k: results[k][1])
    best_model, best_f1, best_cm = results[best_name]
    print(f"\n>>> Лучшая модель: {best_name} (F1 macro = {best_f1:.4f})")

    # 9. Сохранение всего, что понадобится для live-детекции на сервере
    joblib.dump(best_model, os.path.join(args.out_dir, "ids_model.joblib"))
    joblib.dump(scaler, os.path.join(args.out_dir, "scaler.joblib"))
    joblib.dump(le, os.path.join(args.out_dir, "label_encoder.joblib"))
    joblib.dump(feature_cols, os.path.join(args.out_dir, "feature_columns.joblib"))

    print(f"\nСохранено в {args.out_dir}:")
    print("  ids_model.joblib       — обученная модель")
    print("  scaler.joblib          — StandardScaler для новых данных")
    print("  label_encoder.joblib   — соответствие индекс <-> название класса атаки")
    print("  feature_columns.joblib — точный порядок и названия признаков (важно для live-детекции)")


if __name__ == "__main__":
    main()
