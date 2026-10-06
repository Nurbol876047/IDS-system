# IDS-system

Система обнаружения сетевых атак (DDoS, PortScan, Web Attack/XSS, Brute Force и т.д.)
на базе машинного обучения, обученная на датасете **CICIDS2017**. Полный пайплайн:
захват трафика → извлечение признаков потока (CICFlowMeter) → классификация ML-моделью
→ лог/блокировка. Плюс демо-стенд для наглядной проверки (мок-сайт жертвы,
симулятор нагрузки, живой дашборд).

## Структура

- **`ids-project/`** — обучение модели и живая детекция.
  - `train_ids_model.py` — обучение (RandomForest/XGBoost) на CSV из CICIDS2017,
    сравнение по F1 (macro), сохранение лучшей модели.
  - `model_out/` — уже обученная модель (`ids_model.joblib` — XGBoost) + scaler +
    label encoder + список признаков.
  - `live_ids_watcher.py` — следит за CSV-потоками от CICFlowMeter в реальном
    времени, классифицирует, логирует атаки, может блокировать IP через iptables
    (`--enforce`).
  - `predict_once.py` — разовая классификация уже готового CSV (используется
    тестовыми скриптами из `demo/`).
  - `process_pcap.sh` — обвязка для CICFlowMeter (кладётся в папку CICFlowMeter,
    см. установку ниже).

- **`demo/`** — стенд для живой демонстрации (мок-сайт «жертва», дашборд с
  логами в реальном времени, симулятор DDoS-подобной нагрузки, готовые
  тестовые сценарии).

## Важная деталь: несовпадение версий CICFlowMeter

Модель обучена на оригинальном датасете CICIDS2017 (колонки вида
`Total Fwd Packets`, `Destination Port`, `CWE Flag Count` и т.д.), а для живого
захвата используется современный `ahlashkari/CICFlowMeter` (V4), который часть
колонок называет иначе (`Total Fwd Packet`, `Dst Port`, `CWR Flag Count`...).
Без поправки на это модель на живом трафике получала бы почти все признаки
нулями. `live_ids_watcher.py` и `predict_once.py` содержат явную таблицу
соответствия (`COLUMN_ALIASES`), которая это компенсирует.

## Установка

### 1. Python-зависимости

```bash
cd ids-project
python3 -m venv venv
./venv/bin/pip install scikit-learn xgboost joblib pandas numpy flask
```

### 2. CICFlowMeter (не входит в репозиторий — сторонний инструмент)

```bash
git clone https://github.com/ahlashkari/CICFlowMeter.git
cd CICFlowMeter
cp ../ids-project/process_pcap.sh .
chmod +x process_pcap.sh
mkdir -p data/in data/out data/processed
chmod o+w data/in data/out data/processed   # tcpdump после ротации -G пишет уже от непривилегированного юзера

# Установить jnetpcap в локальный maven-репозиторий
cd jnetpcap/linux/jnetpcap-1.4.r1425
mvn install:install-file -Dfile=jnetpcap.jar -DgroupId=org.jnetpcap -DartifactId=jnetpcap -Dversion=1.4.1 -Dpackaging=jar
cd ../../..

# В build.gradle, в задаче exeCMD, раскомментировать/задать аргументы:
#   args = ["data/in", "data/out"]

JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 ./gradlew compileJava
```

## Запуск демо

```bash
# 1. Мок-сайт жертвы и дашборд
python3 demo/target_server/app.py &      # http://127.0.0.1:5000
python3 demo/dashboard/app.py &          # http://127.0.0.1:5050

# 2. Тестовый прогон: benign / flood / scan
cd demo
./capture_and_test.sh benign 15   # обычный трафик -> ожидаем BENIGN
./capture_and_test.sh flood 15    # управляемый всплеск запросов -> аномалия
./capture_and_test.sh scan 10     # nmap SYN-скан -> класс PortScan
```

Каждый прогон: захватывает трафик на `lo` (нужен root для `tcpdump`/`nmap -sS`),
прогоняет через CICFlowMeter, классифицирует моделью и пишет вердикт в
`ids-project/ids_events.log` — результат сразу виден на дашборде.

## Live-режим (непрерывная детекция)

```bash
sudo tcpdump -i lo -w "CICFlowMeter/data/in/live_%Y%m%d_%H%M%S.pcap" -G 20 -W 200 &
./demo/start_pipeline_watcher.sh
```

tcpdump сам нарезает захват каждые 20 сек (без сигналов — на некоторых системах
AppArmun-профиль `/etc/apparmor.d/usr.bin.tcpdump` блокирует `SIGTERM`/`SIGKILL`
даже от root, поэтому полагаться на `timeout`/`kill` для остановки нельзя).
