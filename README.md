# IDS-system

Система обнаружения сетевых атак (DDoS, PortScan, Web Attack/XSS, Brute Force,
Heartbleed и т.д.) на базе машинного обучения, обученная на датасете
**CICIDS2017**. Полный пайплайн — захват трафика → расчёт признаков потока →
классификация ML-моделью → лог — работает одним Python-процессом
(`live_capture_engine.py`), без Java/CICFlowMeter и без root. Плюс
демо-стенд для наглядной проверки (мок-сайт жертвы, симулятор нагрузки,
живой дашборд с вердиктами в реальном времени).

## Структура

- **`ids-project/`** — обучение модели и живая детекция.
  - `train_ids_model.py` — обучение (RandomForest/XGBoost) на CSV из CICIDS2017,
    сравнение по F1 (macro), сохранение лучшей модели.
  - `model_out/` — уже обученная модель (`ids_model.joblib` — XGBoost) + scaler +
    label encoder + список признаков.
  - **`live_capture_engine.py`** — основной живой движок (см. «Запуск демо»
    ниже). Сам захватывает трафик на интерфейсе, сам считает ~70 признаков
    потока (как в CICIDS2017) напрямую из пакетов и классифицирует —
    CICFlowMeter/Java не нужны. Логирует **каждый** TCP/UDP-поток (не только
    атаки) в `ids_events.log` (JSONL) — именно так дашборд показывает,
    кто и как заходил на сервер, в реальном времени.
  - `live_ids_watcher.py` / `predict_once.py` / `process_pcap.sh` — старый
    путь через внешний CICFlowMeter (легаси, для желающих воспроизвести
    академический пайплайн один-в-один с оригинальным CICIDS2017; см.
    раздел «Legacy-пайплайн» ниже). Для обычного запуска демо не нужны.

- **`demo/`** — стенд для живой демонстрации (мок-сайт «жертва», дашборд с
  логами в реальном времени, симулятор DDoS-подобной нагрузки, готовые
  тестовые сценарии).

## Как это работает теперь (без CICFlowMeter/Java)

`live_capture_engine.py` сам:
1. Короткими самозавершающимися циклами запускает `tcpdump` (`-G`/`-W`, без
   сигналов — см. ниже почему) и читает получившийся pcap через `scapy`.
2. Агрегирует пакеты в сетевые потоки (5-tuple, с учётом направления
   fwd/bwd) и считает те же ~70 признаков, на которых обучалась модель
   (`Flow Duration`, `Total Fwd/Bwd Packets`, `Flow Bytes/s`, флаги TCP,
   Active/Idle и т.д.) — напрямую из пакетов, без внешнего инструмента и без
   несовпадения названий колонок.
3. При закрытии потока (FIN/RST, таймаут неактивности или истёк возраст)
   прогоняет его через модель и пишет вердикт в `ids_events.log` (JSONL) —
   **для каждого потока**, не только для атак, поэтому на дашборде видно
   вообще весь трафик к серверу, а не только инциденты.

Для захвата не нужен root: нужно, чтобы `tcpdump` (или `dumpcap`) в системе
имел capability `cap_net_raw` на файле — так настроено по умолчанию в
Ubuntu/Debian для членов группы `wireshark`. Проверить:

```bash
getcap /usr/bin/tcpdump   # ожидаем: cap_net_admin,cap_net_raw=eip
groups                    # ваш пользователь должен быть в группе wireshark
```

Если этого нет — либо запускайте движок через `sudo`, либо один раз выполните
`sudo dpkg-reconfigure wireshark-common` (разрешить non-root capture) и
`sudo usermod -aG wireshark $USER` (перелогиниться после этого).

Старый путь через внешний `ahlashkari/CICFlowMeter` (Java/Gradle/jnetpcap,
плюс таблица `COLUMN_ALIASES` из-за разных названий колонок между версиями)
остался в репозитории как legacy-вариант — см. раздел «Legacy-пайплайн» внизу.

## Установка

```bash
cd ids-project
python3 -m venv venv
./venv/bin/pip install scikit-learn xgboost joblib pandas numpy flask scapy
```

## Запуск демо

```bash
# 1. Мок-сайт «жертва» и дашборд
python3 demo/target_server/app.py &      # http://127.0.0.1:5000
python3 demo/dashboard/app.py &          # http://127.0.0.1:5050

# 2. Живой сетевой IDS — следит за lo и видит ЛЮБОЙ TCP/UDP-трафик к серверу
./demo/start_live_engine.sh              # по умолчанию интерфейс lo
```

Открой мок-сайт (`http://127.0.0.1:5000`), покликай по нему, нажми «Запустить
всплеск запросов» — и смотри на дашборде (`http://127.0.0.1:5050`), как в
реальном времени появляются и классифицируются потоки: кто зашёл, на какой
порт, сколько пакетов/байт, и вердикт модели (BENIGN / конкретный класс атаки).

Остановить движок: `kill <PID>` (PID печатается при запуске `start_live_engine.sh`,
либо смотри `ids-project/live_engine.status`).

## Legacy-пайплайн (оригинальный CICFlowMeter, 1:1 с датасетом)

Если нужно воспроизвести детекцию именно так, как в академической версии
проекта (через настоящий `ahlashkari/CICFlowMeter`), а не через собственный
расчёт признаков:

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

Тестовые прогоны (benign / flood / scan) через CICFlowMeter:

```bash
cd demo
./capture_and_test.sh benign 15   # обычный трафик -> ожидаем BENIGN
./capture_and_test.sh flood 15    # управляемый всплеск запросов -> аномалия
./capture_and_test.sh scan 10     # nmap SYN-скан -> класс PortScan
```

Модель обучена на оригинальном датасете CICIDS2017 (колонки вида
`Total Fwd Packets`, `Destination Port`, `CWE Flag Count` и т.д.), а
`ahlashkari/CICFlowMeter` (V4) часть колонок называет иначе (`Total Fwd Packet`,
`Dst Port`, `CWR Flag Count`...) — `live_ids_watcher.py`/`predict_once.py`
компенсируют это таблицей `COLUMN_ALIASES`.

Непрерывный live-режим этим путём:

```bash
sudo tcpdump -i lo -w "CICFlowMeter/data/in/live_%Y%m%d_%H%M%S.pcap" -G 20 -W 200 &
./demo/start_pipeline_watcher.sh
```

tcpdump сам нарезает захват каждые 20 сек (без сигналов — на некоторых системах
AppArmor-профиль `/etc/apparmor.d/usr.bin.tcpdump` блокирует `SIGTERM`/`SIGKILL`
даже от root, поэтому полагаться на `timeout`/`kill` для остановки нельзя —
этим же приёмом, `-G`/`-W` без сигналов, пользуется и новый `live_capture_engine.py`).
