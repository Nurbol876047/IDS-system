"""
live_capture_engine.py — автономный живой сетевой IDS без Java/CICFlowMeter.

Идея: раньше для живой детекции нужен был tcpdump с рутом + CICFlowMeter
(Java/Gradle/jnetpcap) + сопоставление колонок (см. live_ids_watcher.py).
Это хрупко и требует ручной многошаговой установки.

Здесь весь конвейер в одном процессе на чистом Python:
  1. Короткими циклами запускаем tcpdump (-G/-W, без прав root — tcpdump/dumpcap
     в этой системе имеют capability cap_net_raw на файле, root не нужен) —
     каждый цикл сам завершается через ROTATE_SEC секунд, сигналы ему не
     нужны (на некоторых системах AppArmor блокирует SIGTERM/SIGKILL для
     tcpdump даже от root — поэтому используем естественное завершение).
  2. Читаем получившийся pcap через scapy и сами агрегируем пакеты в потоки
     (5-tuple, с учётом направления fwd/bwd) — те же ~70 признаков, на
     которых обучалась модель (train_ids_model.py), вычисляются напрямую из
     пакетов, без внешнего инструмента.
  3. Когда поток закрывается (FIN/RST, таймаут неактивности или истёк
     максимальный возраст) — прогоняем его через модель и пишем вердикт
     (BENIGN и атаки — ВСЕ потоки, не только атаки) в ids_events.log в
     формате JSONL, плюс обновляем live_engine.status для дашборда.

Запуск:
    ./venv/bin/python3 live_capture_engine.py --iface lo

Остановка: Ctrl+C (SIGINT штатно доходит до нашего процесса; у дочернего
tcpdump просто не ждём сигналом — он сам завершает текущий короткий цикл).
"""

import argparse
import glob
import json
import math
import os
import signal
import subprocess
import sys
import time
from collections import defaultdict, deque
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from scapy.all import IP, IPv6, TCP, UDP, PcapReader

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

TCP_FLAG_LETTERS = {
    "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
    "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR",
}

NEVER_LOG_PORTS = set()  # зарезервировано на будущее (например, сам движок)


class RunningStats:
    """Потоковое накопление mean/std/min/max/total по Уэлфорду — без хранения всех значений."""

    __slots__ = ("n", "mean", "m2", "lo", "hi", "total")

    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0
        self.lo = None
        self.hi = None
        self.total = 0.0

    def update(self, x: float):
        self.n += 1
        self.total += x
        delta = x - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (x - self.mean)
        if self.lo is None or x < self.lo:
            self.lo = x
        if self.hi is None or x > self.hi:
            self.hi = x

    @property
    def std(self) -> float:
        if self.n < 2:
            return 0.0
        return math.sqrt(self.m2 / self.n)

    @property
    def var(self) -> float:
        if self.n < 2:
            return 0.0
        return self.m2 / self.n

    def get_mean(self) -> float:
        return self.mean if self.n else 0.0

    def get_min(self) -> float:
        return self.lo if self.lo is not None else 0.0

    def get_max(self) -> float:
        return self.hi if self.hi is not None else 0.0


class FlowState:
    """Накопители признаков для одного сетевого потока (bidirectional 5-tuple)."""

    def __init__(self, proto: str, src: str, sport: int, dst: str, dport: int, ts: float):
        self.proto = proto
        self.fwd_src, self.fwd_sport = src, sport
        self.fwd_dst, self.fwd_dport = dst, dport
        self.start_ts = ts
        self.last_ts = ts
        self.cur_active_start = ts

        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0.0
        self.bwd_bytes = 0.0

        self.fwd_len = RunningStats()
        self.bwd_len = RunningStats()
        self.all_len = RunningStats()

        self.flow_iat = RunningStats()
        self.fwd_iat = RunningStats()
        self.bwd_iat = RunningStats()
        self.last_fwd_ts = None
        self.last_bwd_ts = None

        self.flags = {v: 0 for v in TCP_FLAG_LETTERS.values()}
        self.fwd_psh = 0
        self.fwd_urg = 0

        self.fwd_header_sum = 0.0
        self.bwd_header_sum = 0.0
        self.fwd_header_min = None

        self.init_win_fwd = None
        self.init_win_bwd = None
        self.fwd_data_pkts = 0

        self.active = RunningStats()
        self.idle = RunningStats()

        self.closed_reason = None

    def add_packet(self, ts, direction, length, header_len, payload_len, flags, win, activity_timeout):
        has_prior = (self.fwd_packets + self.bwd_packets) > 0
        if has_prior:
            gap = ts - self.last_ts
            if gap > 0:
                self.flow_iat.update(gap * 1e6)
            if gap > activity_timeout:
                active_dur = max(self.last_ts - self.cur_active_start, 0.0) * 1e6
                self.active.update(active_dur)
                self.idle.update(gap * 1e6)
                self.cur_active_start = ts
        self.last_ts = ts

        if direction == "fwd":
            if self.last_fwd_ts is not None:
                d = ts - self.last_fwd_ts
                if d > 0:
                    self.fwd_iat.update(d * 1e6)
            self.last_fwd_ts = ts
            self.fwd_packets += 1
            self.fwd_bytes += length
            self.fwd_len.update(length)
            self.fwd_header_sum += header_len
            if self.fwd_header_min is None or header_len < self.fwd_header_min:
                self.fwd_header_min = header_len
            if payload_len > 0:
                self.fwd_data_pkts += 1
            if win is not None and self.init_win_fwd is None:
                self.init_win_fwd = win
            if flags.get("PSH"):
                self.fwd_psh += 1
            if flags.get("URG"):
                self.fwd_urg += 1
        else:
            if self.last_bwd_ts is not None:
                d = ts - self.last_bwd_ts
                if d > 0:
                    self.bwd_iat.update(d * 1e6)
            self.last_bwd_ts = ts
            self.bwd_packets += 1
            self.bwd_bytes += length
            self.bwd_len.update(length)
            self.bwd_header_sum += header_len
            if win is not None and self.init_win_bwd is None:
                self.init_win_bwd = win

        self.all_len.update(length)
        for name, present in flags.items():
            if present and name in self.flags:
                self.flags[name] += 1

    def finalize(self):
        active_dur = max(self.last_ts - self.cur_active_start, 0.0) * 1e6
        self.active.update(active_dur)

        duration_us = max((self.last_ts - self.start_ts) * 1e6, 0.0)
        duration_sec = duration_us / 1e6
        total_packets = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_bytes + self.bwd_bytes

        def rate(x):
            return x / duration_sec if duration_sec > 0 else 0.0

        num_subflows = max(1, self.idle.n + 1)

        features = {
            "Destination Port": self.fwd_dport,
            "Flow Duration": duration_us,
            "Total Fwd Packets": self.fwd_packets,
            "Total Backward Packets": self.bwd_packets,
            "Total Length of Fwd Packets": self.fwd_bytes,
            "Total Length of Bwd Packets": self.bwd_bytes,
            "Fwd Packet Length Max": self.fwd_len.get_max(),
            "Fwd Packet Length Min": self.fwd_len.get_min(),
            "Fwd Packet Length Mean": self.fwd_len.get_mean(),
            "Fwd Packet Length Std": self.fwd_len.std,
            "Bwd Packet Length Max": self.bwd_len.get_max(),
            "Bwd Packet Length Min": self.bwd_len.get_min(),
            "Bwd Packet Length Mean": self.bwd_len.get_mean(),
            "Bwd Packet Length Std": self.bwd_len.std,
            "Flow Bytes/s": rate(total_bytes),
            "Flow Packets/s": rate(total_packets),
            "Flow IAT Mean": self.flow_iat.get_mean(),
            "Flow IAT Std": self.flow_iat.std,
            "Flow IAT Max": self.flow_iat.get_max(),
            "Flow IAT Min": self.flow_iat.get_min(),
            "Fwd IAT Total": self.fwd_iat.total,
            "Fwd IAT Mean": self.fwd_iat.get_mean(),
            "Fwd IAT Std": self.fwd_iat.std,
            "Fwd IAT Max": self.fwd_iat.get_max(),
            "Fwd IAT Min": self.fwd_iat.get_min(),
            "Bwd IAT Total": self.bwd_iat.total,
            "Bwd IAT Mean": self.bwd_iat.get_mean(),
            "Bwd IAT Std": self.bwd_iat.std,
            "Bwd IAT Max": self.bwd_iat.get_max(),
            "Bwd IAT Min": self.bwd_iat.get_min(),
            "Fwd PSH Flags": self.fwd_psh,
            "Fwd URG Flags": self.fwd_urg,
            "Fwd Header Length": self.fwd_header_sum,
            "Bwd Header Length": self.bwd_header_sum,
            "Fwd Packets/s": rate(self.fwd_packets),
            "Bwd Packets/s": rate(self.bwd_packets),
            "Min Packet Length": self.all_len.get_min(),
            "Max Packet Length": self.all_len.get_max(),
            "Packet Length Mean": self.all_len.get_mean(),
            "Packet Length Std": self.all_len.std,
            "Packet Length Variance": self.all_len.var,
            "FIN Flag Count": self.flags["FIN"],
            "SYN Flag Count": self.flags["SYN"],
            "RST Flag Count": self.flags["RST"],
            "PSH Flag Count": self.flags["PSH"],
            "ACK Flag Count": self.flags["ACK"],
            "URG Flag Count": self.flags["URG"],
            "CWE Flag Count": self.flags["CWR"],
            "ECE Flag Count": self.flags["ECE"],
            "Down/Up Ratio": (self.bwd_packets / self.fwd_packets) if self.fwd_packets else 0.0,
            "Average Packet Size": self.all_len.get_mean(),
            "Avg Fwd Segment Size": self.fwd_len.get_mean(),
            "Avg Bwd Segment Size": self.bwd_len.get_mean(),
            "Fwd Header Length.1": self.fwd_header_sum,
            "Subflow Fwd Packets": self.fwd_packets / num_subflows,
            "Subflow Fwd Bytes": self.fwd_bytes / num_subflows,
            "Subflow Bwd Packets": self.bwd_packets / num_subflows,
            "Subflow Bwd Bytes": self.bwd_bytes / num_subflows,
            "Init_Win_bytes_forward": self.init_win_fwd if self.init_win_fwd is not None else 0,
            "Init_Win_bytes_backward": self.init_win_bwd if self.init_win_bwd is not None else 0,
            "act_data_pkt_fwd": self.fwd_data_pkts,
            "min_seg_size_forward": self.fwd_header_min if self.fwd_header_min is not None else 0,
            "Active Mean": self.active.get_mean(),
            "Active Std": self.active.std,
            "Active Max": self.active.get_max(),
            "Active Min": self.active.get_min(),
            "Idle Mean": self.idle.get_mean(),
            "Idle Std": self.idle.std,
            "Idle Max": self.idle.get_max(),
            "Idle Min": self.idle.get_min(),
        }
        return features, duration_us, total_packets, total_bytes


def parse_packet(pkt):
    """Возвращает (proto, src, sport, dst, dport, length, header_len, payload_len, flags, win) либо None."""
    ip = pkt.getlayer(IP)
    if ip is not None:
        ip_header_len = ip.ihl * 4 if ip.ihl else 20
    else:
        ip = pkt.getlayer(IPv6)
        if ip is None:
            return None
        ip_header_len = 40

    length = len(ip)  # размер IP-пакета (заголовок + всё после), без Ethernet

    tcp = pkt.getlayer(TCP)
    if tcp is not None:
        l4_header_len = (tcp.dataofs or 5) * 4
        header_len = ip_header_len + l4_header_len
        payload_len = max(length - header_len, 0)
        flags_field = tcp.flags
        flags = {name: (letter in flags_field) for letter, name in TCP_FLAG_LETTERS.items()}
        win = int(tcp.window)
        return ("TCP", ip.src, int(tcp.sport), ip.dst, int(tcp.dport),
                float(length), float(header_len), payload_len, flags, win)

    udp = pkt.getlayer(UDP)
    if udp is not None:
        l4_header_len = 8
        header_len = ip_header_len + l4_header_len
        payload_len = max(length - header_len, 0)
        flags = {name: False for name in TCP_FLAG_LETTERS.values()}
        return ("UDP", ip.src, int(udp.sport), ip.dst, int(udp.dport),
                float(length), float(header_len), payload_len, flags, None)

    return None


class FlowTracker:
    def __init__(self, idle_timeout: float, max_duration: float, activity_timeout: float, on_close, ignore_ports=None):
        self.idle_timeout = idle_timeout
        self.max_duration = max_duration
        self.activity_timeout = activity_timeout
        self.on_close = on_close
        self.ignore_ports = ignore_ports or set()
        self.flows = {}

    @staticmethod
    def _key(proto, src, sport, dst, dport):
        a = (src, sport)
        b = (dst, dport)
        lo, hi = (a, b) if a <= b else (b, a)
        return (proto, lo, hi)

    def ingest(self, pkt):
        parsed = parse_packet(pkt)
        if parsed is None:
            return
        proto, src, sport, dst, dport, length, header_len, payload_len, flags, win = parsed
        if sport in self.ignore_ports or dport in self.ignore_ports:
            return
        ts = float(pkt.time)
        key = self._key(proto, src, sport, dst, dport)

        flow = self.flows.get(key)
        if flow is None:
            flow = FlowState(proto, src, sport, dst, dport, ts)
            self.flows[key] = flow

        direction = "fwd" if (src, sport) == (flow.fwd_src, flow.fwd_sport) else "bwd"
        flow.add_packet(ts, direction, length, header_len, payload_len, flags, win, self.activity_timeout)

        if proto == "TCP" and (flags.get("FIN") or flags.get("RST")):
            flow.closed_reason = "fin" if flags.get("FIN") else "rst"
            self._close(key)

    def sweep(self, now: float):
        for key in list(self.flows.keys()):
            flow = self.flows[key]
            if now - flow.last_ts > self.idle_timeout:
                flow.closed_reason = "idle"
                self._close(key)
            elif now - flow.start_ts > self.max_duration:
                flow.closed_reason = "max_duration"
                self._close(key)

    def close_all(self):
        for key in list(self.flows.keys()):
            self.flows[key].closed_reason = "shutdown"
            self._close(key)

    def _close(self, key):
        flow = self.flows.pop(key, None)
        if flow is None:
            return
        features, duration_us, total_packets, total_bytes = flow.finalize()
        self.on_close(flow, features, duration_us, total_packets, total_bytes)


class Classifier:
    def __init__(self, model_dir: str):
        self.model = joblib.load(os.path.join(model_dir, "ids_model.joblib"))
        self.scaler = joblib.load(os.path.join(model_dir, "scaler.joblib"))
        self.label_encoder = joblib.load(os.path.join(model_dir, "label_encoder.joblib"))
        self.feature_cols = joblib.load(os.path.join(model_dir, "feature_columns.joblib"))

    @property
    def classes(self):
        return list(self.label_encoder.classes_)

    def predict(self, features: dict):
        row = []
        for col in self.feature_cols:
            v = features.get(col, 0.0)
            if v is None or not np.isfinite(v):
                v = 0.0
            row.append(v)
        X = self.scaler.transform(pd.DataFrame([row], columns=self.feature_cols).values)
        pred_idx = self.model.predict(X)[0]
        label = self.label_encoder.inverse_transform([pred_idx])[0]
        confidence = None
        if hasattr(self.model, "predict_proba"):
            confidence = float(self.model.predict_proba(X)[0][pred_idx])
        return label, confidence


class EventLogger:
    def __init__(self, log_path: str):
        self.log_path = log_path

    def log_flow(self, flow: FlowState, label: str, confidence, duration_us, total_packets, total_bytes):
        entry = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "type": "flow",
            "proto": flow.proto,
            "src_ip": flow.fwd_src,
            "src_port": flow.fwd_sport,
            "dst_ip": flow.fwd_dst,
            "dst_port": flow.fwd_dport,
            "packets": total_packets,
            "bytes": int(total_bytes),
            "duration_ms": round(duration_us / 1000.0, 2),
            "verdict": label,
            "confidence": round(confidence, 3) if confidence is not None else None,
            "closed_reason": flow.closed_reason,
        }
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def log_alert(self, src_ip: str, dst_ip: str, label: str, packets: int, bytes_: int, duration_ms: float):
        entry = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "type": "alert",
            "proto": "RULE",
            "src_ip": src_ip,
            "src_port": None,
            "dst_ip": dst_ip,
            "dst_port": None,
            "packets": packets,
            "bytes": bytes_,
            "duration_ms": round(duration_ms, 2),
            "verdict": label,
            "confidence": None,
            "closed_reason": "rule-aggregate",
        }
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry


class RuleEngine:
    """Детектирует межпотоковые паттерны (PortScan, DDoS/флуд), которые ML-классификатор
    в принципе не видит, т.к. он классифицирует каждый поток изолированно, без памяти о
    других потоках того же источника. Здесь — простое скользящее окно по src_ip."""

    def __init__(self, window_sec: float, portscan_port_threshold: int,
                 ddos_flow_threshold: int, cooldown_sec: float):
        self.window_sec = window_sec
        self.portscan_port_threshold = portscan_port_threshold
        self.ddos_flow_threshold = ddos_flow_threshold
        self.cooldown_sec = cooldown_sec
        self.events = defaultdict(deque)   # src_ip -> deque[(ts, dst_ip, dst_port)]
        self.last_alert = {}               # (src_ip, rule_name) -> ts

    def _prune(self, dq, now):
        while dq and now - dq[0][0] > self.window_sec:
            dq.popleft()

    def observe(self, src_ip: str, dst_ip: str, dst_port: int, now: float):
        dq = self.events[src_ip]
        dq.append((now, dst_ip, dst_port))
        self._prune(dq, now)

        distinct_ports = {e[2] for e in dq}
        flow_count = len(dq)
        alerts = []

        if len(distinct_ports) >= self.portscan_port_threshold:
            key = (src_ip, "portscan")
            if now - self.last_alert.get(key, 0.0) >= self.cooldown_sec:
                self.last_alert[key] = now
                label = (f"PortScan (rule-based, {len(distinct_ports)} портов "
                         f"за {self.window_sec:.0f}с)")
                alerts.append((label, dst_ip, len(distinct_ports), flow_count))

        if flow_count >= self.ddos_flow_threshold:
            key = (src_ip, "ddos")
            if now - self.last_alert.get(key, 0.0) >= self.cooldown_sec:
                self.last_alert[key] = now
                label = (f"DDoS (rule-based, {flow_count} потоков "
                         f"за {self.window_sec:.0f}с)")
                alerts.append((label, dst_ip, len(distinct_ports), flow_count))

        return alerts


def write_status(status_path, **kwargs):
    payload = {"updated_at": datetime.now().isoformat(timespec="seconds"), **kwargs}
    tmp = status_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    os.replace(tmp, status_path)


def run_capture_cycle(iface: str, bpf_filter: str, capture_dir: str, rotate_sec: int):
    """Запускает самозавершающийся tcpdump на rotate_sec секунд, возвращает путь к pcap."""
    os.makedirs(capture_dir, exist_ok=True)
    ts_name = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    pcap_path = os.path.join(capture_dir, f"cap_{ts_name}.pcap")
    cmd = [
        "tcpdump", "-i", iface, "-w", pcap_path, "-U",
        "-G", str(rotate_sec), "-W", "1",
    ]
    if bpf_filter:
        cmd.append(bpf_filter)
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except FileNotFoundError:
        print("!!! tcpdump не найден в системе — установите его (apt install tcpdump)")
        raise SystemExit(1)
    return pcap_path


def main():
    parser = argparse.ArgumentParser(description="Живой сетевой IDS без Java/CICFlowMeter")
    parser.add_argument("--iface", default="lo", help="Интерфейс для захвата (по умолчанию lo)")
    parser.add_argument("--filter", default="tcp or udp", help="BPF-фильтр tcpdump")
    parser.add_argument("--model-dir", default=os.path.join(BASE_DIR, "model_out"))
    parser.add_argument("--capture-dir", default=os.path.join(BASE_DIR, "live_capture"))
    parser.add_argument("--log-file", default=os.path.join(BASE_DIR, "ids_events.log"))
    parser.add_argument("--status-file", default=os.path.join(BASE_DIR, "live_engine.status"))
    parser.add_argument("--rotate-sec", type=int, default=4, help="Длительность одного цикла захвата, сек")
    parser.add_argument("--idle-timeout", type=float, default=8.0, help="Закрывать поток без активности дольше N сек")
    parser.add_argument("--max-duration", type=float, default=120.0, help="Максимальный возраст потока, сек")
    parser.add_argument("--activity-timeout", type=float, default=1.0, help="Порог паузы между пакетами для Active/Idle, сек")
    parser.add_argument("--keep-pcaps", action="store_true", help="Не удалять обработанные pcap-файлы")
    parser.add_argument("--quiet", action="store_true", help="Не печатать BENIGN-потоки в консоль")
    parser.add_argument("--ignore-ports", default="5050",
                         help="Порты, которые не логируются (свой опрос дашборда — не часть демонстрируемого трафика), через запятую. Пусто — видеть вообще всё.")
    parser.add_argument("--rule-window", type=float, default=5.0,
                         help="Окно скользящего анализа для rule-based детекции PortScan/DDoS, сек")
    parser.add_argument("--rule-portscan-ports", type=int, default=15,
                         help="Порог: сколько разных портов от одного src_ip за окно считать сканом")
    parser.add_argument("--rule-ddos-flows", type=int, default=30,
                         help="Порог: сколько потоков от одного src_ip за окно считать флудом/DDoS")
    parser.add_argument("--rule-cooldown", type=float, default=10.0,
                         help="Не повторять один и тот же rule-алерт для src_ip чаще, чем раз в N сек")
    args = parser.parse_args()
    ignore_ports = {int(p) for p in args.ignore_ports.split(",") if p.strip()}

    classifier = Classifier(args.model_dir)
    logger = EventLogger(args.log_file)

    print(f"[live_capture_engine] модель загружена, классы: {classifier.classes}")
    print(f"[live_capture_engine] слежу за интерфейсом '{args.iface}', фильтр: '{args.filter}'")
    print(f"[live_capture_engine] события пишутся в {args.log_file}")

    stats = {"flows_total": 0, "attacks_total": 0}
    rules = RuleEngine(args.rule_window, args.rule_portscan_ports,
                        args.rule_ddos_flows, args.rule_cooldown)

    def on_close(flow, features, duration_us, total_packets, total_bytes):
        label, confidence = classifier.predict(features)
        entry = logger.log_flow(flow, label, confidence, duration_us, total_packets, total_bytes)
        stats["flows_total"] += 1
        if label != "BENIGN":
            stats["attacks_total"] += 1
            conf_str = f" ({confidence:.2f})" if confidence is not None else ""
            print(f"[АТАКА] {label}{conf_str} | {entry['src_ip']}:{entry['src_port']} -> "
                  f"{entry['dst_ip']}:{entry['dst_port']} | {total_packets} пак., {int(total_bytes)} байт")
        elif not args.quiet:
            print(f"[benign] {entry['src_ip']}:{entry['src_port']} -> "
                  f"{entry['dst_ip']}:{entry['dst_port']} | {total_packets} пак.")

        # Агрегирующий слой: ML видит только один поток за раз и не замечает PortScan/DDoS,
        # которые проявляются лишь в паттерне МНОГИХ потоков от одного источника — см. README.
        now = time.time()
        for rule_label, dst_ip, distinct_ports, flow_count in rules.observe(
                flow.fwd_src, flow.fwd_dst, flow.fwd_dport, now):
            logger.log_alert(flow.fwd_src, dst_ip, rule_label, distinct_ports,
                              flow_count, args.rule_window * 1000)
            stats["attacks_total"] += 1
            print(f"[ПРАВИЛО] {rule_label} | src={flow.fwd_src} -> dst={dst_ip}")

    tracker = FlowTracker(args.idle_timeout, args.max_duration, args.activity_timeout, on_close, ignore_ports)

    stop = {"flag": False}

    def handle_sigint(signum, frame):
        stop["flag"] = True

    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigint)

    started_at = datetime.now().isoformat(timespec="seconds")
    write_status(
        args.status_file, running=True, pid=os.getpid(), iface=args.iface,
        started_at=started_at, flows_total=0, attacks_total=0,
    )

    try:
        while not stop["flag"]:
            pcap_path = run_capture_cycle(args.iface, args.filter, args.capture_dir, args.rotate_sec)

            if os.path.exists(pcap_path) and os.path.getsize(pcap_path) > 0:
                try:
                    with PcapReader(pcap_path) as reader:
                        for pkt in reader:
                            tracker.ingest(pkt)
                except Exception as e:
                    print(f"!!! Ошибка чтения {pcap_path}: {e}")

            if args.keep_pcaps:
                pass
            else:
                try:
                    os.remove(pcap_path)
                except OSError:
                    pass

            tracker.sweep(time.time())

            write_status(
                args.status_file, running=True, pid=os.getpid(), iface=args.iface,
                started_at=started_at, flows_total=stats["flows_total"],
                attacks_total=stats["attacks_total"],
            )
    finally:
        tracker.close_all()
        for f in glob.glob(os.path.join(args.capture_dir, "*.pcap")):
            if not args.keep_pcaps:
                try:
                    os.remove(f)
                except OSError:
                    pass
        write_status(
            args.status_file, running=False, pid=os.getpid(), iface=args.iface,
            started_at=started_at, flows_total=stats["flows_total"],
            attacks_total=stats["attacks_total"],
        )
        print(f"[live_capture_engine] остановлено. Всего потоков: {stats['flows_total']}, "
              f"атак: {stats['attacks_total']}")


if __name__ == "__main__":
    main()
