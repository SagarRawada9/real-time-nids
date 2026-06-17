"""
capture.py — Real-time Network Intrusion Detection for Flask Dashboard
Supports:
 - Live capture via PyShark
 - Demo Mode (synthetic attacks for testing)
"""
import os, time, random, pandas as pd, numpy as np, joblib
from collections import deque

# Load trained model + preprocessors
try:
    rf = joblib.load("models/rf_final.pkl")
    scaler = joblib.load("models/scaler.pkl")
    le = joblib.load("models/label_encoder.pkl")
    print(" Model, Scaler, and Encoder loaded successfully.")
except FileNotFoundError as e:
    print(f"X issing model/preprocessor: {e}")
    raise SystemExit

# Feature selection
TOP_FEATURES = [
    'Bwd Packet Length Std', 'Init_Win_bytes_forward', 'average_packet_size',
    'Packet Length Variance', 'bwd_packet_length_mean', 'Packet Length Std',
    'Avg Bwd Segment Size', 'Bwd Packets/s', 'Init_Win_bytes_backward',
    'Bwd Packet Length Max', 'Packet Length Mean', 'Max Packet Length',
    'Subflow Bwd Bytes', 'Fwd Header Length', 'fwd_packet_length_mean'
]

# Flow Aggregator
class FlowAggregator:
    def __init__(self, maxlen=50):
        self.packets = deque(maxlen=maxlen)

    def add_packet(self, pkt):
        try:
            self.packets.append(pkt)
        except Exception:
            pass

    def extract_features(self):
        if not self.packets:
            return None
        f = {k: 0 for k in TOP_FEATURES}
        try:
            lens = [int(pkt.length) for pkt in self.packets if hasattr(pkt, "length")]
            if lens:
                f['Packet Length Mean'] = np.mean(lens)
                f['Max Packet Length'] = np.max(lens)
                f['Packet Length Std'] = np.std(lens)
                f['Packet Length Variance'] = np.var(lens)
                f['average_packet_size'] = np.mean(lens)

            bwd = [int(pkt.length) for pkt in self.packets
                   if hasattr(pkt, 'ip') and pkt.ip.src != self.packets[0].ip.src]
            if bwd:
                f['Bwd Packet Length Max'] = np.max(bwd)
                f['Bwd Packet Length Std'] = np.std(bwd)
                f['bwd_packet_length_mean'] = np.mean(bwd)
                f['Avg Bwd Segment Size'] = np.mean(bwd)

            start, end = float(self.packets[0].sniff_timestamp), float(self.packets[-1].sniff_timestamp)
            dur = max(0.001, end - start)
            f['Bwd Packets/s'] = len(bwd) / dur

            if hasattr(self.packets[0], 'tcp'):
                f['Init_Win_bytes_forward'] = int(self.packets[0].tcp.window_size_value)
            if hasattr(self.packets[-1], 'tcp'):
                f['Init_Win_bytes_backward'] = int(self.packets[-1].tcp.window_size_value)

            f['Subflow Bwd Bytes'] = sum(bwd) if bwd else 0
            if hasattr(self.packets[0], 'ip'):
                f['Fwd Header Length'] = int(self.packets[0].ip.hdr_len)
        except Exception:
            return None

        df = pd.DataFrame([f])
        return df.reindex(columns=TOP_FEATURES, fill_value=0)

# Helper: Extract IPs
def get_addresses(pkt):
    try:
        if hasattr(pkt, "ip"):
            return pkt.ip.src, pkt.ip.dst
        elif hasattr(pkt, "eth"):
            return pkt.eth.src, pkt.eth.dst
    except Exception:
        pass
    return "Unknown", "Unknown"

# LIVE MODE
def start_capture(log_queue, data_store, interface="Wi-Fi", stop_flag=None):
    try:
        import pyshark
        cap = pyshark.LiveCapture(interface=interface)
        print(f"🟢 Live capture started on interface: {interface}")
    except Exception as e:
        print(f"XCould not start PyShark: {e}")
        print("Switching to DEMO mode instead.")
        start_demo(log_queue, data_store, stop_flag)
        return

    flow = FlowAggregator()
    total = 0
    try:
        for pkt in cap.sniff_continuously():
            if stop_flag and stop_flag.is_set():
                break
            if not hasattr(pkt, "ip"):
                continue
            flow.add_packet(pkt)
            total += 1
            if len(flow.packets) >= 10:
                feat = flow.extract_features()
                if feat is None:
                    continue
                try:
                    X = scaler.transform(feat)
                    pred = rf.predict(X)
                    label = le.inverse_transform(pred)[0]
                except Exception:
                    label = "Normal"
                s, d = get_addresses(pkt)
                log_entry = {
                    "time": time.strftime("%H:%M:%S"),
                    "src_ip": s,
                    "dst_ip": d,
                    "attack": label
                }
                log_queue.put(log_entry)
                data_store.add_log(log_entry)
                print(f"[{log_entry['time']}] {s} → {d} | {label}")
                flow.packets.clear()
    except KeyboardInterrupt:
        print("🛑 Capture manually stopped.")
    except Exception as e:
        print(f"X rror during capture: {e}")
    print("🛑 Capture thread exited.")

# DEMO MODE (Synthetic Traffic)
def start_demo(log_q, data_store, stop_flag=None):
    attacks = ["Normal", "DoS", "BruteForce", "Bot", "PortScan", "Infiltration"]
    weights = [0.75, 0.08, 0.06, 0.04, 0.05, 0.02]
    print("Demo Mode Started (synthetic network events)")
    while not (stop_flag and stop_flag.is_set()):
        src = f"192.168.1.{random.randint(10, 250)}"
        dst = f"10.0.0.{random.randint(10, 250)}"
        attack = random.choices(attacks, weights=weights, k=1)[0]
        log = {
            "time": time.strftime("%H:%M:%S"),
            "src_ip": src,
            "dst_ip": dst,
            "attack": attack
        }
        data_store.add_log(log)
        log_q.put(log)
        time.sleep(0.8)
    print("🛑 Demo Mode stopped.")
