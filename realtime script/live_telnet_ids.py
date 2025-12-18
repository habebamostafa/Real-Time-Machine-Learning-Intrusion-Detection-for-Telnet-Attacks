# live_ids.py
import pyshark
import pandas as pd
import joblib
from collections import deque, Counter
# ===============================
# Load trained artifacts
# ===============================
model = joblib.load('rf_telnet_ids_model.pkl')
scaler = joblib.load('scaler.pkl')
features = joblib.load('features.pkl')
def extract_psh_flag(flags):
    try:
        return int(flags, 16) & 0x08 > 0
    except:
        return 0
capture = pyshark.LiveCapture(
    interface='any',
    bpf_filter='tcp port 23'
)
print("\n🚀 Live Telnet IDS Started...\n")
window = deque(maxlen=10)
for packet in capture.sniff_continuously():
    if not hasattr(packet, 'tcp'):
        continue
    try:
        data = {
            'frame.len': int(packet.length),
            'tcp.stream': int(packet.tcp.stream),
            'tcp_PSH': extract_psh_flag(packet.tcp.flags),
            'tcp.len': int(packet.tcp.len),
            'tcp.window_size': int(packet.tcp.window_size),
            'tcp.ack': int(packet.tcp.ack),
            'tcp.seq': int(packet.tcp.seq),
        }
        window.append(data)
        if len(window) < 10:
            continue
        df = pd.DataFrame(window)
        df = df[features]
        df_scaled = scaler.transform(df)
        preds = model.predict(df_scaled)
        decision = Counter(preds).most_common(1)[0][0]
        label = "🚨 ATTACK DETECTED" if decision == 1 else "✅ NORMAL TRAFFIC"
        print(label)
        window.clear()
    except Exception as e:
        print("⚠️ Error:", e) 