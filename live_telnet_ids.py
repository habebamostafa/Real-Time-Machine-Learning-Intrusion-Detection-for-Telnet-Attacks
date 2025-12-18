import pandas as pd
import joblib

# ===============================
# Load trained artifacts
# ===============================
model = joblib.load('rf_telnet_ids_model.pkl')
scaler = joblib.load('scaler.pkl')
features = joblib.load('features.pkl')  # Top 5 features only

# ===============================
# PSH flag extractor (ONLY)
# ===============================
def extract_psh_flag(x):
    try:
        return int(x, 16) & 0x08 > 0
    except:
        return 0

# ===============================
# Load live traffic
# ===============================
df = pd.read_csv('telnet_live.csv')

# ===============================
# Feature engineering (MATCH TRAINING)
# ===============================
df['tcp_PSH'] = df['tcp.flags'].apply(extract_psh_flag).astype(int)

# Drop unused columns (exactly like training)
df = df.drop(columns=[
    'tcp.flags',
    'frame.time_epoch',
    'frame.time_delta',
    'frame.time_relative',
    'tcp.srcport',
    'tcp.dstport'
], errors='ignore')

# Keep ONLY trained features and SAME ORDER
df = df[features]

# ===============================
# Scaling + Prediction
# ===============================
df_scaled = scaler.transform(df)
preds = model.predict(df_scaled)

df['Prediction'] = preds.map({0: 'NORMAL', 1: 'ATTACK'})

print(df['Prediction'].value_counts())
