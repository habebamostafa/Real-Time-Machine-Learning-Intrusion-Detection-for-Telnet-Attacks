# ===================================================================
# Live Telnet IDS 
# ===================================================================

import pyshark
import pandas as pd
import numpy as np
import joblib
import time
import warnings
from collections import deque, Counter
from datetime import datetime

warnings.filterwarnings('ignore')

# ===============================
# Load model
# ===============================
try:
    model = joblib.load('models/lgbm_telnet_ids_model.pkl')
    scaler = joblib.load('models/scalerlgbm.pkl')
    features = joblib.load('models/featureslgbm.pkl')
    
    print(" Model loaded")
    
except Exception as e:
    print(f" Error: {e}")
    exit(1)

# ===============================
# Feature extraction
# ===============================
def get_features(packet):
    f = {}
    f['frame.len'] = int(packet.length) if hasattr(packet, 'length') else 0
    
    if hasattr(packet, 'tcp'):
        tcp = packet.tcp
        
        f['tcp.len'] = int(tcp.len) if hasattr(tcp, 'len') and tcp.len else 0
        f['tcp.stream'] = int(tcp.stream) if hasattr(tcp, 'stream') and tcp.stream else 0
        
        # PSH flag
        if hasattr(tcp, 'flags'):
            try:
                flags = tcp.flags
                if isinstance(flags, str):
                    if flags.startswith('0x'):
                        flag_int = int(flags, 16)
                    else:
                        flag_int = int(flags)
                else:
                    flag_int = int(flags)
                f['tcp_PSH'] = 1 if (flag_int & 0x08) > 0 else 0
            except:
                f['tcp_PSH'] = 0
        else:
            f['tcp_PSH'] = 0
        
        f['tcp.window_size'] = int(tcp.window_size) if hasattr(tcp, 'window_size') and tcp.window_size else 0
    else:
        f['tcp.len'] = 0
        f['tcp.stream'] = 0
        f['tcp_PSH'] = 0
        f['tcp.window_size'] = 0
    
    return f

# ===============================
# CORRECT prediction logic
# ===============================
def analyze_window(df, model, scaler, features):
    """Analyze a window of packets """
    # Ensure correct features
    for feat in features:
        if feat not in df.columns:
            df[feat] = 0
    
    df = df[features]
    df = df.apply(pd.to_numeric, errors='coerce').fillna(0)
    
    # Scale and predict
    scaled = scaler.transform(df)
    predictions = model.predict(scaled)
    probabilities = model.predict_proba(scaled)
    
    # Count votes
    votes = Counter(predictions)
    majority_class = votes.most_common(1)[0][0]
    vote_count = votes[majority_class]
    
    # CORRECT interpretation (as trained):
    # Class 0 = NORMAL, Class 1 = ATTACK
    if majority_class == 0:
        decision = "NORMAL"
        confidence = np.mean(probabilities[:, 0])  # Confidence for class 0
        color = "🟢"
    else:  # majority_class == 1
        decision = "ATTACK"
        confidence = np.mean(probabilities[:, 1])  # Confidence for class 1
        color = "🔴"
    
    return {
        'decision': decision,
        'color': color,
        'confidence': confidence,
        'vote_count': vote_count,
        'total_votes': len(predictions),
        'avg_length': df['frame.len'].mean(),
        'psh_count': df['tcp_PSH'].sum()
    }

# ===============================
# Main function - SIMPLE & CORRECT
# ===============================
def main():
    print("\n" + "="*60)
    print(" TELNET IDS - FINAL CORRECT VERSION")
    print("="*60)
    
    # Setup capture
    capture = pyshark.LiveCapture(
        interface='any',
        bpf_filter='tcp port 23'
    )
    
    # Window for analysis
    window = deque(maxlen=10)
    packet_num = 0
    
    # Statistics
    stats = {
        'total': 0,
        'normal': 0,
        'attack': 0,
        'alerts': []
    }
    
    print("\nTime     | Packet | Decision | Conf% | Features")
    print("-" * 60)
    
    try:
        print(" Monitoring Telnet traffic...\n")
        
        for packet in capture.sniff_continuously():
            if not hasattr(packet, 'tcp'):
                continue
            
            packet_num += 1
            stats['total'] += 1
            
            try:
                # Get features
                window.append(get_features(packet))
                
                # Analyze when window is full
                if len(window) == 10:
                    df = pd.DataFrame(list(window))
                    result = analyze_window(df, model, scaler, features)
                    
                    # Update statistics
                    if result['decision'] == "NORMAL":
                        stats['normal'] += 1
                    else:
                        stats['attack'] += 1
                    
                    # Display
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    print(f"{result['color']} {timestamp} | {packet_num:6d} | "
                          f"{result['decision']:7s} | {result['confidence']:5.1%} | "
                          f"Len:{result['avg_length']:.0f} PSH:{result['psh_count']}")
                    
                    # Alert for high confidence attacks
                    if (result['decision'] == "ATTACK" and 
                        result['confidence'] > 0.7 and 
                        result['vote_count'] >= 7):
                        
                        print(f"\n{'!'*50}")
                        print(f"🚨 SECURITY ALERT - REAL ATTACK DETECTED!")
                        print(f"   Time: {timestamp}")
                        print(f"   Packet: #{packet_num}")
                        print(f"   Confidence: {result['confidence']:.1%}")
                        print(f"   Agreement: {result['vote_count']}/10 packets")
                        print(f"   Features: Len={result['avg_length']:.0f}, "
                              f"PSH={result['psh_count']}")
                        print(f"{'!'*50}\n")
                        
                        stats['alerts'].append({
                            'time': timestamp,
                            'packet': packet_num,
                            'confidence': result['confidence']
                        })
                    
                    # Summary every 20 packets
                    if packet_num % 20 == 0:
                        windows = packet_num // 10
                        if windows > 0:
                            print(f"\n{'─'*50}")
                            print(f" Status after {packet_num} packets:")
                            print(f"   Windows analyzed: {windows}")
                            print(f"   Normal: {stats['normal']}")
                            print(f"   Attack: {stats['attack']}")
                            
                            if stats['attack'] > 0:
                                attack_rate = (stats['attack'] / windows) * 100
                                print(f"   Attack rate: {attack_rate:.1f}%")
                            
                            print(f"   Alerts: {len(stats['alerts'])}")
                            print(f"{'─'*50}\n")
                
            except Exception:
                continue
    
    except KeyboardInterrupt:
        print(f"\n\n{'='*60}")
        print(" Monitoring stopped")
        print(f"{'='*60}")
        
        windows = packet_num // 10
        if windows > 0:
            print(f" FINAL RESULTS:")
            print(f"   Total packets: {packet_num}")
            print(f"   Windows analyzed: {windows}")
            print(f"   Normal: {stats['normal']} decisions")
            print(f"   Attack: {stats['attack']} decisions")
            
            if stats['attack'] > 0:
                attack_pct = (stats['attack'] / windows) * 100
                print(f"   Attack percentage: {attack_pct:.1f}%")
            
            print(f"   Security alerts: {len(stats['alerts'])}")
            
            if stats['alerts']:
                print(f"\n Alert log (last 5):")
                for alert in stats['alerts'][-5:]:
                    print(f"  {alert['time']} - Packet {alert['packet']} "
                          f"(conf: {alert['confidence']:.1%})")
        

        
    
    except Exception as e:
        print(f"\n Error: {e}")


if __name__ == "__main__":
    main()
