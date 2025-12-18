# 🔐 Telnet Brute Force Attack Detection

## 📌 Project Overview
Machine Learning-based Intrusion Detection System (IDS) for detecting Telnet brute-force attacks using network traffic analysis.

## 🎯 Objectives
- Simulate Telnet brute-force attacks
- Capture and label network traffic
- Train ML models for attack detection
- Deploy real-time IDS

## 🖥️ Lab Setup

| Machine     | OS              | Role               |
|------------|-----------------|--------------------|
| Attacker   | Kali Linux      | Attack simulation  |
| Victim     | Metasploitable  | Data collection    |
| Deployment | Ubuntu          | Real-time detection|

## 🔧 Tools Used
- **Packet Capture:** Wireshark, PyShark
- **ML Libraries:** Scikit-learn, XGBoost
- **Programming:** Python
- **Virtualization:** VirtualBox / VMware

## 📊 Dataset
- **Total Records:** 5,724 packets
- **Normal Traffic:** 3,125 records
- **Attack Traffic:** 2,599 records
- **Split:** 90% train, 10% test

## 🎯 Features Used
Selected via RFE with Random Forest:
- `frame.len` – Packet length
- `tcp.len` – TCP payload length
- `tcp.stream` – Stream index
- `tcp.window_size` – Window size
- `tcp_PSH` – Push flag indicator

## 🤖 ML Models Performance

| Model           | Accuracy | Precision | Recall | F1-Score |
|-----------------|----------|-----------|--------|----------|
| Decision Tree   | 90%      | 91%       | 91%    | 91%      |
| Random Forest   | 88%      | 88%       | 91%    | 89%      |
| XGBoost         | 89%      | 88%       | 93%    | 90%      |
| SVM (RBF)       | 82%      | 78%       | 93%    | 85%      |

## 🚀 Deployment
- Real-time detection system on Ubuntu
- Uses PyShark for live packet capture
- Loads pre-trained Random Forest model
- Classifies traffic as Normal or Attack instantly
- Runs locally on victim machine

## ✅ Conclusion
- Decision Tree performed best (90% accuracy)
- TCP-level features effectively distinguish attacks
- Real-time detection is feasible with ML
- Lightweight deployment possible using PyShark

## 🔮 Future Work
- Extend to SSH / FTP protocols
- Implement deep learning models
- Add automated alerting system
- Cloud-based deployment

## 👥 Team Members
- Salma Ahmed Eltayb
- Boles Medhat Arian
- Habeba Mostafa Desoky
