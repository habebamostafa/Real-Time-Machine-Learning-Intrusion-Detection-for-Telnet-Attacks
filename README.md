# 🔐 Telnet Brute Force Attack Detection

## 📌 Project Overview
A **Machine Learning–based Intrusion Detection System (IDS)** designed to detect **Telnet brute-force attacks** through network traffic analysis and behavior-based feature extraction.

---

## 🎯 Objectives
- Simulate Telnet brute-force attacks in a controlled environment  
- Capture and label network traffic  
- Train and evaluate multiple machine learning models  
- Deploy a real-time intrusion detection system  

---

## 🖥️ Lab Setup

| Machine     | OS              | Role               |
|------------|-----------------|--------------------|
| Attacker   | Kali Linux      | Attack simulation  |
| Victim     | Metasploitable  | Traffic generation |
| Deployment | Ubuntu          | Real-time detection|

---

## 🔧 Tools Used
- **Packet Capture:** Wireshark, PyShark  
- **Machine Learning:** Scikit-learn, XGBoost, CatBoost  
- **Programming Language:** Python  
- **Virtualization:** VirtualBox / VMware  

---

## 📊 Dataset
- **Total Records:** 5,724 network packets  
- **Normal Traffic:** 3,125 packets  
- **Attack Traffic:** 2,599 packets  
- **Data Split:** 90% Training, 10% Testing (stratified)  

---

## 🎯 Feature Selection
Features were selected using **Recursive Feature Elimination (RFE)** with a Random Forest estimator to reduce redundancy and prevent overfitting:

- `frame.len` – Packet length  
- `tcp.len` – TCP payload length  
- `tcp.stream` – TCP stream index  
- `tcp.window_size` – TCP window size  
- `tcp_PSH` – TCP push flag indicator  

Time-based and port-based features were intentionally removed to prevent shortcut learning and improve model generalization.

---

## 🤖 Machine Learning Models Performance

| Model           | Accuracy | Precision | Recall | F1-Score |
|-----------------|----------|-----------|--------|----------|
| Decision Tree   | 90%      | 91%       | 91%    | 91%      |
| Random Forest   | 88%      | 88%       | 91%    | 89%      |
| XGBoost         | 89%      | 88%       | 93%    | 90%      |
| SVM (RBF)       | 82%      | 78%       | 93%    | 85%      |
| **CatBoost**    | **90%**  | **89%**   | **93%**| **91%**  |

---

## 🚀 Deployment
- Real-time intrusion detection deployed on **Ubuntu**  
- Live packet capture using **PyShark**  
- Pre-trained machine learning model loaded for inference  
- Traffic classified instantly as **Normal** or **Attack**  
- Designed for lightweight local execution  

---

## ✅ Conclusion
- Tree-based ensemble models achieved strong performance in detecting Telnet brute-force attacks  
- **CatBoost provided the best balance between recall and F1-score**, making it suitable for IDS deployment  
- TCP-level behavioral features effectively distinguish attack traffic from normal traffic  
- Real-time machine learning–based intrusion detection is feasible and efficient  

---

## 🔮 Future Work
- Extend detection to additional protocols (SSH, FTP)  
- Explore deep learning–based intrusion detection models  
- Integrate automated alerting and logging mechanisms  
- Deploy the system in a cloud-based or distributed environment  

---

## 👥 Team Members
- Salma Ahmed Eltayb  
- Boles Medhat Arian  
- Habeba Mostafa Desoky  
