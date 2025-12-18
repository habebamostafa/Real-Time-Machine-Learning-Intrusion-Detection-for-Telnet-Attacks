📄 Telnet Brute Force Attack Detection - Project Report
📌 Project Overview
This project implements a Telnet Brute Force Attack Detection System using Machine Learning. The goal is to classify network traffic as either normal or malicious by analyzing TCP-level features extracted from Telnet sessions.

🎯 Objectives
Simulate Telnet brute-force attacks in a controlled lab environment.

Capture and label network traffic.

Train and evaluate multiple ML models for intrusion detection.

Deploy a lightweight real-time IDS on a victim machine.

🛠️ Lab Setup & Topology
Virtual Machines Used:
Machine	OS	Role
Attacker	Kali Linux	Initiates Telnet attacks
Victim	Metasploitable	Collects dataset
Deployment Host	Ubuntu	Runs real-time IDS
Tools & Technologies:
Wireshark / TShark / PyShark – Packet capturing

Python – ML inference & deployment

Scikit-learn – Machine learning models

Joblib – Model persistence

VirtualBox / VMware – Virtualization

📊 Dataset
Collection:
Captured Telnet traffic using Wireshark (tcp.port == 23).

Exported packets as CSV for feature extraction.

Statistics:
Class	Records
Normal	3125
Attack	2599
Total	5724
Preprocessing:
Removed duplicates and missing values.

Encoded non-numeric/hex features.

Dropped time-related features to prevent data leakage.

Split: 90% training, 10% testing (stratified).

Applied StandardScaler and handled class imbalance.

🔍 Features
Feature	Description
frame.time_delta	Time between consecutive packets
frame.len	Packet length (bytes)
tcp.len	TCP payload length
tcp.window_size	TCP window size
TCP flags (PSH, SYN, ACK, FIN, RST)	Binary indicators
Feature Selection:
Used Recursive Feature Elimination (RFE) with Random Forest.
Top features:

frame.len

tcp.len

tcp.stream

tcp.window_size

tcp_PSH

🤖 Machine Learning Models
Four models were trained and evaluated:

Random Forest

Decision Tree

Support Vector Machine (RBF Kernel)

XGBoost

📈 Results
Model	Accuracy	Precision	Recall	F1-Score
Random Forest	0.88	0.88	0.91	0.89
SVM (RBF)	0.82	0.78	0.93	0.85
Decision Tree	0.90	0.91	0.91	0.91
XGBoost	0.89	0.88	0.93	0.90
Decision Tree achieved the best overall performance.

🚀 Deployment
Overview:
The trained model was deployed on an Ubuntu VM for real-time traffic classification.

Environment:
OS: Ubuntu

Language: Python

Tool: PyShark (live packet capture)

Model: Random Forest (saved via Joblib)

Architecture:
Kali Linux generates Telnet attacks.

Ubuntu captures live traffic via PyShark.

Features are extracted and passed to the ML model.

Traffic is classified as Normal (0) or Attack (1) in real time.

✅ Conclusion
ML models can effectively detect Telnet brute-force attacks using network traffic features.

The Decision Tree model performed best with 90% accuracy.

Real-time deployment using PyShark demonstrated practical IDS feasibility.

🔮 Future Work
Extend detection to other protocols (SSH, FTP, etc.).

Implement deep learning models for temporal analysis.

Deploy as a service with automated alerting.

Test in larger, more diverse network environments.

👥 Team Members
Salma Ahmed Eltayb

Boles Medhat Arian

Habeba Mostafa Desoky
