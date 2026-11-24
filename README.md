# NetSentry: Live Network Traffic Anomaly and DDoS Mitigation Sentinel

**Domain:** Cybersecurity and Blockchain

**Live demo:** https://netsentry-4r3vhmdhtckjun2sbxbh2w.streamlit.app/

## Problem
Cloud servers and campus networks face constant port scans, SSH brute force attempts and volumetric DDoS floods. Traditional firewalls rely on static IP blacklists, which fail against rotating residential proxies and new botnets. NetSentry detects attacks from traffic behavior instead of fixed IP lists.

## What it does
- Ingests network traffic from packet logs, benchmark datasets or simulated packet streams
- Extracts statistical flow features: packet arrival rate, average payload size, protocol entropy, TCP flag distribution and SYN/ACK ratio
- Detects abnormal traffic with unsupervised anomaly detection (Isolation Forest / One-Class SVM)
- Separates normal web browsing from SYN floods and port sweeps
- Shows a live dashboard with flow metrics and bandwidth spike warnings
- Generates firewall block rules (iptables commands) for flagged sources

## How it works
Traffic data -> feature extraction -> anomaly model -> anomaly score -> alert -> block rule

## Tech stack
Python, Scikit-learn, Pandas, NumPy, Scapy, Streamlit, Plotly

## Datasets
Benchmark intrusion datasets (NSL-KDD, CIC-IDS2017) or simulated traffic.

## Project files
| File | Purpose |
|---|---|
| app.py | Streamlit dashboard |
| requirements.txt | Python packages |

## Run locally
pip install -r requirements.txt
streamlit run app.py

## Scope and ethics
NetSentry is a defensive monitoring prototype. It does not perform deep inspection of encrypted TLS traffic, replace hardware packet-inspection appliances, or run attacks on any external target. Generated iptables rules are suggestions and should be reviewed before use.

## Future improvements
- Live packet capture on a real interface
- Supervised models to compare against the anomaly detector
- Automatic rule expiry and whitelisting
- Alert notifications by email or chat

## Author
RANGAREDDY GARI MADHAN 