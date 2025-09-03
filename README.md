# Pakkit - Network Traffic Classification & Anomaly Detection

## Overview
Classifies network traffic and detects anomalies from PCAP files using flow-based features and a pre-trained **Isolation Forest** model. Built with **Streamlit** for easy file upload, results display, and visualizations.


## Features
- Extracts flow-based features (Flow Duration, Packet Counts, Bytes/sec, IAT, Flags, etc.)
- Detects anomalies (`1 = normal`, `-1 = anomalous`)
- Visualizes results with histograms, scatter plots, bar charts, heatmaps, and pie charts
- Saves results to `anomaly.csv`


## Setup
```bash
python -m venv venv
source venv/bin/activate # Windows: venv\Scripts\activate
pip install streamlit pandas joblib matplotlib seaborn numpy scapy
```


## Run
```bash
streamlit run app.py
```


## Usage
1. Upload a `.pcap` file in the Streamlit app
2. Features are extracted and saved
3. Anomalies are predicted and displayed
4. Visualize and download results
