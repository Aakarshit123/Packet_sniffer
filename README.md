#  Streamlit Packet Sniffer

A lightweight, interactive network packet sniffer built using **Streamlit + Scapy**.  
Capture live network traffic directly from your browser with clean packet summaries.

---

## 🚀 Features

- ✅ Sniff packets from any network interface (eth0, wlan0, lo, etc.)
- ✅ Apply BPF filters (`tcp port 80`, `udp`, `host 1.1.1.1`, etc.)
- ✅ Real-time packet summary logging
- ✅ Supports:
  - ARP
  - IPv4 (TCP, UDP, ICMP, others)
  - IPv6 (TCP6, UDP6, others)
- ✅ Doesn't store full packets in RAM → better performance
- ✅ Displays the latest 50 captured packets in UI
- ✅ Modular design for easy extension

---

## 📦 Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/streamlit-packet-sniffer.git
cd streamlit-packet-sniffer
