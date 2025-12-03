import streamlit as st
from datetime import datetime
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP

captured_packets = []

def packet_info(packet):

    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    source = destination = protocol = src_port = dst_port = "N/A"

    # ARP packet handling
    if ARP in packet:
        source = packet[ARP].psrc
        destination = packet[ARP].pdst
        protocol = "ARP"
        return f"{timestamp}  {protocol:<5}  {source} → {destination}"

    # IPv4 packet handling
    if IP in packet:
        source = packet[IP].src
        destination = packet[IP].dst
        protocol = packet[IP].proto

        if TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            dest_port = packet[TCP].dport
            return f"{timestamp}  {protocol:<5}  {source}:{source_port} → {destination}:{dest_port}"

        if UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            dest_port = packet[UDP].dport
            return f"{timestamp}  {protocol:<5}  {source}:{source_port} → {destination}:{dest_port}"

        if ICMP in packet:
            protocol = "ICMP"
            return f"{timestamp}  {protocol:<5}  {source} → {destination}"

        return f"{timestamp}  IP({protocol})  {source} → {destination}"

    # IPv6 packet handling
    if IPv6 in packet:
        source = packet[IPv6].src
        destination = packet[IPv6].dst

        if TCP in packet:
            protocol = "TCP6"
            source_port = packet[TCP].sport
            dest_port = packet[TCP].dport
            return f"{timestamp}  {protocol:<5}  {source}:{source_port} → {destination}:{dest_port}"

        if UDP in packet:
            protocol = "UDP6"
            source_port = packet[UDP].sport
            dest_port = packet[UDP].dport
            return f"{timestamp}  {protocol:<5}  {source}:{source_port} → {destination}:{dest_port}"

        return f"{timestamp}  IPv6  {source} → {destination}"

    # Fallback case
    return f"{timestamp}  Packet Type: Unrecognized"

def record(packet):
    
    summary = packet_info(packet)
    captured_packets.append(summary)
    st.session_state.packet_logs.append(summary)

# UI Setup
st.set_page_config(page_title="Packet Sniffer", layout="wide")
st.title("Network Packet Sniffer")

network_interface = st.text_input("Network Interface (eth0, wlan0, etc.)")
rule_filter = st.text_input("Packet Filter (like: tcp port 443)")
packet_limit = st.number_input("Packet Count (0 = unlimited)", min_value=0, value=0)

if "packet_logs" not in st.session_state:
    st.session_state.packet_logs = []

if st.button("Begin Capture"):
    st.toast("Listening to network traffic...")
    try:
        sniff(
            prn=record,
            iface=network_interface if network_interface else None,
            filter=rule_filter if rule_filter else None,
            store=False,
            count=packet_limit if packet_limit > 0 else 0
        )
    except Exception as capture_error:
        st.error(f"Capture failed: {capture_error}")

# Display Results
if st.session_state.packet_logs:
    st.divider()
    st.subheader("Recent Captured Packets")

    for log in st.session_state.packet_logs[-50:]:
        st.text(log)

