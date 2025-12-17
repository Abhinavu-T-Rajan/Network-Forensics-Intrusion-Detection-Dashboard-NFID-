from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
import json
from datetime import datetime
import os

OUTPUT_FILE = "../storage/traffic_log.json"

def chooseInterface():
    interfaces = get_if_list()
    print("[*] Available Interfaces: ")

    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface}")

    interfacesNumber = int(input("Select interface number: "))
    return interfaces[interfacesNumber]

def prasePacket(packet):
    if IP not in packet:
        return None
    
    data = {
        "Timestamp": datetime.utcnow().isoformat(),
        "Source IP": packet[IP].src,
        "Distination IP": packet[IP].dst,
        "Protocol": packet[IP].proto,
        "Packet size": len(packet) 
    }

    if TCP in packet:
        data.update({
            "Layer": "TCP",
            "Source Port": packet[TCP].sport,
            "Distination Port": packet[TCP].dport
        })

    elif UDP in packet:
        data.update({
            "Layer": "UDP",
            "Source Port": packet[UDP].sport,
            "Distination Port": packet[UDP].dport
        })
    
    elif ICMP in packet:
        data.update({
            "Layer": "ICMP",
            "ICMP Type": packet[ICMP].type
        })

    return data

def savePacket(packet_data):
    if not packet_data:
        return
    
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    try:
        with open(OUTPUT_FILE, "r") as f:
            logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodError):
        logs = []

    logs.append(packet_data)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(logs, f, indent=2)

def HandlePacket(packet):
    parsed = prasePacket(packet)
    if parsed:
        savePacket(parsed)
        print(parsed)

def startScapy():
    iface = chooseInterface()
    print(f"[*] Capturing on {iface}")
    sniff(iface=iface, prn=HandlePacket, store=False)
    