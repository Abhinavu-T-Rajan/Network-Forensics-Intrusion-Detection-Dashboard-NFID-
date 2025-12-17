import subprocess
import os

PCAP_DIR = "../storage/pcaps"

def startTshark():
    os.makedirs(PCAP_DIR, exist_ok=True)
    pcap_path = os.path.join(PCAP_DIR, "capture.pcap")

    print("[*] Starting tshark capture...")
    print("[*] Press CTRL+C to stop")

    subprocess.run({
        "tshark",
        "-i", "any",
        "-w", pcap_path
    })