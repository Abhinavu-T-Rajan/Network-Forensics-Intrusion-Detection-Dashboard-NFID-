import platform
import sys

def GetPlatform():
    return platform.system().lower()

def StartCapture():
    osName = GetPlatform()

    if osName in ["windows", "linux", "darwin"]:
        try:
            from scapy_snfifer import startScapy
            print("[*] Using Scapy backend on {osName}")
            startScapy()
        except Exception as e:
            print("[!] Scapy failed, fallling back to tshark")
            print(e)
            from tshark_sniffer import startTshark
            startTshark()
    
    else:
        print("[!] Unsupported OS")
        sys.exit(1)

if __name__ == "__main__":
    StartCapture()