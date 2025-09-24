import json
import time
import redis
from scapy.all import sniff, IP, conf

# --- Configuration ---
REDIS_HOST = '127.0.0.1'
REDIS_PORT = 6379
REDIS_CHANNEL = 'packet_stream'

# --- IMPORTANT: SET YOUR NETWORK INTERFACE HERE ---
# To find your interface name, run this script once. It will print a list.
# Then, stop the script (Ctrl+C), and put the correct name below.
# It will likely be something like "Wi-Fi" or "Ethernet".
# This is the new, correct line
INTERFACE_TO_SNIFF = "Wi-Fi"

def list_interfaces():
    """Lists all available network interfaces."""
    print("--- Available Network Interfaces ---")
    # This is a more reliable way to get interfaces
    for iface_name in sorted(conf.ifaces.keys()):
        iface = conf.ifaces[iface_name]
        print(f"  - Name: \"{iface.name}\", Description: {iface.description}")
    print("------------------------------------")
    print("Please find your main network interface (e.g., 'Wi-Fi' or 'Ethernet') from the list above.")
    print("Then, stop this script (Ctrl+C) and set the INTERFACE_TO_SNIFF variable inside the sniffer.py file.")

def packet_callback(packet):
    """This function is called for every packet sniffed."""
    if IP in packet:
        try:
            payload = {
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "size": len(packet),
                "timestamp": time.time(),
            }
            r.publish(REDIS_CHANNEL, json.dumps(payload))
        except Exception:
            pass

if __name__ == '__main__':
    if not INTERFACE_TO_SNIFF:
        list_interfaces()
    else:
        print("--- Starting Packet Sniffer Service ---")
        try:
            r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT)
            r.ping() # Check connection
            print(f"Connected to Redis. Sniffing on interface: '{INTERFACE_TO_SNIFF}'...")
            print("Press Ctrl+C to stop.")
            sniff(prn=packet_callback, iface=INTERFACE_TO_SNIFF, store=0, filter="ip")
        except redis.exceptions.ConnectionError as e:
            print(f"!!! Redis Connection Error: {e}")
            print("!!! Please ensure your Redis Docker container is running.")
        except Exception as e:
            print(f"!!! An error occurred: {e}")
            print("!!! Make sure you are running this script as an Administrator.")
