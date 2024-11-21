from scapy.all import *
from threading import Thread
import pandas as pd
import time
import os
import subprocess

networks = pd.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto", "Clients", "Handshake_Captured", "Timer"])
networks.set_index("BSSID", inplace=True)
clients = {}
last_seen = {}
handshake_captured = {}
stop_sniffing = False
HANDSHAKE_DIR = '/home/randompolymath/Desktop/RedRidingHoodCompany/AINetwork/Handshakes'
os.makedirs(HANDSHAKE_DIR, exist_ok=True)

def callback(packet):
    global networks, clients, last_seen, handshake_captured, stop_sniffing
    current_time = time.time()

    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2
        try:
            ssid = packet[Dot11Elt].info.decode(errors="ignore")
        except:
            ssid = "N/A"
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        stats = packet[Dot11Beacon].network_stats()
        channel = stats.get("channel", "N/A")
        crypto = stats.get("crypto", set())
        crypto = '/'.join(sorted(list(crypto))) or "OPEN"
        
        if bssid not in clients:
            clients[bssid] = set()
        
        client_count = len(clients[bssid])
        
        if bssid not in handshake_captured:
            handshake_captured[bssid] = False
        
        if bssid not in networks.index:
            networks.loc[bssid] = (ssid, dbm_signal, channel, crypto, client_count, handshake_captured[bssid], None)
        else:
            networks.at[bssid, 'Clients'] = client_count
        
        if client_count > 0 and networks.at[bssid, 'Timer'] is None:
            networks.at[bssid, 'Timer'] = 0 

    elif packet.haslayer(Dot11):
        if packet.addr1 and packet.addr2:
            bssid = packet.addr1 if packet.addr1 in networks.index else packet.addr2
            client = packet.addr2 if packet.addr1 in networks.index else packet.addr1

            if bssid in networks.index:
                if bssid not in clients:
                    clients[bssid] = set()
                
                if client != bssid:
                    clients[bssid].add(client)
                    last_seen[(bssid, client)] = current_time

                clients[bssid] = {c for c in clients[bssid] if current_time - last_seen.get((bssid, c), 0) < 300}
                networks.at[bssid, 'Clients'] = len(clients[bssid])

    if packet.haslayer(EAPOL) and packet[Dot11].addr2 in networks.index:
        bssid = packet[Dot11].addr2
        if not handshake_captured[bssid]:
            handshake_captured[bssid] = True
            capture_time = current_time
            networks.at[bssid, 'Handshake_Captured'] = 1
            if networks.at[bssid, 'Timer'] is not None:
                elapsed_time = current_time - networks.at[bssid, 'Timer']
                networks.at[bssid, 'Timer'] = round(elapsed_time, 2)
            
            save_handshake(packet, bssid)

    for bssid in networks.index:
        if networks.at[bssid, 'Timer'] is not None and not handshake_captured[bssid]:
            elapsed_time = current_time - networks.at[bssid, 'Timer']
            networks.at[bssid, 'Timer'] = round(elapsed_time, 2)

def save_handshake(packet, bssid):
    """Saves the captured WPA handshake to a file."""
    handshake_filename = os.path.join(HANDSHAKE_DIR, f"{bssid}.cap")
    
    if not os.path.exists(handshake_filename):
        print(f"Saving handshake for BSSID: {bssid}")
        wrpcap(handshake_filename, packet)

def save_data():
    """Save raw data to the CSV file."""
    global networks

    if networks.empty:
        print("No networks captured. Skipping saving.")
        return

    networks_copy = networks.copy()
    networks_copy = networks_copy.reset_index()

    file_path = os.path.expanduser('/home/randompolymath/Desktop/RedRidingHoodCompany/AINetwork/Data/raw_network_data.csv')
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    if os.path.exists(file_path):
        existing_data = pd.read_csv(file_path)
        
        existing_data.dropna(axis=1, how='all', inplace=True)
        networks_copy.dropna(axis=1, how='all', inplace=True)
        
        if not existing_data.empty and not networks_copy.empty:
            combined_data = pd.concat([existing_data, networks_copy], axis=0, ignore_index=True)
            combined_data.to_csv(file_path, index=False)
            print(f"Appended data to '{file_path}'.")
        elif existing_data.empty:
            networks_copy.to_csv(file_path, index=False)
            print(f"Created and saved data to '{file_path}'.")

    else:
        networks_copy.to_csv(file_path, index=False)
        print(f"Created and saved data to '{file_path}'.")

def print_and_save():
    while not stop_sniffing:
        os.system("clear")
        print(networks)
        save_data()
        time.sleep(1)

def change_channel(interface):
    ch = 1
    while not stop_sniffing:
        try:
            subprocess.run(["iwconfig", interface, "channel", str(ch)], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            try:
                subprocess.run(["iw", "dev", interface, "set", "channel", str(ch)], check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                print(f"Failed to change channel: {e}")
        ch = ch % 14 + 1
        time.sleep(0.5)

def sniff_packets(interface):
    global stop_sniffing
    try:
        sniff(prn=callback, iface=interface, store=0, stop_filter=lambda x: stop_sniffing)
    except Exception as e:
        print(f"An error occurred while sniffing: {e}")
        stop_sniffing = True
        save_data()

if __name__ == "__main__":
    interface = input("Enter network card: ")
    
    try:
        subprocess.run(["iwconfig", interface], check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError:
        print(f"Interface {interface} not found or not accessible. Make sure it exists and you have the necessary permissions.")
        exit(1)

    try:
        subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
        subprocess.run(["sudo", "iw", interface, "set", "monitor", "none"], check=True)
        subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
        print(f"Successfully set {interface} to monitor mode.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to set monitor mode: {e}")
        print("The script may not work correctly if the interface is not in monitor mode.")
        exit(1)

    printer_and_saver = Thread(target=print_and_save)
    printer_and_saver.daemon = True
    printer_and_saver.start()

    channel_changer = Thread(target=change_channel, args=(interface,))
    channel_changer.daemon = True
    channel_changer.start()

    try:
        sniff_packets(interface)
    except KeyboardInterrupt:
        print("\nSniffing stopped. Final data saving...")
        stop_sniffing = True
        save_data()
        print("Exiting...")
