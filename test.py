def callback(packet):
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2
        try:
            ssid = packet[Dot11Elt].info.decode(errors="ignore")
        except:
            ssid = "N/A"
        try:
            dbm_signal = 0 - packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"

        stats = packet[Dot11Beacon].network_stats()
        channel = stats.get("channel", "N/A")
        crypto = stats.get("crypto", set())
        crypto = '/'.join(sorted(list(crypto))) or "OPEN"
        if bssid not in clients:
            clients[bssid] = set()

def score(crypto, dbm_signal, num_clients):
    crypto_scores = {"OPEN": 10, "WEP": 8, "WPA": 6, "WPA2": 4, "WPA3": 2}
    crypto_score = max([crypto_scores.get(c, 0) for c in crypto.split('/')], default=0)
    
    signal_score = max(0, 10 - (dbm_signal // 20))
    
    client_score = min(10, 2 * num_clients)
    
    return crypto_score + signal_score + client_score
