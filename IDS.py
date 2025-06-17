import csv
from collections import defaultdict
from datetime import datetime

criteria = {}
with open('PortCriteria.CSV', mode='r') as file2:
    csv_reader2 = csv.reader(file2)
    next(csv_reader2)
    for row2 in csv_reader2:
        try:
            port = int(row2[0])
            threshold = int(row2[1])
            criteria[port] = threshold
        except ValueError:
            pass

block_count = defaultdict(int)

port_access = defaultdict(set)     
mac_addresses = defaultdict(set)   

port_scan_alerted = set()
mac_spoof_alerted = set()

time_format = "%d/%m/%Y %H:%M" 

with open('IDS_DATA3.csv', mode='r') as file1:
    csv_reader1 = csv.reader(file1)
    next(csv_reader1)

    for row1 in csv_reader1:
        if not row1[4] or not row1[8]:
            continue

        try:
            timestamp_str = row1[0]
            timestamp = datetime.strptime(timestamp_str, time_format)
            source_ip = row1[1]
            dest_ip = row1[2]
            port = int(row1[4])
            action = row1[5].strip().lower()
            source_mac = row1[6]
            dest_mac = row1[7]
            packet_transfer_rate = int(row1[8])

            if port in criteria and packet_transfer_rate > criteria[port]:
                print(f"ALERT! High Packet Transfer Rate Found! Timestamp: {timestamp_str} | Port: {port} | Packet Size: {packet_transfer_rate} | Source IP: {source_ip} | Destination IP: {dest_ip} | Action: {action} | Source MAC: {source_mac} | Destination MAC: {dest_mac}")

            if port == 22 and action == "blocked":
                key = (source_ip, source_mac)
                block_count[key] += 1
                if block_count[key] == 3:
                    print(f"ALERT! Possible SSH Bruteforce Attempt Found! Source IP {source_ip} with MAC {source_mac} has been blocked 3 times on port 22.")

            time_window = timestamp.replace(minute=(timestamp.minute // 5) * 5, second=0, microsecond=0)

            key_port = (source_ip, time_window)
            port_access[key_port].add(port)

            if len(port_access[key_port]) > 10 and key_port not in port_scan_alerted:
                print(f"ALERT! Possible port scanning detected from {source_ip} at {time_window.strftime('%d/%m/%Y %H:%M')} with {len(port_access[key_port])} different ports accessed.")
                port_scan_alerted.add(key_port)

            key_mac = (source_ip, time_window)
            mac_addresses[key_mac].add(source_mac)

            if len(mac_addresses[key_mac]) > 1 and key_mac not in mac_spoof_alerted:
                mac_list = ", ".join(mac_addresses[key_mac])
                print(f"ALERT! Possible MAC spoofing detected for source IP {source_ip} at {time_window.strftime('%d/%m/%Y %H:%M')}. Different MACs seen: {mac_list}")
                mac_spoof_alerted.add(key_mac)

        except ValueError:
            continue
