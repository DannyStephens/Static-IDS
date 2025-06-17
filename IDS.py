import csv
from collections import defaultdict

criteria = {}
with open('/content/drive/MyDrive/Static_IDS_Files/PortCriteria.CSV', mode='r') as file2:
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

with open('/content/drive/MyDrive/Static_IDS_Files/IDS_DATA3.csv', mode='r') as file1:
    csv_reader1 = csv.reader(file1)
    next(csv_reader1)

    for row1 in csv_reader1:
        if not row1[4] or not row1[8]:
            continue

        try:
            timestamp = row1[0]
            source_ip = row1[1]
            dest_ip = row1[2]
            port = int(row1[4])
            action = row1[5].strip().lower()
            source_mac = row1[6]
            dest_mac = row1[7]
            packet_transfer_rate = int(row1[8])

            if port in criteria and packet_transfer_rate > criteria[port]:
                print(f"ALERT! High Packet Transfer Rate Found! Timestamp: {timestamp} | Port: {port} | Packet Size: {packet_transfer_rate} | Source IP: {source_ip} | Destination IP: {dest_ip} | Action: {action} | Source MAC: {source_mac} | Destination MAC: {dest_mac}")

            
            if port == 22 and action == "blocked":
                key = (source_ip, source_mac)
                block_count[key] += 1
                if block_count[key] == 3:
                    print(f"ALERT! SSH Bruteforce Attempt Found! Source IP {source_ip} with MAC {source_mac} has been blocked 3 times on port 22.")


        except ValueError:
            continue
