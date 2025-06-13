import csv

criteria = {}
with open('/PortCriteria.CSV', mode='r') as file2:
    csv_reader2 = csv.reader(file2)
    next(csv_reader2) 

    for row2 in csv_reader2:
        try:
            port = int(row2[0])
            threshold = int(row2[1])
            criteria[port] = threshold
        except ValueError:
            pass


with open('/IDS_DATA3.csv', mode='r') as file1:
    csv_reader1 = csv.reader(file1)
    next(csv_reader1)  

    for row1 in csv_reader1:
        if not row1[4] or not row1[8]:
            continue

        try:
            port = int(row1[4])
            packet_transfer_rate = int(row1[8])

            if port in criteria and packet_transfer_rate > criteria[port]:
                print(f"ALERT! High Packet Transfer Rate Found on Port! Timestamp: {row1[0]} | Port: {port} | Packet Size: {packet_transfer_rate} | Source IP: {row1[1]} | Destination IP: {row1[2]} | Action: {row1[5]} | Source MAC: {row1[6]} | Source IP: {row1[7]}")

        except ValueError:
            pass
