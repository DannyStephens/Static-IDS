# IDS Alert Script

This is a Python program that processes IDS log data to detect suspicious network activities. It looks for unusually high packet transfer rates, SSH brute force attempts, port scanning, and MAC address spoofing.

## What It Does
- Checks if packet transfer rate exceeds predefined thresholds per port  
- Detects when a source IP/MAC gets blocked 3 times on SSH port (22) — possible brute force  
- Detects port scanning if an IP accesses more than 10 different ports within 5 minutes  
- Detects MAC spoofing if multiple MAC addresses are seen from the same source IP within 5 minutes  
- Avoids repeating alerts for the same IP and time window  

## What You Need
- Python 3 installed on your computer  
- The CSV file called `PortCriteria.CSV` with ports and thresholds (example: port 80 → 150000 bytes)  
- The CSV file called `IDS_DATA3.csv` with IDS log data containing timestamps, IPs, ports, MACs, and packet sizes  

## How to Run
1. Save the code in a file, for example: `ids_alert_script.py`  
2. Open a terminal or command prompt  
3. Run the program with:

python ids_alert_script.py

4. Watch the console for alerts when suspicious activity is detected  

## Notes
- The script groups events in 5-minute windows for port scanning and MAC spoofing detection  
- Alerts are printed only once per IP/time window to avoid duplicates  
- Update `PortCriteria.CSV` to change packet size thresholds for different ports  

## Future Improvements
- Save alerts to a log file instead of just printing  
- Add more types of intrusion detection  
- Allow customizable time windows for scanning alerts  
- Integrate with real-time IDS feeds  
