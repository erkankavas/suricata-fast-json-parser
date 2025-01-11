import re
from collections import deque

# Path to the Suricata fast.log file
log_file_path = "/var/log/suricata/fast.log"

# Regular expression to parse the log entries
log_pattern = re.compile(
    r'(?P<timestamp>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+'
    r'\[\*\*\]\s+\[(?P<sid>\d+):(?P<gid>\d+):(?P<rev>\d+)\]\s+'
    r'(?P<alert_msg>.*?)\s+\[\*\*\]\s+'
    r'\[Classification:\s+(?P<classification>.*?)\]\s+'
    r'\[Priority:\s+(?P<priority>\d+)\]\s+'
    r'\{(?P<protocol>\w+)\}\s+'
    r'(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+)\s+->\s+'
    r'(?P<dst_ip>\d+\.\d+\.\d+\.\d+):(?P<dst_port>\d+)'
)

# Number of lines to read from the end
lines_to_read = 20

# Parse the last N lines of the log file
parsed_logs = []
try:
    with open(log_file_path, 'r') as log_file:
        # Use deque to read only the last N lines
        last_lines = deque(log_file, maxlen=lines_to_read)
        for line in last_lines:
            match = log_pattern.search(line)
            if match:
                parsed_logs.append(match.groupdict())
except FileNotFoundError:
    print(f"Error: Log file not found at {log_file_path}")
except Exception as e:
    print(f"An error occurred: {e}")

# Display the parsed logs
if parsed_logs:
    for log in parsed_logs:
        print(f"Timestamp: {log['timestamp']}")
        print(f"Alert: {log['alert_msg']}")
        print(f"Classification: {log['classification']}")
        print(f"Priority: {log['priority']}")
        print(f"Protocol: {log['protocol']}")
        print(f"Source: {log['src_ip']}:{log['src_port']}")
        print(f"Destination: {log['dst_ip']}:{log['dst_port']}")
        print("-" * 50)
else:
    print("No valid log entries were found.")