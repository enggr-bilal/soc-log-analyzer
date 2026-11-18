#!/usr/bin/env python3
"""
SOC Log Analyzer — Enterprise Security Log Triage & Brute-Force Detector
Author: Muhammad Bilal
"""

import re
import argparse
from datetime import datetime
from collections import defaultdict

LOG_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'EventID=(?P<event_id>\d+)\s+'
    r'Status=(?P<status>\S+)\s+'
    r'User=(?P<user>\S+)\s*'
    r'(?:IP=(?P<ip>\S+))?\s*'
    r'(?:Workstation=(?P<workstation>\S+))?\s*'
    r'(?:LogonType=(?P<logon_type>\d+))?\s*'
    r'(?:Reason=(?P<reason>\S+))?'
)

class SecurityLogAnalyzer:
    def __init__(self, log_file, brute_force_threshold=4, window_seconds=60):
        self.log_file = log_file
        self.brute_force_threshold = brute_force_threshold
        self.window_seconds = window_seconds
        self.records = []
        self.alerts = []

    def parse_logs(self):
        with open(self.log_file, 'r', encoding='utf-8') as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                match = LOG_PATTERN.search(line)
                if match:
                    data = match.groupdict()
                    data['line_no'] = line_no
                    data['dt'] = datetime.strptime(data['timestamp'], '%Y-%m-%d %H:%M:%S')
                    self.records.append(data)
        return len(self.records)

    def detect_brute_force(self):
        """Detect multiple failed logins followed by possible success from same IP."""
        failures_by_ip = defaultdict(list)
        for r in self.records:
            if r['status'] == 'Failure' and r.get('ip'):
                failures_by_ip[r['ip']].append(r)
            elif r['status'] == 'Success' and r.get('ip') in failures_by_ip:
                fails = failures_by_ip[r['ip']]
                if len(fails) >= self.brute_force_threshold:
                    delta = (r['dt'] - fails[0]['dt']).total_seconds()
                    if delta <= self.window_seconds:
                        self.alerts.append({
                            'type': 'BRUTE_FORCE_SUCCESS',
                            'severity': 'HIGH',
                            'ip': r['ip'],
                            'target_user': r['user'],
                            'attempts': len(fails),
                            'timestamp': r['timestamp'],
                            'description': f"IP {r['ip']} performed {len(fails)} failed attempts before successful logon as '{r['user']}'."
                        })
                failures_by_ip[r['ip']] = []

    def detect_off_hours_activity(self):
        """Detect remote logons occurring during unusual hours (00:00 - 05:00)."""
        for r in self.records:
            if r['status'] == 'Success' and r.get('logon_type') in ['3', '10']:
                hour = r['dt'].hour
                if 0 <= hour <= 5:
                    self.alerts.append({
                        'type': 'OFF_HOURS_REMOTE_LOGON',
                        'severity': 'MEDIUM',
                        'ip': r.get('ip', 'N/A'),
                        'target_user': r['user'],
                        'attempts': 1,
                        'timestamp': r['timestamp'],
                        'description': f"Remote logon (Type {r['logon_type']}) by user '{r['user']}' at {r['timestamp']} (Off-hours)."
                    })

    def run(self):
        self.parse_logs()
        self.detect_brute_force()
        self.detect_off_hours_activity()
        return self.alerts

    def print_report(self):
        print("="*65)
        print(" SOC SECURITY INCIDENT TRIAGE REPORT")
        print("="*65)
        print(f"Total Log Events Parsed: {len(self.records)}")
        print(f"Total Security Alerts Flagged: {len(self.alerts)}\n")
        
        if not self.alerts:
            print("No security anomalies detected.")
            return

        for idx, alert in enumerate(self.alerts, 1):
            color = "[!]" if alert['severity'] == 'HIGH' else "[*]"
            print(f"{color} Alert #{idx} | Severity: {alert['severity']} | Type: {alert['type']}")
            print(f"    Timestamp  : {alert['timestamp']}")
            print(f"    Source IP  : {alert['ip']}")
            print(f"    Account    : {alert['target_user']}")
            print(f"    Details    : {alert['description']}")
            print("-" * 65)

def main():
    parser = argparse.ArgumentParser(description="Enterprise Security Log Triage CLI")
    parser.add_argument("--log", default="../data/sample_auth.log", help="Path to auth log file")
    parser.add_argument("--threshold", type=int, default=4, help="Brute-force failure threshold")
    args = parser.parse_args()

    analyzer = SecurityLogAnalyzer(args.log, brute_force_threshold=args.threshold)
    analyzer.run()
    analyzer.print_report()

if __name__ == "__main__":
    main()
