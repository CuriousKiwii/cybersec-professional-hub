#!/usr/bin/env python3

import re
import argparse
import json
from collections import defaultdict, Counter
from rich.console import Console
from rich.table import Table
from datetime import datetime

console = Console()

class LogAnalyzer:
    def __init__(self, log_file):
        self.log_file = log_file
        self.suspicious_patterns = [
            r'(\d+\.\d+\.\d+\.\d+).*?(failed|error|unauthorized|forbidden)',
            r'(\d+\.\d+\.\d+\.\d+).*?(admin|root|administrator)',
            r'(\d+\.\d+\.\d+\.\d+).*?(sql|script|exec|cmd)',
        ]
        self.ip_counter = Counter()
        self.alerts = []
    
    def analyze_logs(self):
        try:
            with open(self.log_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    self.process_line(line.strip(), line_num)
        except FileNotFoundError:
            console.print(f"[red]File {self.log_file} not found[/red]")
            return
        
        self.generate_report()
    
    def process_line(self, line, line_num):
        ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
        ip_match = re.search(ip_pattern, line)
        
        if ip_match:
            ip = ip_match.group(1)
            self.ip_counter[ip] += 1
            
            for pattern in self.suspicious_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.alerts.append({
                        'line': line_num,
                        'ip': ip,
                        'message': line[:100] + '...' if len(line) > 100 else line,
                        'severity': 'HIGH'
                    })
    
    def generate_report(self):
        console.print("[bold blue]Log Analysis Report[/bold blue]")
        
        if self.alerts:
            table = Table(title="Security Alerts")
            table.add_column("Line", style="cyan")
            table.add_column("IP", style="yellow")
            table.add_column("Message", style="white")
            table.add_column("Severity", style="red")
            
            for alert in self.alerts[:10]:
                table.add_row(
                    str(alert['line']),
                    alert['ip'],
                    alert['message'],
                    alert['severity']
                )
            
            console.print(table)
        
        top_ips = self.ip_counter.most_common(5)
        if top_ips:
            console.print("\n[bold green]Top 5 Most Active IPs:[/bold green]")
            for ip, count in top_ips:
                console.print(f"  {ip}: {count} requests")

def main():
    parser = argparse.ArgumentParser(description="Security log analyzer")
    parser.add_argument("--log-file", required=True, help="Path to log file")
    
    args = parser.parse_args()
    
    analyzer = LogAnalyzer(args.log_file)
    analyzer.analyze_logs()

if __name__ == "__main__":
    main()
