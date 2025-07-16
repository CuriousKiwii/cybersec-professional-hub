#!/usr/bin/env python3

import socket
import threading
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import time

console = Console()

class PortScanner:
    def __init__(self, target, threads=100):
        self.target = target
        self.threads = threads
        self.open_ports = []
        self.lock = threading.Lock()
        
    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
                    console.print(f"[green]Port {port}: OPEN[/green]")
            else:
                console.print(f"[red]Port {port}: CLOSED[/red]")
        except Exception as e:
            console.print(f"[red]Port {port}: ERROR - {str(e)}[/red]")
    
    def scan_ports(self, ports):
        console.print(f"[bold blue]Scanning {self.target}[/bold blue]")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for port in ports:
                executor.submit(self.scan_port, port)
        
        return sorted(self.open_ports)

def parse_ports(port_string):
    ports = []
    for part in port_string.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports

def main():
    parser = argparse.ArgumentParser(description="Multi-threaded port scanner")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--ports", default="1-1000", help="Port range (e.g., 1-1000 or 80,443,8080)")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads")
    
    args = parser.parse_args()
    
    ports = parse_ports(args.ports)
    
    scanner = PortScanner(args.target, args.threads)
    open_ports = scanner.scan_ports(ports)
    
    if open_ports:
        table = Table(title="Open Ports Summary")
        table.add_column("Port", style="cyan")
        table.add_column("Status", style="green")
        
        for port in open_ports:
            table.add_row(str(port), "OPEN")
        
        console.print(table)
        console.print(f"[bold green]Found {len(open_ports)} open ports[/bold green]")
    else:
        console.print("[red]No open ports found[/red]")

if __name__ == "__main__":
    main()
