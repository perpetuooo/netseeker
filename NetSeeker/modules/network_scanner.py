import socket
import sys
import time
import random

from rich.progress import Progress, SpinnerColumn, TextColumn, TaskID
from scapy.all import ARP, Ether, IP, srp, RandMAC, ICMP, sr1, TCP
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import IPv4Network
from threading import Event, Lock
from rich.table import Table

import typer

from resources import console
from resources import services

"""
TODO: 
- Add support to IPv6
- UDP and TCP ACK scans
- OS fingerprinting
- Detect devices types based on their MACs (OUI)
- Add a verbose option?
"""

def networkScanner(target, retries, timeout, threads, stealth):
    
    def scan(host):
        if stop.is_set(): return

        try:
            # Update the progress description to show the current host.
            with progress_lock:
                progress.update(task_id, description=f"Scanning host {host}")

                host_responded = False
                host_data = {
                    'hostname': "NOT FOUND",
                    'mac': "NOT FOUND",
                    'scans': []
                }

            # ARP Scan for local networks.
            if local_network:
                if stop.is_set(): return

                arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=(RandMAC() if stealth else None))/ARP(pdst=str(host))
                result = None

                if retries == 0:
                    if stealth: time.sleep(random.uniform(0.1, 0.5))
                    result = srp(arp_pkt, timeout=timeout, verbose=0)[0]
                
                else:
                    for _ in range(retries):
                        if stealth: time.sleep(random.uniform(0.1, 0.5))
                        result = srp(arp_pkt, timeout=timeout, verbose=0)[0]
                    
                        if result: break

                if result:
                    for _, received in result:
                        host_data['hostname'] = info.get_hostname(host)
                        host_data['mac'] = received.hwsrc
                        host_data['scans'].append("ARP")
                        host_responded = True

            
            # # ICMP echo for all networks (standard ping).
            if not stealth:
                if stop.is_set(): return

                icmp_echo = IP(dst=str(host))/ICMP()
                ans = None

                if retries == 0:
                    ans = sr1(icmp_echo, timeout=timeout, verbose=0)

                else:   
                    for _ in range(retries):
                        ans = sr1(icmp_echo, timeout=timeout, verbose=0)

                        if ans: break

                # Echo Reply.
                if ans and ans.haslayer(ICMP) and ans[ICMP].type == 0:
                    host_data['scans'].append("ICMP")
                    host_responded = True
    
            
            # TCP SYN to common ports for all networks.
            open_ports = []
            for port in [80, 443, 22]:
                if stop.is_set(): return

                syn_pkt = IP(dst=str(host))/TCP(dport=port, flags="S")

                for _ in range(retries):
                    ans = sr1(syn_pkt, timeout=timeout, verbose=0)

                    # Check for SYN-ACK or RST.
                    if ans and ans.haslayer(TCP):
                        if ans[TCP].flags & 0x12:  # SYN-ACK (port open).
                            open_ports.append(str(port))
                            host_responded = True
                        
                        elif ans[TCP].flags & 0x04: # RST (host alive).
                            host_responded = True
            
            if open_ports:
                host_data['scans'].append(f"TCP({','.join(open_ports)})")

            if host_responded:
                found_hosts[host] = host_data
        
        except Exception as e:
            console.print(f"[bold red][!][/bold red] ERROR: {str(e)}")
            raise typer.Exit(1)

        except KeyboardInterrupt:
            stop.set()
            return

        finally:
            progress.update(task_id, advance=1)


    found_hosts = {}    # IP as key, hostname and MAC as values.
    info = services.DevicesInfo()
    table = Table("Hostname", "IP", "MAC", "Scans")
    stop = Event()
    progress_lock = Lock()

    current_network = info.get_network()

    # Validate and process the target input.
    if target in ("Connected Network", current_network):
        target = current_network # Use the current connected network if no target is specified.
        local_network = True
    
    try:
        network = IPv4Network(target)
    except ValueError:
        console.print(f"[bold red][!][/bold red] Invalid target: {target}")
        sys.exit(1)
    
    # Create a list of all hosts in the network.
    hosts = [str(ip) for ip in network.hosts()]
    process_time = time.perf_counter()

    try:
        with Progress(
            SpinnerColumn(spinner_name="line", style="white"),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task_id:TaskID = progress.add_task("Initializing scan...", total=len(hosts))

            with ThreadPoolExecutor(max_workers=threads) as executor:    # Using ThreadPoolExecutor to scan multiple hosts concurrently, improving performance.
                futures = {executor.submit(scan, host): host for host in hosts}

                try:
                    for future in as_completed(futures):
                        if stop.is_set():
                            # Cancel all pending futures.
                            for f in futures:
                                if not f.done():
                                    f.cancel()
                            
                            break

                except KeyboardInterrupt:
                    stop.set()

    except KeyboardInterrupt:
        stop.set()
        
    if stop.is_set():
        console.print(f"[bold red][!][/bold red] Scan interrupted! Time elapsed: {int(time.perf_counter() - process_time)}s")
    
    else:
        console.print(f"[bold green][+][/bold green] Scan completed! Time elapsed: {int(time.perf_counter() - process_time)}s")


    for ip_addr, data in found_hosts.items():
        scans_list = data.get('scans', [])
        table.add_row(data['hostname'], ip_addr, data['mac'], ", ".join(scans_list))

    if table.row_count == 0:
        console.print(f"\n[bold red][!][/bold red] No hosts found on [bold]{target}[/bold] network.")

    else:
        console.print(f"\n[bold yellow]\\[i][/bold yellow] Found {table.row_count} hosts: ")
        console.print(table)



if __name__ == '__main__':
    pass
