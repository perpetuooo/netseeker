import socket
import sys
import time
import random
from threading import Event, Lock
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, TaskID
from scapy.all import ARP, Ether, IP, srp, RandMAC
from ipaddress import IPv4Network
from concurrent.futures import ThreadPoolExecutor, as_completed

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
        if stop.is_set():
            return

        try:
            # Update the progress description to show the current host.
            with progress_lock:
                progress.update(task_id, description=f"Scanning host {host}")

            # ARP Scan for local networks.
            if local_network:
                arp = ARP(pdst=str(host))
                ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=RandMAC() if stealth else None)
                packet = ether / arp

                for _ in range(retries):
                    result = srp(packet, timeout=timeout, verbose=0)[0]    # Sends the package and waits for a response.
                    
                    if result: break
                    if stealth: time.sleep(random.uniform(0.1, 0.5))

                # Process each response received from the network.
                for _, received in result:
                    if stop.is_set():
                        break
                    
                    if received.psrc not in found_hosts:
                        found_hosts[received.psrc] = {"hostname": info.get_hostname(received.psrc), "mac": received.hwsrc}
            
            # ICMP Ping + TCP SYN for remote networks.
            else:
                pass
        
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
    table = Table("Hostname", "IP", "MAC")
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
        table.add_row(data['hostname'], ip_addr, data['mac'])

    if table.row_count == 0:
        console.print(f"\n[bold red][!][/bold red] No hosts found on [bold]{target}[/bold] network.")

    else:
        console.print(f"\n[bold yellow]\\[i][/bold yellow] Found {table.row_count} hosts: ")
        console.print(table)



if __name__ == '__main__':
    pass
