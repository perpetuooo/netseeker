import sys
import time
from threading import Event, Lock
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, TaskID
from scapy.all import ARP, Ether, srp
from ipaddress import IPv4Network
from concurrent.futures import ThreadPoolExecutor, as_completed

from resources import console
from resources import services

"""
TODO: 
- Add support to IPv6 
- OS fingerprinting
- Detect devices types based on their MACs (OUI)
"""

def networkScanner(target, timeout, threads):
    
    def scan(host):
        if stop.is_set():
            return

        try:
            # Update the progress description to show the current host.
            with progress_lock:
                progress.update(task_id, description=f"Scanning host {host}")

            # Creates an ARP package to discover hosts.
            arp = ARP(pdst=str(host))
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            # Sends the package and waits for a response.
            result = srp(packet, timeout=timeout, verbose=0)[0]
            
            # Process each response received from the network.
            for sent, received in result:
                if stop.is_set():
                    break

                hostname = info.get_hostname(received.psrc) # Tries to retrieve the hostname using the IP address from the response.
                table.add_row(hostname, received.psrc, received.hwsrc)
        
        except Exception as e:
            console.print(f"[bold red][!][/bold red] ERROR: {str(e)}")
            sys.exit(1)

        except KeyboardInterrupt:
            stop.set()
            return

        finally:
            progress.update(task_id, advance=1)


    info = services.DevicesInfo()
    table = Table("Hostname", "IP", "MAC")
    stop = Event()
    progress_lock = Lock()

    # Validate and process the target input.
    try:
        if target == 'connected network':
            target = info.get_network() # Use the current connected network if no target is specified.

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

    if table.row_count == 0:
        console.print(f"\n[bold red][!][/bold red] No hosts found on [bold]{target}[/bold] network.")

    else:
        console.print(f"\n[bold yellow]\\[i][/bold yellow] Found {table.row_count} hosts: ")
        console.print(table)



if __name__ == '__main__':
    pass
