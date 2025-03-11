import sys
from threading import Event
from rich.table import Table
from datetime import datetime
from alive_progress import alive_bar
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


    info = services.DevicesInfo()
    table = Table("Hostname", "IP", "MAC")
    stop = Event()

    # Validate and process the target input.
    try:
        if target == 'connected network':
            target = info.get_network() # Use the current connected network if no target is specified.

        network = IPv4Network(target)

    except ValueError:
        console.print(f"[bold red][!][/bold red] Invalid target: {target}")
        sys.exit(1)
    
    process_time = datetime.now()

    # Using ThreadPoolExecutor to scan multiple hosts concurrently, improving performance.
    with alive_bar(title=f"\033[1;33m[i]\033[0m Scanning network...", bar=None, spinner="classic", monitor=False, elapsed=False, stats=False) as bar:
        # Create a list of all hosts in the network
        hosts = [str(ip) for ip in network.hosts()]
        try:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(scan, host): host for host in hosts}

                for future in as_completed(futures):
                    if stop.is_set():  
                        # Cancel all pending futures.
                        for f in futures:
                            if not f.done():
                                f.cancel()
                        
                        break
            
        except KeyboardInterrupt:
            stop.set()
        
        if stop.is_set():
            bar.title(f"\033[1;31m[!]\033[0m Scan interrupted! Time elapsed: {int((datetime.now() - process_time).total_seconds())}s\n")
        
        else:
            bar.title(f"\033[1;32m[+]\033[0m Scan completed! Time elapsed: {int((datetime.now() - process_time).total_seconds())}s\n")

    if table.row_count == 0:
        console.print(f"\n[bold red][!][/bold red] No hosts found on [bold]{target}[/bold] network.")

    else:
        console.print(f"\n[bold yellow]\\[i][/bold yellow] Found {table.row_count} hosts: ")
        console.print(table)



if __name__ == '__main__':
    pass
