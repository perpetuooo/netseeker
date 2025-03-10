import sys
import socket
from threading import Event
from rich.table import Table
from datetime import datetime
from alive_progress import alive_bar
from scapy.all import ARP, Ether, srp
from ipaddress import IPv4Address, IPv4Network

from resources import console
from resources import services


def networkScanner(target, timeout):
    
    def scan(target):
        try:
            # Creates an ARP package to discover hosts.
            arp = ARP(pdst=str(target))
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            # Sends the package and waits for a response.
            result = srp(packet, timeout=timeout, verbose=0)[0]
            
            for sent, received in result:
                if stop.is_set() or KeyboardInterrupt:
                    stop.set()
                    break

                hostname = info.get_hostname(received.psrc)
                table.add_row(hostname, received.psrc, received.hwsrc)
        
        except Exception as e:
            console.print(f"[bold red][!][/bold red] ERROR: {str(e)}")
            return None

        except KeyboardInterrupt:
            stop.set()


    info = services.DevicesInfo()
    table = Table("Hostname", "IP", "MAC")
    stop = Event()

    # Validating target.
    if target == 'connected network':
        target = info.get_network()
        
    try:
        IPv4Network(target)

    except ValueError:
        console.print(f"[bold red][!][/bold red] Invalid target: {target}")
        sys.exit(1)
    
    process_time = datetime.now()

    try:
        with alive_bar(title=f"\033[1;33m[i]\033[0m Scanning network...", bar=None, spinner="classic", monitor=False, elapsed=False, stats=False) as bar:
            scan(target)

            if stop.is_set():
                bar.title(f"\033[1;31m[!]\033[0m Scan interrupted! Time elapsed: {int((datetime.now() - process_time).total_seconds())}s\n")
            
            else:
                bar.title(f"\033[1;32m[+]\033[0m Scan completed! Time elapsed: {int((datetime.now() - process_time).total_seconds())}s\n")


    except KeyboardInterrupt:
        stop.set()

    if table.row_count == 0:
        console.print(f"\n[bold red][!][/bold red] No hosts found on [bold]{target}[/bold] network.")

    else:
        console.print(f"\n[bold yellow]\\[i][/bold yellow] Found {table.row_count} hosts: ")
        console.print(table)



if __name__ == '__main__':
    pass
