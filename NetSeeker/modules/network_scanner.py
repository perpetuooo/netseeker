import sys
import socket
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
                hostname = get_hostname(received.psrc)
                table.add_row(hostname, received.psrc, received.hwsrc)
        
        except KeyboardInterrupt:
            bar.title(f"\033[1;31m[!]\033[0m Scan interrupted! Time elapsed: {int((datetime.now() - process_time).total_seconds())}s\n")
            return


    def get_hostname(ip):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
            
        except socket.error:
            return 'NOT FOUND'


    info = services.DevicesInfo()
    table = Table("Hostname", "IP", "MAC")

    # Validating target.
    if target == 'connected network':
        target = info.get_network()
        
    try:
        IPv4Network(target)

    except ValueError:
        console.print(f"[bold red][!][/bold red] Invalid target: {target}")
        sys.exit(1)
    
    process_time = datetime.now()

    with alive_bar(title=f"\033[1;33m[i]\033[0m Scanning network...", bar=None, spinner="classic", monitor=False, elapsed=False, stats=False) as bar:
        scan(target)

        bar.title(f"\033[1;32m[+]\033[0m Scan completed! Time elapsed: {int((datetime.now() - process_time).total_seconds())}s\n")

    if table.row_count == 0:
        console.print(f"\n[bold red][!][/bold red] No hosts found on [bold]{target}[/bold] network.")

    else:
        console.print(f"\n[bold yellow]\\[i][/bold yellow] Found {table.row_count} hosts: ")
        console.print(table)



if __name__ == '__main__':
    pass
