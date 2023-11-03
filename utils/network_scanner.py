import sys
import socket
from nmap import PortScanner
from rich import print
from rich.table import Table
from datetime import datetime

#from services import get_mac


def NmapNetScanner(target, timing, args):

    def scanner():
        try:
            result = nm.scan(target, arguments=f"-sn -T{timing} {args}", timeout=3000)

            for host in result['scan'].values():
                host_list.append(host)

                #getting the host ipv4 address
                ipv4_address = (host['addresses']['ipv4'])
                
                #getting the host mac address
                if len(host['addresses']) == 1:
                    try:
                        #mac_address = get_mac(ipv4_address)
                        pass
                    
                    except:
                        mac_address = "mac address not found"
                
                else:
                    mac_address = (host['addresses']['mac'])

                #getting the hostname
                if len(host['vendor']) == 1:
                    hostname = (host['vendor'][mac_address])
                
                else:
                    try:
                        hostname = socket.gethostbyaddr(ipv4_address)[0]
                    
                    except socket.error:
                        hostname = "host not found"
                
                #adding info to the table
                table.add_row(hostname, ipv4_address, mac_address)

        except Exception as e:
            print(f"[bold red][!]ERROR: {str(e)}[/bold red]")
            sys.exit(1)


    nm = PortScanner()

    print(f"[bold yellow][-][/bold yellow] Scanning devices on [bold yellow]{target}[/bold yellow] network...\n")
    host_list = []
    table = Table("Hostname", "IP", "MAC")
    process_time = datetime.now()

    scanner()

    time = int((datetime.now() - process_time).total_seconds())

    if table.row_count == 0:
        print(f"[bold red][!] No hosts found.[/bold red]")
    
    else:
        print(f"[bold green][+] {len(host_list)}[/bold green] devices were found.")
        print(table)
        print(f"\n[bold green][+][/bold green] Time elapsed: [bold green]{time}s[/bold green]")



if __name__ == '__main__':
    pass