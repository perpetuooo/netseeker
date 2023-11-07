import sys
import socket
from nmap import PortScanner
from rich import print
from rich.table import Table
from datetime import datetime

from resources.services import DeviceInfo

def NmapNetScanner(target, timing, args):

    def scanner():
        try:
            result = nm.scan(target, arguments=f"-sn -T{timing} {args}", timeout=3000)

            #searching info from the result dictionary
            for host in result['scan'].values():
                host_list.append(host)

                #getting the host ipv4 address
                try:
                    ipv4_address = (host['addresses']['ipv4'])

                except:
                    ipv4_address = "ipv4 address not found"
                
                #getting the host mac address
                if len(host['addresses']) == 1:
                    try:
                        mac_address = info.get_mac(str(ipv4_address))
                    
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

        except KeyboardInterrupt:
            sys.exit()
            
        except Exception as e:
            print(f"[bold red][!]ERROR: {str(e)}[/bold red]")
            sys.exit(1)


    #initializing variables and objects
    nm = PortScanner()
    info = DeviceInfo()
    host_list = []
    table = Table("Hostname", "IP", "MAC")
    process_time = datetime.now()

    print(f"[bold yellow][-][/bold yellow] Scanning devices through the network...\n")
    
    scanner()
    time = int((datetime.now() - process_time).total_seconds())

    #displaying results
    if table.row_count == 0:
        print(f"[bold red][!] No hosts found.[/bold red]")
    
    else:
        print(f"[bold green][+][/bold green] [green]{len(host_list)}[/green] devices found.")
        print(table)
        print(f"\n[bold green][+][/bold green] Time elapsed: [green]{time}s[/green]")



if __name__ == '__main__':
    pass
