import sys
import time
import socket
import scapy.all as scapy
from rich import print
from rich.table import Table

def ScapyNetScanner(target, vFlag):

    def scanner(ip):
        try:
            arp_request = scapy.ARP(pdst=ip)
            ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            request = ether_frame/arp_request

            response_list = scapy.srp(request, timeout=3, retry=1, verbose=vFlag)[0]

            for _, received in response_list:
                try:
                    hostname = socket.gethostbyaddr(received.psrc)[0]

                except:
                    hostname = "???"

                table.add_row(received.psrc, received.hwsrc, str(hostname))

        except Exception as e:
            print(f"[bold red][!] ERROR: {str(e)}[/bold red]")
            sys.exit(1)
        
        except KeyboardInterrupt:
            sys.exit()


    print(f"[bold yellow][-] Scanning devices on {target}...[/bold yellow]\n")

    table = Table("IP", "MAC", "HOSTNAME")
    s = time.process_time()
    scanner(target)


    if table.row_count == 0:
        print("[bold red][!] Scan failed, no devices detected.[/bold red]")
    
    else:
        e = time.time()
        print(table)
        print(f"\n[+] Time elapsed: {(e - s)}")



if __name__ == '__main__':
    pass