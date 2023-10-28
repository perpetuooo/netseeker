import sys
import socket
import scapy.all as scapy
from rich import print
from rich.table import Table

def ScapyNetScanner(target, vFlag):
    print(f"[bold yellow][-] Scanning devices on {target}...[/bold yellow]\n")

    table = Table("IP", "MAC", "HOSTNAME")

    def scanner(ip):
        try:
            arp_request = scapy.ARP(pdst=ip)
            #arp_request.show()
            ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            #ether_frame.show()
            request = ether_frame/arp_request
            #request.show()

            response_list = scapy.srp(request, timeout=3, retry=1, verbose=vFlag)[0]

            for sent, received in response_list:
                #print(received.show())
                try:
                    hostname = socket.gethostbyaddr(received.psrc)
                    #print(hostname)

                except:
                    hostname = ("???",)

                table.add_row(received.psrc, received.hwsrc, str(hostname[0]))

        except Exception as e:
            print(f"[bold red][!] ERROR: {str(e)}[/bold red]")
            sys.exit(1)
        
        except KeyboardInterrupt:
            sys.exit()


    scanner(target)

    if table.row_count == 0:
        print("[bold red][-] Scanner Failed.[/bold red]")
    
    else:
        print(table)


if __name__ == '__main__':
    pass