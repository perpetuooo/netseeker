import ipaddress
import scapy.all as scapy

class DevicesInfo:
    # Sends an ICMP packet to the target host, waiting for a reply.
    def ping(self, target):
        packet = scapy.IP(dst=target) / scapy.ICMP()
        reply = scapy.sr1(packet, timeout=1, verbose=False)

        return True if reply else False


    # Gets the MAC address from the target IP using an ARP request.
    def get_mac(self, ip):
        arp_request = scapy.ARP(pdst=ip)
        ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        request = ether_frame/arp_request

        response_list = scapy.srp(request, timeout=5, retry=1, verbose=False)[0]

        if response_list:
            return response_list[0][1].hwsrc

        else:
            raise Exception(f"{ip} MAC not found.")


    # Gets default gateway.
    def get_default_gateway(self):
        gw = scapy.conf.route.route("0.0.0.0")[2]

        return gw


    # Checks IPv4 type.
    def check_ipv4(self, ip):
        try:
            target = ipaddress.ip_address(ip)
            
            return False if target.is_private else True
        
        except ValueError:
            return False



if __name__ == '__main__':
    pass
