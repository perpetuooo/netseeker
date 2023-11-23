import scapy.all as scapy

class DeviceInfo:
    #creates an ICMP packet and sends to the target host, waiting for a reply
    def ping(self, target):
        packet = scapy.IP(dst=target) / scapy.ICMP()
        reply = scapy.sr1(packet, timeout=1, verbose=False)

        if reply:
            return True

        else:
            return False


    #get the mac address from the target IP using an ARP request
    def get_mac(self, ip):
        arp_request = scapy.ARP(pdst=ip)
        ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        request = ether_frame/arp_request

        response_list = scapy.srp(request, timeout=5, retry=1, verbose=False)[0]

        if response_list:
            return response_list[0][1].hwsrc

        else:
            raise Exception(f"{ip} MAC not found.")


    #extracting the default gateway IP address
    def get_default_gateway(self):
        gw = scapy.conf.route.route("0.0.0.0")[2]

        return gw



if __name__ == '__main__':
    pass
