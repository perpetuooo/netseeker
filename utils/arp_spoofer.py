import time
import socket
import subprocess
import scapy.all as scapy


"""----  TO DO:  ----
def get_gateway():
def spoofer():
def return_default():
"""

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    request = ether_frame/arp_request

    response_list = scapy.srp(request, timeout=5, retry=1, verbose=False)[0]

    return response_list[0][1].hwsrc


print(get_mac('192.168.5.132'))