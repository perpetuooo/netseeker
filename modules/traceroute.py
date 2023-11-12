import requests
import socket
import struct
import sys
import re
from rich import print
from datetime import datetime

"""
----  TO DO:  ----
finish sockets prep;
while loop;
create a map with the info provided (if possible);
"""

def SocketTraceroute(target, timeout):

    def get_location(ip):
        response = requests.get(f'https://ipapi.co/{ip}/json/').json()
        location_data = {
        "city": response.get("city"),
        "country": response.get("country_name"),
        "lat": response.get("latitude"),
        "long": response.get("longitude")}
    
        return location_data


    #getting the ip address from a domain
    if target.endswith(".com"):
        try:
            target = socket.gethostbyname(target)
        
        except Exception as e:
            print(f"[bold red][!] ERROR: {e}[/bold red]")
            sys.exit(1)

    #creating the ICMP and UDP socket packets
    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    #setting the timeout for receiving packets and binding the socket for ports
    icmp_socket.settimeout(timeout)
    icmp_socket.bind(("", 0))

    ttl = 1

    while True:
        process_time = datetime.now()
        udp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        udp_socket.sendto(target, 33434)

    time = int((datetime.now() - process_time).total_seconds())



if __name__ == '__main__':
    SocketTraceroute("8.8.8.8", 5)
    