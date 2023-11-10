import requests
import socket
import struct
import time
import sys
import re

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


    if target.endswith(".com"):
        target = socket.gethostbyname(target)

    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    while True:
        pass



if __name__ == '__main__':
    SocketTraceroute("8.8.8.8", 5)
    