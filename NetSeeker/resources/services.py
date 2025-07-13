import os
import re
import socket
import logging
import pathlib
import requests
import platform
import ipaddress
import netifaces
import subprocess
import scapy.all as scapy
from pathlib import Path

class DevicesInfo:
    # Sends an ICMP echo request to the target host and checks for a reply.
    def ping(self, target):
        packet = scapy.IP(dst=target) / scapy.ICMP()
        reply = scapy.sr1(packet, timeout=1, verbose=False)

        return True if reply else False


    # Retrieves the MAC address associated with the target IP using an ARP request.
    def get_mac(self, ip):
        arp_request = scapy.ARP(pdst=ip)
        ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        request = ether_frame/arp_request

        response_list = scapy.srp(request, timeout=1, verbose=False)[0]

        if response_list:
            return response_list[0][1].hwsrc

        else:
            raise Exception(f"{ip} MAC not found.")


    # Retrieves the default gateway IP address for the current network.
    def get_default_gateway(self):
        gw = scapy.conf.route.route("0.0.0.0")[2]
        return gw


    # Calculates and retrieves the local network in CIDR notation.
    def get_network(self):
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET]
        interface = default_gateway[1]

        addr = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
        ip = addr['addr']
        mask = addr['netmask']

        return ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    

    # Gets location info from an IP address.
    def get_geolocation(self, target = None):
        if not target:
            result = requests.get('http://ip-api.com/json?fields=20705279')

        else:
            if re.match(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', target, re.IGNORECASE):
                target = socket.gethostbyname(target)

            result = requests.get(f'http://ip-api.com/json/{target}?fields=20705279')
        
        if result.status_code == 429:   # Too many requests, need to do something with this later...
            return None

        return result.json()


    # Tries to find the target hostname by reverse DNS lookup.
    def get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
            
        except socket.error:
            return 'NOT FOUND'


    # Checks if the given IP address is a valid public IPv4 address.
    def check_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False


    # Checks if the given domain is a valid address.
    def check_domain(self, domain):
        return bool(re.match(r'^(?=.{1,253}$)(?!-)([a-zA-Z0-9]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$', domain))


    # Gets user desktop path.
    def get_desktop_path(self):
        system = platform.system()

        if system == "Windows":
            # Use Windows API to get the real Desktop path.
            from ctypes import wintypes, windll, create_unicode_buffer

            CSIDL_DESKTOP = 0  # Desktop
            SHGFP_TYPE_CURRENT = 0

            buf = create_unicode_buffer(wintypes.MAX_PATH)

            if windll.shell32.SHGetFolderPathW(None, CSIDL_DESKTOP, None, SHGFP_TYPE_CURRENT, buf) == 0:
                return buf.value
            else:
                return os.path.join(Path.home(), "Desktop")

        elif system == "Linux":
            try:
                # Try using xdg-user-dir (works if available).
                desktop = subprocess.check_output(["xdg-user-dir", "DESKTOP"]).decode().strip()

                if os.path.isdir(desktop):
                    return desktop
            except Exception:
                pass
            
            desktop = os.path.join(pathlib.Path.home(), "Desktop")

            if os.path.isdir(desktop):
                return desktop
            return str(Path.home())  # Fallback: ~/home
        
        # macOS or other.
        else:
            return os.path.join(Path.home(), "Desktop")


    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)



if __name__ == '__main__':
    pass
