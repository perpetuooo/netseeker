import subprocess
import requests
import platform
import socket
import sys
import re
from rich import print
from datetime import datetime
from alive_progress import alive_bar

"""
----  TO DO:  ----
find a way to organize the the result output; 
create a map with the info provided;
"""

def Traceroute(target):

    #getting location info from the ip address
    def get_location(ip):
        if ip.endswith(".com"):
            ip = socket.gethostbyname(ip)

        response = requests.get(f'https://ipapi.co/{ip}/json/').json()
        location_data = {
        "city": response.get("city"),
        "country": response.get("country_name"),
        "lat": response.get("latitude"),
        "long": response.get("longitude")}

        return location_data


    #changing the command depending on the OS
    if platform.system() == "Windows":
        command = "tracert"

    elif platform.system() == "Linux" or platform.system() == "Darwin":
        command = "traceroute"

    else:
        print(f"[bold red][!] Invalid OS.[/bold red]")
        sys.exit(1)


    with alive_bar(title="Tracerouting...", bar=None, spinner="classic", monitor=False, elapsed=False, stats=False) as bar:
        result = subprocess.run([command, target], stdout=subprocess.PIPE, text=True, universal_newlines=True)
        bar.title("Done!")

    for line in result.stdout:
        print(line, end="")

    filtred_result = result.stdout.splitlines()
    ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
    ip_list = []

    for line in filtred_result:
        match = re.findall(ip_pattern, line)

        if match:
            ip_list.extend(match)

    print('\n')

    for ip in ip_list:
        try:
            print(f"{ip} : {get_location(ip)}")

        except:
            print(f"{ip} location not found...")



if __name__ == '__main__':
    Traceroute("8.8.8.8")
    