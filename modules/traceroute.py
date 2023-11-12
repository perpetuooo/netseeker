import subprocess
import requests
import platform
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

def Traceroute(target):

    def get_location(ip):
        response = requests.get(f'https://ipapi.co/{ip}/json/').json()
        location_data = {
        "city": response.get("city"),
        "country": response.get("country_name"),
        "lat": response.get("latitude"),
        "long": response.get("longitude")}
    
        return location_data


    print(get_location(target))

    if platform.system() == "Windows":
        command = "tracert"

    elif platform.system() == "Linux" or platform.system() == "Darwin":
        command = "traceroute"

    else:
        print(f"[bold red][!] Invalid OS.[/bold red]")
        sys.exit(1)

    result = subprocess.run(command + target)
    print(result)



if __name__ == '__main__':
    Traceroute("8.8.8.8")
    