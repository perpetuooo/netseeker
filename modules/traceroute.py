import re
import sys
import socket
import requests
import platform
import subprocess
from rich import print
from datetime import datetime
from alive_progress import alive_bar

"""
----  TO DO:  ----
create a map with the info provided;
"""

def TracerouteWithMap(target, timeout):

    #getting location info from an ip
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

    #initializing variables
    ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
    process_time = datetime.now()
    ip_list = []
    skip = True

    #getting the users ip address and appending to the ip list
    ip_list.append(str(requests.get('https://api.ipify.org').text))


    #running the traceroute command
    with alive_bar(title=f"Tracerouting to {target}", bar=None, spinner="classic", monitor=False, elapsed=False, stats=False) as bar:
        result = subprocess.run([command, target], stdout=subprocess.PIPE, text=True, universal_newlines=True)

        #for line in result.stdout:
            #print(line, end="")

        bar.title("Parsing results")

        #finding all addresses in the filtred result
        filtred_result = result.stdout.splitlines()

        for line in filtred_result:
            match = re.findall(ip_pattern, line)

            if match:
                #skiping the first match because the regex also gets the destination address from the top of the result
                if skip:
                    skip = False
                    continue

                ip_list.extend(match)

        bar.title("Done!")


    print('\n')

    #displaying results
    for ip in ip_list:
        print(f"[bold green][+][/bold green] [white]{ip}[/white] - {get_location(ip)}")

    time = int((datetime.now() - process_time).total_seconds())
    print(f"\n[bold green][+][/bold green] Time elapsed: [green]{time}s[/green]")



if __name__ == '__main__':
    pass
    