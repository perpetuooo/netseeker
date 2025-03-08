import re
import sys
from rich import print
from rich.table import Table
from datetime import datetime
from alive_progress import alive_bar
from concurrent.futures import ThreadPoolExecutor

from resources import services

def NmapPortScanner(target, ports, threads):

    def scanner(port):
        try:
            bar.title(f"Scanning port {port}")
            result = nm.scan(str(target), str(port))

            #getting ports info from the result dictionary
            port_status = (result['scan'][target]['tcp'][port]['state'])
            port_state = (result['scan'][target]['tcp'][port]['state'])
            port_service = (result['scan'][target]['tcp'][port]['name'])

            if port_status == "open":
                
                if not port_service:
                    port_service = "NOT FOUND"

                table.add_row(str(port), port_state, port_service)

        except Exception as e:
            print(f"[bold red][!] ERROR: {str(e)}[/bold red]")
            sys.exit(1)
        
        except KeyboardInterrupt:
            sys.exit()


    info = services.DeviceInfo()
    table = Table("Port", "State", "Service")
    process_time = datetime.now()
    ports_pattern = r'(\d+)[-,.;](\d+)'

    if not target:
        target = "127.0.0.1"

    if not ports:
        ports = "1-1024"


    match = re.search(ports_pattern, ports)

    #getting values from the argument string and checking if the host is up
    if match:
        port_range = range(int(match.group(1)), int(match.group(2)) + 1)

        if info.ping(target):
            print(f"[bold green][+][/bold green] Host {target} is [green]up[/green]!")
        
        else:
            print(f"[bold red][!][/bold red] Host {target} is [red]down[/red], exiting...")
            sys.exit() 

    else:
        print("[bold red][!] Invalid port range, use 'start-end' or 'start,end'.[/bold red]")
        sys.exit(1)
   

    #calling multiple threads for the scanner function
    with alive_bar(title=None, bar=None, spinner="classic", monitor=False, elapsed=False, stats=False) as bar:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(scanner, port_range)
        bar.title("Scan completed!")


    time = int((datetime.now() - process_time).total_seconds())
    print('\n')

    if table.row_count == 0:
        print(f"[bold red][!] No open ports on {target}.[/bold red]")

    else:
        print(table)
        print(f"\n[bold green][+][/bold green] Time elapsed: [green]{time}s[/green]")



if __name__ == '__main__':
    pass
