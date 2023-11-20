import re
import sys
from rich import print
from rich.table import Table
from nmap import PortScanner
from datetime import datetime
from alive_progress import alive_bar
from concurrent.futures import ThreadPoolExecutor

from resources.services import DeviceInfo

def NmapPortScanner(target, ports, threads, args):

    def scanner(port):
        try:
            bar.title(f"Scanning port {port}")
            result = nm.scan(str(target), str(port), arguments=args)

            #getting ports info from the result dictionary
            port_status = (result['scan'][target]['tcp'][port]['state'])
            port_state = (result['scan'][target]['tcp'][port]['state'])
            port_service = (result['scan'][target]['tcp'][port]['name'])

            #adding info to the table if the port its open
            if port_status == "open":
                table.add_row(str(port), port_state, port_service)

        except Exception as e:
            print(f"[bold red][!] ERROR: {str(e)}[/bold red]")
            sys.exit(1)
        
        except KeyboardInterrupt:
            sys.exit()


    #initializing variables and objects
    nm = PortScanner()
    info = DeviceInfo()
    table = Table("Port", "State", "Service")
    process_time = datetime.now()
    ports_pattern = r'(\d+)[-,.;](\d+)'

    #getting values from the argument string
    match = re.search(ports_pattern, ports)

    if match:
        port_range = range(int(match.group(1)), int(match.group(2)) + 1)

    else:
        print("[bold red][!] Invalid port range, use 'start-end' or 'start,end'.[/bold red]")
        sys.exit(1)
   
   #checks if the host is up
    if info.ping(target):
        print(f"[bold green][+][/bold green] Host {target} is [green]up[/green]!")
    
    else:
        print(f"[bold red][!] Host {target} is down, exiting...[/bold red]")
        sys.exit() 
    

    #calling multiple threads for the scanner function
    with alive_bar(title=None, bar=None, spinner="classic", monitor=False, elapsed=False, stats=False) as bar:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(scanner, port_range)
        bar.title("Scan completed!")

    time = int((datetime.now() - process_time).total_seconds())
    print('\n')

    #displaying results
    if table.row_count == 0:
        print(f"[bold red][!] No open ports on {target}.[/bold red]")

    else:
        print(table)
        print(f"\n[bold green][+][/bold green] Time elapsed: [green]{time}s[/green]")




if __name__ == '__main__':
    pass
