import sys
from rich import print
from rich.table import Table
from nmap import PortScanner
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

def NmapPortScanner(target, start, end, threads, args):

    def scanner(port):
        try:
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
    table = Table("Port", "State", "Service")
    port_range = range(start, end + 1)
    process_time = datetime.now()
    
    if start - end == 0:
        print(f"[bold yellow][-][/bold yellow] Scanning port {start} on [yellow]{target}[/yellow]...\n")
    
    else:
        print(f"[bold yellow][-][/bold yellow] Scanning ports {start} to {end} on [yellow]{target}[/yellow]...\n")

    #calling multiple threads for the scanner function
    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(scanner, port_range)

    time = int((datetime.now() - process_time).total_seconds())

    #displaying results
    if table.row_count == 0:
        print(f"[bold red][!] No open ports on {target}.[/bold red]")

    else:
        print(table)
        print(f"\n[bold green][+][/bold green] Time elapsed: [green]{time}s[/green]")




if __name__ == '__main__':
    pass
