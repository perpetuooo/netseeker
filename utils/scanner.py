import nmap
from rich import print
from rich.table import Table
from concurrent.futures import ThreadPoolExecutor

def port_scanner(target, start, end, threads):
    print(f"[bold yellow][%] Starting scanner...[/bold yellow]")
    port_range = range(start, end + 1)
    nm = nmap.PortScanner()

    table = Table("Port", "State", "Service")

    def scanner(port):
        try:
            result = nm.scan(target, str(port))

            port_status = (result['scan'][target]['tcp'][port]['state'])
            port_state = (result['scan'][target]['tcp'][port]['state'])
            port_service = (result['scan'][target]['tcp'][port]['name'])

            if port_status == "open":
                table.add_row(str(port), port_state, port_service)

        except Exception as e:
            print(f"[bold red][!] ERROR: {e}[/bold red]")


    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(scanner, port_range)

    if table.row_count == 0:
        print(f"[bold red][!] No open ports on {target}.[/bold red]")

    else:
        print(table)



if __name__ == '__main__':
    pass