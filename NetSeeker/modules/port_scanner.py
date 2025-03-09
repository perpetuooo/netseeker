import sys
import typer
import socket
from threading import Event
from rich.table import Table
from rich.panel import Panel
from typing import List, Set
from datetime import datetime
from alive_progress import alive_bar
from concurrent.futures import ThreadPoolExecutor, as_completed

from resources import services
from resources import console

def portScanner(target, ports, timeout, bg, threads):

    def scan(port):
        if stop.is_set():
            return

        try:
            bar.title(f"\033[1;33m[i]\033[0m Scanning port {port}")

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(timeout)
            
            result = sock.connect_ex((target, port))

            if result == 0:
                port_service = socket.getservbyport(port)
                table.add_row(str(port), "OPEN", (port_service or "NOT FOUND"))

                if bg:
                    try:
                        banner = sock.recv(1024).decode().strip()
                        banners[port] = banner

                    except Exception:
                        banners[port] = "NOT FOUND"
                
        except Exception as e:
            console.print(f"[bold red][!][/bold red] ERROR: {str(e)}")
            return None
        
        except KeyboardInterrupt:
            return None

        finally:
            sock.close()


    def parse_ports(ports: str) -> List[int]:
        parsed_ports: Set[int] = set()  # Using set to dismiss duplicates.

        for part in ports.split(","):
            part = part.strip()

            if "-" in part:
                try:
                    start, end = map(int, part.split("-"))
                    parsed_ports.update(range(start, end + 1))

                except ValueError:
                    raise typer.BadParameter(f"[bold red][!][/bold red] Invalid port range: {part}")
            
            else:
                try:
                    parsed_ports.add(int(part))

                except ValueError:
                    raise typer.BadParameter(f"[bold red][!][/bold red] Invalid port: {part}")

        return sorted(parsed_ports)


    def display_banners(banners):
        for port, banner in banners.items():
            console.print(Panel(
                banner,
                title=f"Port {port}",
                padding=(1, 2),
        ))


    info = services.DevicesInfo()
    table = Table("Port", "State", "Service")
    stop = Event()
    banners = {}

    # Starting the timer.
    process_time = datetime.now()

    if info.ping(target):
        console.print(f"[bold green][+][/bold green] Host [bold]{target}[/bold] is up!")

    else:
        console.print(f"[bold red][!][/bold red] Host [bold]{target}[/bold] is down, exiting...")
        sys.exit()

    # Creating threads to the scanner function.
    try:
        with alive_bar(title=None, bar=None, spinner="classic", monitor=False, elapsed=False, stats=False) as bar:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(scan, port): port for port in parse_ports(ports)}

                try:
                    for future in as_completed(futures):
                        if stop.is_set():  
                            # Cancel all futures.
                            for f in futures:
                                if not f.done():
                                    f.cancel()
                            
                            break
                
                except KeyboardInterrupt:
                    stop.set()

                    # Cancel all futures.
                    for f in futures:
                        if not f.done():
                            f.cancel()

            if stop.is_set():
                bar.title(f"\033[1;31m[!]\033[0m Scan interrupted! Time elapsed: {int((datetime.now() - process_time).total_seconds())}s\n")

            else:
                bar.title(f"\033[1;32m[+]\033[0m Scan completed! Time elapsed: {int((datetime.now() - process_time).total_seconds())}s\n")
    
    except KeyboardInterrupt:
        stop.set()

    if table.row_count == 0:
        console.print(f"\n[bold red][!][/bold red] No open ports on [bold]{target}[/bold]")

    else:
        console.print("\n[bold yellow]\\[i][/bold yellow] Open ports: ")
        console.print(table)

        if bg and banners:
            console.print("\n[bold yellow]\\[i][/bold yellow] Banners: ")
            display_banners(banners)



if __name__ == '__main__':
    pass
