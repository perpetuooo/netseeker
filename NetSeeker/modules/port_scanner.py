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

# TODO: Add support for UDP scanning in addition to TCP.

def portScanner(target, ports, timeout, bg, threads):

    def scan(port):
        if stop.is_set():
            return

        try:
            bar.title(f"\033[1;33m[i]\033[0m Scanning port {port}")

            # Creating and sending a TCP socket to find out if the port is open.
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(timeout)
            
            result = sock.connect_ex((target, port))

            # If the port is open, add it to the results table.
            if result == 0:
                port_service = socket.getservbyport(port)
                table.add_row(str(port), "OPEN", (port_service or "NOT FOUND"))

                if bg:  # If banner grabbing is enabled.
                    try:
                        banner = sock.recv(1024).decode().strip()   # Receive up to 1024 bytes for the banner.
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
        parsed_ports: Set[int] = set()  # Using set to dismiss duplicate ports.

        for part in ports.split(","):
            part = part.strip()

            if "-" in part: # Handle port ranges (e.g., "1-1024").
                try:
                    start, end = map(int, part.split("-"))
                    parsed_ports.update(range(start, end + 1))

                except ValueError:
                    raise typer.BadParameter(f"[bold red][!][/bold red] Invalid port range: {part}")
            
            else:   # Handle single ports.
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

    # Check if the target is reachable by sending him a ICMP echo request.
    if info.ping(target):
        console.print(f"[bold green][+][/bold green] Host [bold]{target}[/bold] is up!")

    else:
        console.print(f"[bold red][!][/bold red] Host [bold]{target}[/bold] is down, exiting...")
        sys.exit()

    process_time = datetime.now()

    # Using ThreadPoolExecutor to scan multiple ports concurrently, improving performance.
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
        console.print(f"\n[bold yellow]\\[i][/bold yellow] Found {table.row_count} open ports: ")
        console.print(table)

        if bg and banners:
            console.print("\n[bold yellow]\\[i][/bold yellow] Banners: ")
            display_banners(banners)



if __name__ == '__main__':
    pass
