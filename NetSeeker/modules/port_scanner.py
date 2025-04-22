import sys
import time
import typer
import socket
from threading import Event, Lock
from rich.table import Table
from rich.panel import Panel
from typing import List, Set
from rich.progress import Progress, SpinnerColumn, TextColumn, TaskID
from concurrent.futures import ThreadPoolExecutor, as_completed

from resources import services
from resources import console

"""
TODO: 
- Add support for UDP scanning in addition to TCP
- Add support to IPv6
- Implement a better banner grabbing technique
- Create a stealth scan alternative
"""

def portScanner(target, ports, timeout, udp, threads, bg):

    def scanner(port):

        def tcp_scan():
            if stop.is_set(): return

            try:
                # Update the progress description to show the current port.
                with progress_lock:
                    progress.update(task_id, description=f"Scanning port {port}")

                # Create and send a TCP socket.
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    
                socket.setdefaulttimeout(timeout)
                response = sock.connect_ex((target, port))

                # If the port is open, add it to the results table.
                if response == 0:
                    port_service = socket.getservbyport(port)
                    table.add_row(str(port), "OPEN", (port_service or "NOT FOUND"))

                    if bg:  # Banner grabbing.
                        try:
                            banner = sock.recv(1024).decode().strip()   # Receive up to 1024 bytes for the banner.
                            banners[port] = banner

                        except Exception:
                            banners[port] = "NOT FOUND"
                    
            except Exception as e:
                if "port/proto not found" in str(e):  # Service name not found.
                    pass

                else:
                    console.print(f"[bold red][!][/bold red] TCP ERROR: {str(e)}")
                    sock.close()
                    return None
            
            except KeyboardInterrupt:
                sock.close()
                stop.set()
                return None

            finally:
                sock.close()
                progress.update(task_id, advance=1)

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
    progress_lock = Lock()
    banners = {}

    # Check if the target is reachable by sending him a ICMP echo request.
    if info.ping(target):
        console.print(f"[bold green][+][/bold green] Host [bold]{target}[/bold] is up!")

    else:
        console.print(f"[bold red][!][/bold red] Host [bold]{target}[/bold] is down, exiting...")
        sys.exit()

    process_time = time.perf_counter()
    parsed_ports = parse_ports(ports)

    try:
        with Progress(
            SpinnerColumn(spinner_name="line", style="white"),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task_id:TaskID = progress.add_task("Initializing scan...", total=len(parsed_ports))
            
            with ThreadPoolExecutor(max_workers=threads) as executor:    # Using ThreadPoolExecutor to scan multiple ports concurrently, improving performance.
                futures = {executor.submit(scanner, port): port for port in parsed_ports}

                try:
                    for future in as_completed(futures):
                        if stop.is_set():  
                            # Cancel all pending futures.
                            for f in futures:
                                if not f.done():
                                    f.cancel()
                            
                            break
                
                except KeyboardInterrupt:
                    stop.set()

    except KeyboardInterrupt:
        stop.set()

    if stop.is_set():
        console.print(f"[bold red][!][/bold red] Scan interrupted! Time elapsed: {int(time.perf_counter() - process_time)}s")

    else:
        console.print(f"[bold green][+][/bold green] Scan completed! Time elapsed: {int(time.perf_counter() - process_time)}s")

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