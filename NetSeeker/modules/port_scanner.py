import sys
import time
import socket
from threading import Event, Lock
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, TaskID
from concurrent.futures import ThreadPoolExecutor, as_completed

from resources import services
from resources import console

"""
TODO: 
- Add support to IPv6
- Implement a better banner grabbing technique
- Create a stealth scan alternative
"""

def portScanner(target, ports, timeout, udp, threads, bg, verbose):

    def scanner(port):

        def banner_grabbing():
            try:
                banner = sock.recv(1024).decode().strip()   # Receive up to 1024 bytes for the banner.
                banners[port] = banner

            except Exception:
                pass


        if stop.is_set(): return

        # Update the progress description to show the current port.
        with progress_lock:
            progress.update(task_id, description=f"Scanning port {port}")

        # UDP scanner.
        if udp:
            try:
                # Create a UDP socket and send an empty packet.
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                sock.sendto(b"",(target, port))

                try:
                    sock.recvfrom(1024)
                    # If there is any response, it might be open or filtered.
                    port_service = socket.getservbyport(port)
                    if verbose: progress.console.print( f"[bold green][+][/bold green] Port [green]{port}[/green] is [bold]OPEN|FILTERED[/bold].")
                    if bg: banner_grabbing()
                    table.add_row(str(port) + "/udp", "OPEN|FILTERED", (port_service or "NOT FOUND"))

                # No response within timeout could also mean it might be open/filtered.
                except socket.timeout:
                    port_service = socket.getservbyport(port, "udp")
                    if verbose: progress.console.print( f"[bold green][+][/bold green] Port [green]{port}[/green] is [bold]OPEN|FILTERED[/bold].")
                    if bg: banner_grabbing()
                    table.add_row(str(port) + "/udp", "OPEN|FILTERED", (port_service or "NOT FOUND"))

                except socket.error as e:
                    if e.errno == 10054 or e.errno == 149:  # ICMP Port Unreachable (Windows/Linux)
                        pass
                    
                except Exception as e:
                    if "port/proto not found" in str(e):  # Service name not found.
                        pass
                    else:
                        progress.console.print(f"[bold red][!][/bold red] UDP SCAN ERROR: {str(e)}")
                        sock.close()
                        return None
            
            except KeyboardInterrupt:
                stop.set()
                return
            
            finally:
                progress.update(task_id, advance=1)
                sock.close()
        
        # TCP scanner
        else:
            try:
                # Create a TCP socket and send an empty packet.
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    
                socket.setdefaulttimeout(timeout)
                response = sock.connect_ex((target, port))

                # If the port is open, add it to the results table.
                if response == 0:
                    port_service = socket.getservbyport(port)
                    if verbose: progress.console.print( f"[bold green][+][/bold green] Port [green]{port}[/green] is [bold]OPEN[/bold].")
                    table.add_row(str(port), "OPEN", (port_service or "NOT FOUND"))

                    if bg: banner_grabbing()
                    
            except Exception as e:
                if "port/proto not found" in str(e):  # Service name not found.
                    pass

                else:
                    progress.console.print(f"[bold red][!][/bold red] TCP SCAN ERROR: {str(e)}")
                    sock.close()
                    return None
            
            except KeyboardInterrupt:
                sock.close()
                stop.set()
                return None

            finally:
                sock.close()
                progress.update(task_id, advance=1)
        
    # Parse ports for the scanner process.
    def parse_ports(ports):
        parsed_ports = set()  # Using set to dismiss duplicate ports.

        if ports == 'all': ports = '1-65535'

        for part in ports.split(","):
            part = part.strip()

            try:
                if "-" in part: # Handle port ranges (e.g., "1-1024").
                    start, end = map(int, part.split("-"))

                    if end > 65535: end = 65535    #Max ports.

                    parsed_ports.update(range(start, end + 1))
                # Handle single ports.
                else:
                    parsed_ports.add(int(part))

            except ValueError:
                console.print(f"[bold red][!][/bold red] Invalid port range specified: {part}")
                sys.exit(1)

        return sorted(parsed_ports)


    def display_banners(banners):
        for port, banner in banners.items():
            console.print(Panel(
                banner,
                title=f"Port {port}",
                padding=(1, 2),
                box=box.ASCII
        ))


    info = services.DevicesInfo()
    table = Table("PORT", "STATE", "SERVICE", box=box.MARKDOWN)
    stop = Event()
    progress_lock = Lock()
    banners = {}

    # Check if the target is reachable by sending him a ICMP echo request.
    if target == '127.0.0.1' or info.ping(target):
        console.print(f"[bold green][+][/bold green] Host [yellow]{target}[/yellow] is up!")

    else:
        console.print(f"[bold red][!][/bold red] Host [yellow]{target}[/yellow] is down, exiting...")
        sys.exit(1)

    if not (parsed_ports := info.parse_ports(ports)):
        console.print(f"[bold red][!][/bold red] Invalid port range specified: {ports}")
        sys.exit(1)

    process_time = time.perf_counter()

    try:
        with Progress(
            SpinnerColumn(spinner_name="line", style="white"),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=console
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

                    with progress_lock:
                        progress.update(task_id, description="Stopping scanner, waiting for threads to finish...")

    except KeyboardInterrupt:
        stop.set()

    if verbose: console.print() # New line.

    if stop.is_set():
        console.print(f"[bold yellow][~][/bold yellow] Scan interrupted! Time elapsed: {int(time.perf_counter() - process_time)}s")

    else:
        console.print(f"[bold green][+][/bold green] Scan completed! Time elapsed: {int(time.perf_counter() - process_time)}s")

    if table.row_count == 0:
        console.print(f"[bold red][!][/bold red] No open ports on [bold]{target}[/bold]")

    else:
        console.print(f"[bold yellow]\\[i][/bold yellow] Found {table.row_count} open ports: ")
        console.print(table)

        if bg:
            if banners:
                console.print("[bold yellow]\\[i][/bold yellow] Banners found: ")
                display_banners(banners)
            else:
                console.print("[bold red][!][/bold red] No banner was found.")



if __name__ == '__main__':
    pass