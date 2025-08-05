import os
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

def portScanner(target, ports, timeout, udp, threads, bg, output, verbose):

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
            progress.update(task_id, description=f"Scanning port [yellow]{port}[/yellow]")

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
                    results.append((str(port) + "/udp", "OPEN|FILTERED", (port_service or "NOT FOUND")))

                # No response within timeout could also mean it might be open/filtered.
                except socket.timeout:
                    port_service = socket.getservbyport(port, "udp")
                    if verbose: progress.console.print( f"[bold green][+][/bold green] Port [green]{port}[/green] is [bold]OPEN|FILTERED[/bold].")
                    if bg: banner_grabbing()
                    table.add_row(str(port) + "/udp", "OPEN|FILTERED", (port_service or "NOT FOUND"))
                    results.append((str(port) + "/udp", "OPEN|FILTERED", (port_service or "NOT FOUND")))

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
                    results.append((str(port), "OPEN", (port_service or "NOT FOUND")))

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
    results = []

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

    if verbose: console.print()

    # Save results in a .txt file.
    if output and table.row_count > 0:
        try:
            # Check for existing files.
            base_filename = f"portscan-{str(target).replace('/', '.')}"
            counter = 0

            while True:
                suffix = f"-{counter}" if counter > 0 else ""
                filename = f"{base_filename}-{time.strftime('%d_%m_%Y')}{suffix}.txt"
                filepath = os.path.join(info.get_path("Documents", "NetSeeker"), filename)

                if not os.path.exists(filepath):
                    break
                counter += 1

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"Port scanner results for {target} - {time.strftime('%H:%M:%S %d/%m/%Y')}\n\n")

                # Write the table data.
                f.write("PORT        STATE       SERVICE\n")
                f.write("-------------------------------------\n")

                for port, state, service in results:
                    f.write(f"{port:<10}  {state:<10}  {service:<10}\n")
                
                # Write the banner grabbing results if any.
                if banners:
                    f.write("\n\n--- BANNERS FOUND ---\n")
                    for port, banner in banners.items():
                        f.write(f"\n- Port {port}:\n")
                        f.write(f"  {banner}\n")

            output_success = True
        except Exception as e:
            output_success = False
            console.print(f"[bold red][!][/bold red] Failed to write file: {e}")

    if stop.is_set():
        console.print(f"[bold yellow][~][/bold yellow] Scan interrupted! Time elapsed: {int(time.perf_counter() - process_time)}s")

    else:
        console.print(f"[bold green][+][/bold green] Scan completed! Time elapsed: {int(time.perf_counter() - process_time)}s")

    if output and output_success:
        console.print(f"[bold green][+][/bold green] Results saved to: {filepath}")
    elif output and not output_success:
        console.print(f"[bold red][!][/bold red] Could not write to file {filepath}")

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