import time
import sys
import random
import logging

from rich.progress import Progress, SpinnerColumn, TextColumn, TaskID
from scapy.all import ARP, Ether, IP, srp, RandMAC, ICMP, sr1, TCP
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import IPv4Network
from threading import Event, Lock
from scapy.config import conf
from rich.table import Table
from rich import box


from resources import console
from resources import services

"""
TODO: 
- Add support to IPv6
- UDP and TCP ACK scans
- OS fingerprinting
- Detect devices types based on their MACs (OUI)
- Add a verbose option?
"""

def networkScanner(target, retries, timeout, threads, stealth, local_tcp_syn, force_scan, verbose):
    
    def scanner(host):

        def arp_scan():
            nonlocal host_responded
            
            try:
                arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=(RandMAC() if stealth else None))/ARP(pdst=str(host))
                response = None

                if stealth: time.sleep(random.uniform(0.1, 0.5))

                if retries == 0:
                    response = srp(arp_pkt, timeout=timeout, verbose=0)[0]
                
                else:
                    for _ in range(retries):
                        response = srp(arp_pkt, timeout=timeout, verbose=0)[0]
                        if response: break

                if response:
                    for _, received in response:
                        host_data['hostname'] = info.get_hostname(host)
                        host_data['mac'] = received.hwsrc
                        host_data['scans'].append("ARP")
                        host_responded = True
            
            except KeyboardInterrupt:
                stop.set()
                return
            
            except Exception as e:
                progress.console.print(f"[bold red][!] ARP SCAN ERROR:[/bold red] {str(e)}")

        def icmp_scan():
            nonlocal host_responded

            try:
                icmp_echo = IP(dst=str(host))/ICMP()
                response = None

                if retries == 0:
                    response = sr1(icmp_echo, timeout=timeout, verbose=0)

                else:   
                    for _ in range(retries):
                        response = sr1(icmp_echo, timeout=timeout, verbose=0)
                        if response: break

                if response and response.haslayer(ICMP) and response[ICMP].type == 0:   # Echo reply.
                    host_data['scans'].append("ICMP")
                    host_responded = True
            
            except KeyboardInterrupt:
                stop.set()
                return
            
            except Exception as e:
                progress.console.print(f"[bold red][!] ICMP SCAN ERROR:[/bold red] {str(e)}")
            
        def tcp_syn_scan():
            nonlocal host_responded

            try:
                open_ports = []
                for port in [80, 443, 22]:
                    if stop.is_set(): return

                    syn_pkt = IP(dst=str(host))/TCP(dport=port, flags="S")
                    response = None

                    if retries == 0:
                        response = sr1(syn_pkt, timeout=timeout, verbose=0)
                    
                    else:
                        for _ in range(retries):
                            response = sr1(syn_pkt, timeout=timeout, verbose=0)
                            if response: break

                    # Check for SYN-ACK or RST.
                    if response and response.haslayer(TCP):
                        if response[TCP].flags & 0x12:  # SYN-ACK (port open).
                            open_ports.append(str(port))
                            host_responded = True
                        
                        elif response[TCP].flags & 0x04: # RST (host alive).
                            host_responded = True
                
                if open_ports:
                    host_data['scans'].append(f"TCP({','.join(open_ports)})")
                
            except KeyboardInterrupt:
                stop.set()
                return
            
            except Exception as e:
                progress.console.print(f"[bold red][!] TCP SYN SCAN ERROR:[/bold red] {str(e)}")


        try:
            if stop.is_set(): return

            # Update the progress description to show the current host.
            with progress_lock:
                progress.update(task_id, description=f"Scanning host [yellow]{host}[/yellow]")

            host_responded = False
            host_data = {
                'hostname': "NOT FOUND",
                'mac': "NOT FOUND",
                'scans': []
            }

            # ARP for local networks.
            if local_network:
                arp_scan()
            
            # ICMP for local/remote networks if stealth scan is disabled (only if the host was not found or force_scan is enabled).
            if not stealth and (not host_responded or force_scan):
                icmp_scan()

            # TCP SYN scan for remote networks or local networks if local_tcp_syn is enabled (only if the host was not found or force_scan is enabled).
            if (not local_network) or (local_network and local_tcp_syn and (not host_responded or force_scan)):
                tcp_syn_scan()

            # Append results.
            if host_responded:
                if verbose:
                    progress.console.print(f"[bold green][+][/bold green] Host found: {host}")

                found_hosts[host] = host_data

        except KeyboardInterrupt:
            stop.set()
            return

        finally:
            progress.update(task_id, advance=1)


    found_hosts = {}    # IP as key, hostname and MAC as values.
    info = services.DevicesInfo()
    table = Table("HOSTNAME", "IP", "MAC", ("SCANS" if force_scan else "SCAN"), box=box.MARKDOWN)
    stop = Event()
    progress_lock = Lock()

    # Force Scapy to refresh routing and suppress warnings.
    conf.route.resync()
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    current_network = info.get_network()

    # Validate and process the target input.
    if target in ("Connected Network", current_network):
        target = current_network # Use the current connected network if no target is specified.
        local_network = True
    
    try:
        network = IPv4Network(target)
    except ValueError:
        console.print(f"[bold red][!] ERROR:[/bold red] Invalid target specified: {target}")
        sys.exit(1)
    
    # Create a list of all hosts in the network.
    hosts = [str(ip) for ip in network.hosts()]
    process_time = time.perf_counter()

    try:
        with Progress(
            SpinnerColumn(spinner_name="line", style="white"),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task_id:TaskID = progress.add_task("Initializing scan...", total=len(hosts))

            with ThreadPoolExecutor(max_workers=threads) as executor:    # Using ThreadPoolExecutor to scan multiple hosts concurrently, improving performance.
                futures = {executor.submit(scanner, host): host for host in hosts}

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
        
    if stop.is_set():
        console.print(f"[bold red][!][/bold red] Scan interrupted! Time elapsed: {int(time.perf_counter() - process_time)}s")
    
    else:
        console.print(f"[bold green][+][/bold green] Scan completed! Time elapsed: {int(time.perf_counter() - process_time)}s")


    for ip_addr, data in found_hosts.items():
        table.add_row(data['hostname'], ip_addr, data['mac'], ", ".join(map(str, data.get('scans', []))))

    if table.row_count == 0:
        console.print(f"[bold red][!][/bold red] No hosts found on [bold]{target}[/bold] network.")

    else:
        console.print(f"[bold yellow]\\[i][/bold yellow] Found {table.row_count} hosts: ")
        console.print(table)



if __name__ == '__main__':
    pass
