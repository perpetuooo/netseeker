import time
import sys
import random
import logging

from rich.progress import Progress, SpinnerColumn, TextColumn, TaskID
from scapy.all import ARP, Ether, IP, srp, RandMAC, ICMP, sr1, TCP, UDP
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

# Force Scapy to refresh routing and suppress warnings.
conf.route.resync()
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def networkScanner(target, retries, timeout, threads, stealth, icmp, arp, tcp_syn, tcp_ack, udp, force_scan, ports, verbose):
    
    def scanner(host):

        def arp_scan():
            nonlocal host_responded
            
            try:
                arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=RandMAC())/ARP(pdst=str(host))
                response = None

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
                progress.console.print(f"[bold red][!][/bold red] ARP SCAN ERROR: {str(e)}")

        def icmp_scan():
            nonlocal host_responded

            try:
                icmp_pkt = IP(dst=str(host))/ICMP()
                response = None

                if retries == 0:
                    response = sr1(icmp_pkt, timeout=timeout, verbose=0)

                else:   
                    for _ in range(retries):
                        response = sr1(icmp_pkt, timeout=timeout, verbose=0)
                        if response: break

                if response and response.haslayer(ICMP) and response[ICMP].type == 0:   # Echo reply.
                    host_data['hostname'] = info.get_hostname(host)
                    host_data['scans'].append("ICMP")
                    host_responded = True
            
            except KeyboardInterrupt:
                stop.set()
                return
            
            except Exception as e:
                progress.console.print(f"[bold red][!][/bold red] ICMP SCAN ERROR: {str(e)}")
            
        def tcp_syn_scan():
            nonlocal host_responded

            try:
                if stealth: time.sleep(random.uniform(0.1, 0.5))

                open_ports = []
                for port in ports:
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

                    if stealth: break   # Try only on port 80.
                
                if open_ports:
                    if not stealth and host_data['hostname'] == "NOT FOUND": host_data['hostname'] = info.get_hostname(host)
                    host_data['scans'].append(f"TCP SYN ({','.join(open_ports)})")
                
            except KeyboardInterrupt:
                stop.set()
                return
            
            except Exception as e:
                progress.console.print(f"[bold red][!][/bold red] TCP SYN SCAN ERROR: {str(e)}")
        
        def tcp_ack_scan():
            nonlocal host_responded

            try:
                open_ports = []
                for port in ports:
                    ack_pkt = IP(dst=str(host))/TCP(dport=port, flags="A")
                    response = None

                    if retries == 0:
                        response = sr1(ack_pkt, timeout=timeout, verbose=0)
                    else:
                        for _ in range(retries):
                            response = sr1(ack_pkt, timeout=timeout, verbose=0)
                            if response:
                                break
                    
                    # Check for RST.
                    if response and response.haslayer(TCP) and response[TCP].flags & 0x04:  # Port is unfiltered by a firewall.
                        open_ports.append(str(port))  
                        host_responded = True
                
                if open_ports:
                    if host_data['hostname'] == "NOT FOUND": host_data['hostname'] = info.get_hostname(host)
                    host_data['scans'].append(f"TCP ACK ({','.join(open_ports)})")

            except KeyboardInterrupt:
                stop.set()
                return
            except Exception as e:
                progress.console.print(f"[bold red][!][/bold red] TCP ACK SCAN ERROR: {str(e)}")

        def udp_scan():
            nonlocal host_responded

            try:
                open_ports = []
                for port in ports:
                    udp_pkt = IP(dst=str(host))/UDP(dport=port)
                    response = None

                    if retries == 0:
                        response = sr1(udp_pkt, timeout=timeout, verbose=0)
                    else:
                        for _ in range(retries):
                            response = sr1(udp_pkt, timeout=timeout, verbose=0)
                            if response:
                                break
                    
                    # Check for ICMP Port Unreachable.
                    # if response and response.haslayer(ICMP):
                    #     if response[ICMP].type == 3 and response[ICMP].code == 3:
                    #         pass
                    
                    # If no response the port is likely open.
                    if not response:
                        open_ports.append(str(port))
                        host_responded = True

                if open_ports:
                    if host_data['hostname'] == "NOT FOUND": host_data['hostname'] = info.get_hostname(host)
                    host_data['scans'].append(f"UDP ({','.join(open_ports)})")
            except KeyboardInterrupt:
                stop.set()
                return
            except Exception as e:
                progress.console.print(f"[bold red][!][/bold red] UDP SCAN ERROR: {str(e)}")



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
            if default_scans or arp and local_network and not stealth:
                arp_scan()
            
            # ICMP.
            if default_scans or icmp and not stealth and (not host_responded or force_scan):
                icmp_scan()

            # TCP SYN for normal and stealth mode.
            if default_scans or tcp_syn or stealth and (not host_responded or force_scan):
                tcp_syn_scan()

            # TCP ACK.
            if tcp_ack and not stealth and (not host_responded or force_scan):
                tcp_ack_scan()

            #UDP.
            if udp and not stealth and (not host_responded or force_scan):
                udp_scan()

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
    

    # Validate and process the target input.
    current_network = info.get_network()
    if target in ("Connected Network", current_network):
        target = current_network # Use the current connected network if no target is specified.
        local_network = True
    
    # ARP scan only for local networks.
    if not local_network and arp:
        progress.console.print(f"[bold red][!][/bold red] Invalid network for ARP scan: {target}")
        sys.exit(1)
    
    # Use default parameters if neither scan was specified.
    default_scans = True if not (arp or icmp or tcp_syn or tcp_ack or udp) else False  

    # Parse ports if is needed in the scanner.
    if default_scans or tcp_syn or tcp_ack or udp:
        if not (parsed_ports := info.parse_ports(ports)) or len(parsed_ports) > 5:
            console.print(f"[bold red][!][/bold red] Invalid port range specified: {ports}")
            sys.exit(1)

    # Validate network range.
    try:
        network = IPv4Network(target)
    except ValueError:
        console.print(f"[bold red][!][/bold red] Invalid network specified: {target}")
        sys.exit(1)
    
    # Create a list of all hosts in the network.
    hosts = [str(ip) for ip in network.hosts()]
    process_time = time.perf_counter() 

    try:
        with Progress(
            SpinnerColumn(spinner_name="line", style="white"),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=console
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
        console.print(f"[bold yellow][~][/bold yellow] Scan interrupted! Time elapsed: {int(time.perf_counter() - process_time)}s")
    
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
