import re
import time
import typer
import socket
import requests
import random
import string
from dns import resolver
from threading import Event, Lock
from rich.progress import Progress, SpinnerColumn, TextColumn, TaskID
from concurrent.futures import ThreadPoolExecutor, as_completed

from resources import services
from resources import console


def subdomainEnumeration(target, wordlist_path, timeout, ipv6, mx, output, http_status, threads):

    # Load wordlists for the bruteforce function.
    def load_wordlist(filepath, wordlist):
        loaded = set(wordlist)

        try:
            with open(filepath, 'r') as file:
                for line in file:
                    subdomain = line.strip()

                    # Verifying if it's a valid subdomain.
                    if not subdomain or not re.match(r'[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?', subdomain):
                        continue

                    if subdomain not in loaded:
                        loaded.add(subdomain)
                        wordlist.append(subdomain)

        except Exception:
            progress.console.print(f"[bold red][!] ERROR:[/bold red] Invalid file path for wordlist: {filepath}") 
            raise typer.Exit(code=1)


    # Detect wildcard addresses to ignore any resolutions on the scanner function.
    def detect_wildcard(domain):

        # Generates a random subdomain.
        def generate_subdomain():
            random.seed(time.time())
            return ''.join(random.choice((string.ascii_letters + string.digits)) for _ in range(12))

        detected_a = []
        detected_aaaa = []
        wildcard_ips = []

        for _ in range(3):
            sub = f"{generate_subdomain()}.{domain}"

            # A records check.
            try:
                response = resolver.resolve(sub, 'A')
                ips = sorted(ip.to_text() for ip in response)
                detected_a.append(tuple(ips))
            except: pass

            # AAAA records check.
            if ipv6:
                try:
                    response6 = resolver.resolve(sub, 'AAAA')
                    ips6 = sorted(c.to_text() for c in response6)
                    detected_aaaa.append(tuple(ips6))
                except: pass

        if not detected_a and not detected_aaaa:
            progress.console.print(f"[bold yellow]\\[i][/bold yellow] No wildcard DNS detected.")
            return None 

        if detected_a and len(set(detected_a)) == 1:
            progress.console.print(f"[bold yellow]\\[i][/bold yellow] A-record wildcard DNS detected: {"".join(ips)}")
            wildcard_ips.extend(detected_a[0])

        if detected_aaaa and len(set(detected_aaaa)) == 1:
            progress.console.print(f"[bold yellow]\\[i][/bold yellow] AAAA-record wildcard DNS detected: {"".join(ips6)}")
            wildcard_ips.extend(detected_aaaa[0])

        return wildcard_ips


    #
    def scanner(subdomain, record_types):

        # Check HTTP/HTTPS status for a domain
        def check_http(domain):
            if stop.is_set(): return

            results = []

            for scheme in ['https', 'http']:
                try:
                    url = f"{scheme}://{domain}"
                    response = requests.get(url, timeout=3, allow_redirects=True, headers={'User-Agent': 'JeffBezos/1.0'})
                    
                    # Color code based on status
                    if 200 <= response.status_code < 300:
                        color = "bold green"
                    elif 300 <= response.status_code < 400:
                        color = "bold yellow" 
                    elif 400 <= response.status_code < 500:
                        color = "bold red"
                    else:
                        color = "bold magenta"

                    server = response.headers.get('Server', 'Unknown')
                    final_url = response.url if response.url != url else ""
                    redirect_info = f" → {final_url}" if final_url and final_url != url else ""   # In case of redirects.

                    results.append(f"\t[{color}]└─[/] {scheme.upper()}: {response.status_code} - [bold]{server}[/bold]{redirect_info}")

                except requests.exceptions.Timeout:
                    results.append(f"\t[bold red]└─[/] {scheme.upper()}: Timeout")
                except requests.exceptions.ConnectionError:
                    results.append(f"\t[bold red]└─[/] {scheme.upper()}: Connection refused")
                except requests.exceptions.RequestException as e:
                    results.append(f"\t[bold red]└─[/] {scheme.upper()}: Error ({type(e).__name__})")
                except KeyboardInterrupt:
                    stop.set()
                    return

            return results


        if stop.is_set(): return

        with progress_lock:
            progress.update(task_id, description=f"Scanning [yellow]{target}[/yellow] for subdomains: {subdomain}", advance=1)

        full_domain = f"{subdomain}.{target}"
        found = False
        output = []

        # Searching subdomains by bruteforce.
        for rtype in record_types:
            try:
                result = resolver.resolve(full_domain, rtype)
                ips = [ip.to_text() for ip in result]

                # Wildcard filtering for A/AAAA records.
                if rtype in ("A", "AAAA") and any(ip in wildcard_ips for ip in ips):
                    break

                if not found:
                    with progress_lock:
                        output.append(f"[bold green][+][/bold green] Found subdomain: [green]{full_domain}[/green]")
                        found_subdomains.append(full_domain)

                    if http_status: 
                        output.extend(check_http(full_domain))

                    found = True
                    break

            # Domain name not found or time expired.
            except (resolver.NXDOMAIN, resolver.Timeout, resolver.NoAnswer):
                continue

            except KeyboardInterrupt:
                stop.set()
                return
        
        # Print output.
        with progress_lock:
            for line in output:
                progress.console.print(line)


    info = services.DevicesInfo()
    stop = Event()
    progress_lock = Lock()
    subdomains = []
    found_subdomains = []

    if not info.check_domain(target):   
        console.print(f"[bold red][!] ERROR:[/bold red] Invalid domain: {target}")
        raise typer.Exit(code=1)

    record_types = ["A", "CNAME", "TXT", "NS"]  
    if ipv6: record_types.append("AAAA")
    if mx: record_types.append("MX")
    
    process_time = time.perf_counter()

    try:
        with Progress(
            SpinnerColumn(spinner_name="line", style="white"),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task_id:TaskID = progress.add_task("Starting enumeration...")
            
            # Loading subdomains.
            progress.update(task_id, description=f"Loading wordlist...")
            if wordlist_path: 
                load_wordlist(wordlist_path, subdomains)
                progress.console.print("[bold green][+][/bold green] Loaded wordlist successfully!")
            load_wordlist('resources/txt/subdomains.txt', subdomains)   # need to create my own subdomains.txt (using subbrute list)

            # Detecting wildcard DNS.
            progress.update(task_id, description=f"Detecting wildcard addresses...")
            wildcard_ips = detect_wildcard(target)

            with ThreadPoolExecutor(max_workers=threads) as executor:    # Using ThreadPoolExecutor to improve performance.
                futures = {executor.submit(scanner, subdomain, record_types): subdomain for subdomain in subdomains}
                
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
                        progress.update(task_id, description="Stopping enumeration, waiting for threads to finish...")

    except KeyboardInterrupt:
        stop.set()
    
    if stop.is_set():
        console.print(f"[bold red][!][/bold red] Enumeration interrupted! Time elapsed: {int(time.perf_counter() - process_time)}s")
    else:
        console.print(f"[bold green][+][/bold green] Enumeration completed! Time elapsed: {int(time.perf_counter() - process_time)}s")
    
    if not found_subdomains:
        console.print("[bold red][!][/bold red] No subdomain was found.")
    else:
        console.print(f"[bold green][+][/bold green] Found {len(found_subdomains)} subdomains.")


if __name__ == '__main__':
    pass