import time
import typer
import socket
import random
import string
from dns import resolver
from threading import Event, Lock
from rich.progress import Progress, SpinnerColumn, TextColumn, TaskID
from concurrent.futures import ThreadPoolExecutor, as_completed

from resources import services
from resources import console


def subdomainEnumeration(target, wordlist_path, timeout, ipv6, http_timeout, output, http_status, threads):

    #
    def load_wordlist(filepath, wordlist):
        try:
            with open(filepath, 'r') as file:
                for line in file:
                    wordlist.add(line.strip())

        except Exception as e:
            progress.console.print(f"[bold red][!] ERROR:[/bold red] Invalid file path for wordlist: {filepath}") 
            raise typer.Exit(code=1)

    # Detect wildcard addresses to ignore any resolutions on the scanner function.
    def detect_wildcard(domain):

        # Generates a random subdomain.
        def generate_subdomain():
            random.seed(time.time())
            return ''.join(random.choice((string.ascii_letters + string.digits)) for _ in range(12))

        detected_a_records = []
        detected_cnames = []
        wildcard_ips = set()
        wildcard_cnames = set()

        for _ in range(3):
            sub = f"{generate_subdomain()}.{domain}"

            # A record check.
            try:
                response = resolver.resolve(sub, 'A')
                ips = sorted(ip.to_text() for ip in response)
                detected_a_records.append(tuple(ips))
            except Exception:
                detected_a_records.append(None)

            # CNAME check.
            try:
                cname_response = resolver.resolve(sub, 'CNAME')
                cnames = sorted(c.to_text() for c in cname_response)
                detected_cnames.append(tuple(cnames))
            except:
                detected_cnames.append(None)

        success_a = [ip for ip in detected_a_records if ip]
        success_c = [c for c in detected_cnames if c]

        if not success_a and not success_c:
            progress.console.print(f"[bold yellow]\\[i][/bold yellow] No wildcard DNS detected.")
            return None 

        # Handle A record wildcard detection.
        unique_a = set(success_a)
        if len(unique_a) == 1:
            wildcard_ips = set(unique_a.pop())
            progress.console.print(f"[bold yellow]\\[i][/bold yellow] A-record widlcard DNS detected: [yellow]{''.join(wildcard_ips)}[/yellow]")
        else:
            progress.console.print(f"[bold yellow]\\[i][/bold yellow] Inconsistent A-record wildcard behavior detected, ignoring results[white]...")

        # Handle CNAME wildcard detection.
        unique_cnames = set(success_c)
        if len(unique_cnames) == 1:
            wildcard_cnames = set(unique_cnames.pop())
            progress.console.print(f"[bold yellow]\\[i][/bold yellow] CNAME wildcard DNS detected: [yellow]{wildcard_cnames}[/yellow]")
        else:
            progress.console.print(f"[bold yellow]\\[i][/bold yellow] Inconsistent CNAME wildcard behavior detected, ignoring results[white]...")

        return wildcard_ips.union(wildcard_cnames)

    #
    def scanner(subdomain):

        # def check_http():
        #   pass

        # def bruteforce():
        #   pass

        try:
            full_domain = f"{subdomain}.{target}"
            result = resolver.resolve(full_domain)
            ips = [ip.to_text() for ip in result]

            # Skip if it's a wildcard response.
            if any(ip in wildcard_ips for ip in ips):
                return

            progress.console.print(f"[bold green][+][/bold green] Found subdomain: [green][link=https://{full_domain}]{full_domain}[/link][/green]")

            with progress_lock:
                found_subdomains.append(full_domain)

        except Exception:
            pass

        finally:
            progress.update(task_id, advance=1)


    info = services.DevicesInfo()
    stop = Event()
    progress_lock = Lock()
    subdomains = set()
    found_subdomains = []

    if not info.check_domain(target):
        console.print(f"[bold red][!] ERROR:[/bold red] Invalid domain: {target}")
        raise typer.Exit(code=1)
    
    process_time = time.perf_counter()

    try:
        with Progress(
            SpinnerColumn(spinner_name="line", style="white"),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task_id:TaskID = progress.add_task("Starting enumeration...")
            
            # Loading subdomains.
            progress.update(task_id, description=f"Loading wordlist")
            load_wordlist('resources/txt/subdomains.txt', subdomains)   # need to create your own subdomains.txt (using subbrute list)
            if wordlist_path: load_wordlist(wordlist_path, subdomains)

            # Detecting wildcard DNS.
            progress.update(task_id, description=f"Detecting wildcard addresses")
            wildcard_ips = detect_wildcard(target)

            progress.update(task_id, description=f"Scanning [yellow]{target}[/yellow] for subdomains (this might take a while)", total=len(subdomains))

            with ThreadPoolExecutor(max_workers=threads) as executor:    # Using ThreadPoolExecutor to improve performance.
                futures = {executor.submit(scanner, subdomain): subdomain for subdomain in subdomains}
                
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
        console.print(f"[bold green][!][/bold green] Found {len(found_subdomains)} subdomains.")


if __name__ == '__main__':
    pass