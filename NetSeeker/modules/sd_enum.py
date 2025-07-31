import os
import re
import time
import sys
import random
import string
import requests
from dns import resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress, SpinnerColumn, TextColumn, TaskID
from threading import Event, Lock

from resources import services
from resources import console

#TODO:
# - Implement the search engine crawler.

def subdomainEnumeration(target, wordlist_path, timeout, rtypes, output, http_status, threads):

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
            progress.console.print(f"[bold red][!][/bold red] Invalid path for wordlist or invalid file: {filepath}") 
            sys.exit(1)

    # Parse DNS record types for the enumeration process.
    def parse_rtypes(rtypes):
        record_types = set()
        available_records = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]

        for part in rtypes.split(','):
            part = part.strip().upper()

            try:
                if part in available_records:
                    record_types.add(part)
                else:
                    raise Exception
            except (ValueError, Exception):
                console.print(f"[bold red][!][/bold red] Invalid record type specified: '{part}'")
                console.print(f"Available DNS record types: {", ".join(available_records)}")
                sys.exit(1)

        return sorted(record_types)


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
            if "A" in record_types:
                try:
                    response = resolver.resolve(sub, 'A')
                    ips = sorted(ip.to_text() for ip in response)
                    detected_a.append(tuple(ips))
                except: pass

            # AAAA records check.
            if "AAAA" in record_types:
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


    # Check HTTP/HTTPS status for a domain.
    def http_probe(domain):
        if stop.is_set(): return []

        results = []

        for scheme in ['https', 'http']:
            if stop.is_set():
                break

            try:
                url = f"{scheme}://{domain}"
                response = requests.get(url, timeout=3, allow_redirects=True, headers={'User-Agent': 'JeffBezos/1.0'})

                # Color code based on status.
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
                redirect_info = f" → {final_url}" if final_url and final_url != url else ""

                results.append(f"\t[{color}]└─[/] {scheme.upper()}: {response.status_code} - [bold]{server}[/bold]{redirect_info}")
            except requests.exceptions.Timeout:
                results.append(f"\t[bold red]└─[/] {scheme.upper()}: Timeout")
            except requests.exceptions.ConnectionError:
                results.append(f"\t[bold red]└─[/] {scheme.upper()}: Connection refused")
            except requests.exceptions.RequestException as e:
                results.append(f"\t[bold red]└─[/] {scheme.upper()}: Error ({type(e).__name__})")
            except KeyboardInterrupt:
                stop.set()
                break

        return results


    # Search subdomains on search engines.
    def se_crawler(subdomain, engine, page):
        if stop.is_set(): return

        output_text = []

        # Print output.
        with progress_lock:
            for line in output_text:
                progress.console.print(line)

        return output_text


    # Search subdomains by DNS bruteforce.
    def enumerator(subdomain, record_types):
        if stop.is_set(): return

        with progress_lock:
            progress.update(task_id, description=f"Performing DNS bruteforce on [yellow]{target}[/yellow] for subdomains: {subdomain}")

        full_domain = f"{subdomain}.{target}"
        found = False
        output_text = []

        for rtype in record_types:
            try:
                result = resolver.resolve(full_domain, rtype, lifetime=timeout)
                ips = [ip.to_text() for ip in result]

                # Wildcard filtering for A/AAAA records.
                if rtype in ("A", "AAAA") and any(ip in wildcard_ips for ip in ips):
                    break

                if not found:
                    with progress_lock:
                        output_text.append(f"[bold green][+][/bold green] Found subdomain: [green]{full_domain}[/green]")

                    # Verify HTTP status response.
                    if http_status:
                        http_result = http_probe(full_domain)
                        output_text.extend(http_result)

                    found = True
                    break
            except (resolver.NXDOMAIN, resolver.Timeout, resolver.NoAnswer):
                continue
            except KeyboardInterrupt:
                stop.set()
                return

        # Print output.
        with progress_lock:
            for line in output_text:
                progress.console.print(line)

        return output_text


    info = services.DevicesInfo()
    stop = Event()
    progress_lock = Lock()
    subdomains = []
    found_sd = []
    sd_count = 0

    if not info.check_domain(target):   
        console.print(f"[bold red][!][/bold red] Invalid domain: {target}")
        sys.exit(1)

    record_types = parse_rtypes(rtypes)
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

            with ThreadPoolExecutor(max_workers=threads) as executor:  # Using ThreadPoolExecutor to improve performance.
                try:
                    progress.update(task_id, description=f"Starting DNS enumeration")
                    futures = {executor.submit(enumerator, subdomain, record_types): subdomain for subdomain in subdomains}
                    for future in as_completed(futures):
                        # Cancel all pending futures.
                        if stop.is_set():
                            for f in futures:
                                if not f.done():
                                    f.cancel()
                            break

                        # Get the output lines.
                        result_lines = future.result()

                        if result_lines:
                            found_sd.extend(result_lines)
                            sd_count += 1

                except KeyboardInterrupt:
                    stop.set()

                    with progress_lock:
                        progress.update(task_id, description="Stopping enumeration, waiting for threads to finish...")

    except KeyboardInterrupt:
        stop.set()
            
    # Save results in a .txt file
    if output and found_sd:
        try:
            filepath = os.path.join(info.get_path("Documents", "NetSeeker"), f"sdenum-{target}-{time.strftime('%d%m%Y%H%M%S', time.localtime())}.txt")

            with open(filepath, 'w', encoding='utf-8') as f:
                current_subdomain = None

                for line in found_sd:
                    # Remove Rich tags and ANSI codes
                    cleaned = re.sub(r'\[/?(?:bold|green|yellow|red|magenta|/?)\]', '', line)
                    cleaned = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', cleaned)

                    # Match cleaned subdomain line
                    match = re.search(r'Found subdomain:\s*(.+)', cleaned)
                    if match:
                        current_subdomain = match.group(1).strip()
                        f.write(f"{current_subdomain}\n")
                    elif current_subdomain:
                        # Clean HTTP/HTTPS result line
                        cleaned_line = re.sub(r'\s*└─\s*', '', cleaned).strip()
                        if cleaned_line:
                            f.write(f"   - {cleaned_line}\n")

                output_success = True
        except Exception as e:
            output_success = False
            console.print(f"[bold red][!][/bold red] Failed to write file: {e}")

    console.print()

    if stop.is_set():
        console.print(f"[bold yellow][~][/bold yellow] Enumeration interrupted! Time elapsed: {int(time.perf_counter() - process_time)}s")
    else:
        console.print(f"[bold green][+][/bold green] Enumeration completed! Time elapsed: {int(time.perf_counter() - process_time)}s")
    
    if output and output_success:
        console.print(f"[bold green][+][/bold green] Results saved to: {filepath}")
    elif output and not output_success:
        console.print(f"[bold red][!][/bold red] Could not write to file {filepath}")

    if not found_sd:
        console.print("[bold red][!][/bold red] No subdomain was found.")
    else:
        console.print(f"[bold green][+][/bold green] Found {sd_count} subdomains.")
        for domain in found_sd:
            console.print(domain)


if __name__ == '__main__':
    pass