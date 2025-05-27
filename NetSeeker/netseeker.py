from typer import Typer, Argument, Option
from typing_extensions import Annotated

from modules import port_scanner
from modules import network_scanner
from modules import traceroute
# from modules import arp_spoofer

app = Typer(rich_markup_mode="rich")


@app.command("info")
def app_info():
    """Info about the project."""
    pass


@app.command("portscan")
def app_port_scanner(target: Annotated[str, Argument(help="Target IP/domain.")] = "127.0.0.1",
                    ports: Annotated[str, Option("--ports", "-p", help="Ports to scan (e.g., 'x' for a single port, 'x-y' for a range, or 'x,y,z' for specific ports).")] = "1-1024",
                    timeout: Annotated[int, Option("--timeout", "-t", help="Timeout for waiting a reply (seconds).")] = 1,
                    udp: Annotated[bool, Option("--udp", "-sU", help="Enable UDP scan.")] = False,
                    banner: Annotated[bool, Option("--banner", "-b", help="Enable banner grabbing for open ports, attempting to identify the service and version.")] = False,
                    threads: Annotated[int, Option("--threads", "-tr", help="Max. ammount of concurrent threads for the scanner process.")] = 100):
    """Scans a target IP address or domain for open TCP and/or UDP ports."""
    port_scanner.portScanner(target, ports, timeout, udp, threads, banner)


@app.command("netscan")
def app_network_scanner(target: Annotated[str, Argument(help="Target IP range (e.g., '192.168.1.0/24' or '10.0.0.1-10.0.0.254').")] = "Connected Network",
                    retries: Annotated[int, Option("--retries", "-r", help="Max. number of retries per host.")] = 0,
                    timeout: Annotated[int, Option("--timeout", "-t", help="Timeout for waiting a reply (seconds).")] = 1,
                    udp: Annotated[bool, Option("--udp", "-sU", help="Enable UDP scan.")] = False,
                    tcp_ack: Annotated[bool, Option("--tcp-ack", "-sTA", help="Enable TCP ACK scan.")] = False,
                    local_tcp_syn: Annotated[bool, Option("--local-tcp-syn", "-sTS", help="Performs a TCP SYN scan on local networks.")] = False,
                    force_scan: Annotated[bool, Option("--force", "-f", help="Force all scans even if a host was already found.")] = False,
                    stealth: Annotated[bool, Option("--stealth", "-sS", help="Enables slower scanning methods and disables aggressive techniques to reduce the likelihood of detection (disables ICMP scans).")] = False,
                    threads: Annotated[int, Option("--threads", "-tr", help="Max. ammount of concurrent threads for the scanner process.")] = 100):
    """Discover hosts on a network (ARP + ICMP for local networks and ICMP + TCP SYN on common ports for remote)."""
    network_scanner.networkScanner(target, retries, timeout, threads, stealth, local_tcp_syn, force_scan)


@app.command("traceroute")
def app_traceroute(target: Annotated[str, Argument(help="Target IP/domain.")] = "",
                timeout: Annotated[int, Option("--timeout", "-t", help="Timeout for receiving packets (seconds).")] = 3,
                max_hops: Annotated[int, Option("--max-hops", "-m", help="Max. amount of hops.")] = 30,
                gen_map: Annotated[bool, Option("--generate-map", "-g", help="Generate an interactive map visualizing the traceroute path.")] = False,
                save_file: Annotated[bool, Option("--save-file", "-s", help="Save the generated map to an HTML file.")] = False):
    """Traces the network path that yours IP packets take to reach a target host."""
    traceroute.tracerouteWithMap(target, timeout, max_hops, gen_map, save_file)


@app.command("arpspoofer")
def app_arp_spoofer(target: Annotated[str, Argument(help="Target IP.")] = "",
                host: Annotated[str, Argument(help="Target host.")] = "",
                timing: Annotated[int, Option("--timing", "-t", help="Timing between sending packets.")] = 2,
                verbose: Annotated[bool, Option("--verbose", "-v", help="Verbose flag.")] = 'False'):
    """Not working (yet)."""
    # arp_spoofer.ScapyArpSpoofer(target, host, timing, verbose)



if __name__ == "__main__":
    app()
