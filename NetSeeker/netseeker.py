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
                    ports: Annotated[str, Option("--ports", "-p", help="Ports to scan (ex: 80 / 1-65535 / 20,22,443).")] = "1-1024",
                    timeout: Annotated[int, Option("--timeout", "-to", help="Timeout for waiting a reply (seconds).")] = 1,
                    udp: Annotated[bool, Option("--udp", "-sU", help="UDP scan.")] = False,
                    banner: Annotated[bool, Option("--banner", "-b", help="Enable banner grabbing for open ports.")] = False,
                    threads: Annotated[int, Option("--threads", "-t", help="Max. threads for the scanner process.")] = 100):
    """Scan for open ports on a address."""
    port_scanner.portScanner(target, ports, timeout, udp, threads, banner)


@app.command("netscan")
def app_network_scanner(target: Annotated[str, Argument(help="Target IP range.")] = "Connected Network",
                    retries: Annotated[int, Option("--retries", "-r", help="Max. retries per host.")] = 0,
                    timeout: Annotated[int, Option("--timeout", "-to", help="Timeout for waiting a reply (seconds).")] = 1,
                    udp: Annotated[bool, Option("--udp", "-sU", help="UDP scan.")] = False,
                    tcp_ack: Annotated[bool, Option("--tcp-ack", "-sTA", help="TCP ACK scan.")] = False,
                    local_tcp_syn: Annotated[bool, Option("--tcp-syn", "-sTS", help="Use TCP SYN scan on local networks.")] = False,
                    force_scan: Annotated[bool, Option("--force", "-f", help="Force all scans even if host was already found.")] = False,
                    stealth: Annotated[bool, Option("--stealth", "-sS", help="Slower scanners to avoid detection (disable ICMP scans).")] = False,
                    threads: Annotated[int, Option("--threads", "-t", help="Max. threads for the scanner process.")] = 100):
    """Discover hosts on a network (ARP + ICMP for local networks and ICMP + TCP SYN on common ports for remote)."""
    network_scanner.networkScanner(target, retries, timeout, threads, stealth, local_tcp_syn, force_scan)


@app.command("traceroute")
def app_traceroute(target: Annotated[str, Argument(help="Target IP/domain.")] = "",
                timeout: Annotated[int, Option("--timeout", "-t", help="Timeout for receiving packets (seconds).")] = 3,
                max_hops: Annotated[int, Option("--hops", "-h", help="Max. amount of hops.")] = 30,
                gen_map: Annotated[bool, Option("--map", "-m", help="Receive results in a dynamic map.")] = False,
                save_file: Annotated[bool, Option("--save", "-s", help="Save map in an HTML file.")] = False):
    """Trace the path of your packets with a map."""
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
