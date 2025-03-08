from typer import Typer, Argument, Option
from typing_extensions import Annotated
from rich.console import Console

from modules import port_scanner
# from modules import traceroute
# from modules import network_scanner
# from modules import arp_spoofer

app = Typer(rich_markup_mode="rich")


@app.command("info")
def get_info():
    """Info about the project."""
    pass


@app.command("traceroute")
def tracert(target: Annotated[str, Argument(help="Target IP/domain.")] = "",
            timeout: Annotated[int, Option("--timeout", "-t", help="Timeout for receiving packets (seconds).")] = 5,
            result_map: Annotated[bool, Option("--map", "-m", help="Create a map with the info provided.")] = False):
    """Trace the path of IP packets."""
    # traceroute.TracerouteWithMap(target, timeout, result_map)


@app.command("portscan")
def threaded_port_scanner(ip: Annotated[str, Argument(help="Target IP/domain.")] = "127.0.0.1",
                          ports: Annotated[str, Argument(help="Ports to scan (ex: 80 / 1-1024 / 20,22,443).")] = "1-1024",
                          timeout: Annotated[int, Option(help="Timeout for waiting a reply (seconds).")] = 1,
                          threads: Annotated[int, Option("--threads", "-t", help="Amount of threads for the scanner process.")] = 100,
                          banner: Annotated[bool, Option("--banner", "-b", help="Enable banner grabbing for open ports.")] = False):
    """Scan the given ports of the target address."""
    port_scanner.portScanner(ip, ports, timeout, banner, threads)


@app.command("netscan")
def host_discovery(ip: Annotated[str, Argument(help="Target IP range (ex: 192.168.1.1/24).")] = "",
                   timing: Annotated[int, Option("--timing", "-t", help="[b]0[/b] (slower scans but harder to be detected) to [b]5[/b] (faster but agressive scans).")] = 3):
    """Discover all devices on the local network."""
    # network_scanner.NmapNetScanner(ip, timing)


@app.command("arpspoofer")
def arp_poisoning(target: Annotated[str, Argument(help="Target IP.")] = "",
                  host: Annotated[str, Argument(help="Target host.")] = "",
                  timing: Annotated[int, Option("--timing", "-t", help="Timing between sending packets.")] = 2,
                  verbose: Annotated[bool, Option("--verbose", "-v", help="Verbose flag.")] = 'False'):
    """Not working (yet)."""
    # arp_spoofer.ScapyArpSpoofer(target, host, timing, verbose)



if __name__ == "__main__":
    app()
