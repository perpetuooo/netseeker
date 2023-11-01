import re
import typer
from rich import print
from typing_extensions import Annotated

from utils import port_scanner
from utils import network_scanner

app = typer.Typer(rich_markup_mode="rich")


@app.command("port-scanner")
def threaded_port_scanner(ip: Annotated[str, typer.Argument(help="Target IP/domain.")] = '127.0.0.1',
                           args: Annotated[str, typer.Argument(help="Arguments for the scanner")] = '',
                            ports: Annotated[str, typer.Option(help="Desired port range to scan.")] = '1-1024', 
                             threads: Annotated[int, typer.Option(help="Threads amount for the scanner process.")] = 20):
    """Scan the given ports of the target address."""
    ports_pattern = r'(\d+)[-,.;](\d+)'
    match = re.search(ports_pattern, ports)

    if match:
        start = int(match.group(1))
        end = int(match.group(2))
        port_scanner.NmapPortScanner(ip, start, end, threads, args)

    else:
        raise ValueError("[!] Invalid port range, use 'start-end' or 'start,end'.")


@app.command("wifi-scanner")
def host_discovery(ip: Annotated[str, typer.Argument(help="Target IP range (ex: 192.168.1.1/24).", show_default=False)] = '192.168.1.1/24',
                    verbose: Annotated[bool, typer.Option(help="Verbose flag.")] = False):
    """Discover all devices on the local network."""
    network_scanner.ScapyNetScanner(ip, verbose)



if __name__ == "__main__":
    app()
