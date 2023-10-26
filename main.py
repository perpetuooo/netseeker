import re
import typer
from rich import print
from typing_extensions import Annotated

from utils.scanner import port_scanner


app = typer.Typer(rich_markup_mode="rich")

@app.command("place-holder")
def hello_world():
    """Command placeholder."""
    print("Hello, World!")

@app.command("port-scanner")
def threaded_port_scanner(ip: Annotated[str, typer.Argument(help="Target IP")] = '127.0.0.1', 
                           threads: Annotated[int, typer.Option(help="Threads number for the scanner.")] = 20,
                            ports: Annotated[str, typer.Option(help="Desired port range to scan.")] = '1-1024'):
    """Scan the given ports of the given IP."""
    
    ip_pattern = r'(\d+)[-,](\d+)'
    match = re.search(ip_pattern, ports)

    if match:
        start = int(match.group(1))
        end = int(match.group(2))

        port_scanner(ip, start, end, threads)

    else:
        raise ValueError("Invalid port range, use 'start-end' or 'start,end'.")







if __name__ == "__main__":
    app()
