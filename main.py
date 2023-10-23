import typer
from rich import print
from utils.port_scanner import pScanner


app = typer.Typer()

@app.command("port-scanner")
def threaded_port_scanner(ip: str = typer.Argument(default="127.0.0.1", help="Target IP address"), 
                 start: int = typer.Argument(default=1, help="", min=1), 
                  end: int = typer.Argument(default=1024, help="", max=65535),
                   threads: int = typer.Option(default=100, help="")):
    """Scan the given ports of the given IP."""
    
    pScanner(ip, start, end, threads)



if __name__ == "__main__":
    app()
