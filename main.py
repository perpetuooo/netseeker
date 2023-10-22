import typer
from rich import print
from rich.prompt import Prompt

app = typer.Typer()

@app.command("hello-world")
def test():
    print("[bold red]Hello, World![/bold red]")

@app.command()
def port_scanner(ip: str = "127.0.0.1", start: int = 1, end: int = 1024, threads: int = 100):
    """Testing docstrings for --help"""
    pass
    
@app.command()
def prompt_port_scanner():
    ip = Prompt.ask("(default = localhost): ", default='127.0.0.1')
    portsS = Prompt.ask("(default = 1): ", default=1)
    portsE = Prompt.ask("(default = 1024): ", default=1024)
    threads_number = int(Prompt.ask("(default = 100)", default=100))

    if threads_number > 500:
        threads_number = Prompt.Confirm("Are you sure?")



if __name__ == "__main__":
    app()
