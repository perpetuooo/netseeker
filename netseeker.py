import sys
import cmd2
from rich import print

from modules import traceroute
from modules import port_scanner
from modules import network_scanner
from modules import arp_spoofer

"""app = Typer(rich_markup_mode="rich")


@app.command("traceroute")
def tracert(target: Annotated[str, Argument(help="Target IP/domain.", show_default=False)],
            timeout: Annotated[int, Option(help="Timeout for receiving packets.")] = 5):
    ""Trace the path of IP packets with its location.""
    traceroute.TracerouteWithMap(target, timeout)


@app.command("port-scanner")
def threaded_port_scanner(ip: Annotated[str, Argument(help="Target IP/domain (loopback for default).", show_default=False)] = '127.0.0.1',
                          ports: Annotated[str, Option(help="Desired port range to scan (ex: 1-1024).", show_default=False)] = '1-1024', 
                          threads: Annotated[int, Option(help="Threads amount for the scanner process.")] = 20,
                          args: Annotated[str, Option(help="Other arguments for the scanner", show_default=False)] = ''):
    ""Scan the given ports of the target address.""
    port_scanner.NmapPortScanner(ip, ports, threads, args)


@app.command("host-discovery")
def host_discovery(ip: Annotated[str, Argument(help="Target IP range (ex: 192.168.1.1/24).", show_default=False)],
                   args: Annotated[str, Option(help="Other arguments for the scanner.")] = "-sn",
                   timing: Annotated[int, Option(help="[b]0[/b] (slower scans but harder to be detected) to [b]5[/b] (faster scans but very agressive).")] = 3):
    ""Discover all devices on the local network.""
    network_scanner.NmapNetScanner(ip, timing, args)


@app.command("arp-spoofer")
def arp_poisoning(target: Annotated[str, Argument(help="Target IP.", show_default=False)],
                  host: Annotated[str, Argument(help="Target host (default gateway for default).", show_default=False)] = "",
                  timing: Annotated[int, Option(help="Timing between sending packets.", show_default=False)] = 2,
                  verbose: Annotated[bool, Option(help="Verbose flag.", show_default=False)] = 'False'):
    ""Not working yet.""
    arp_spoofer.ScapyArpSpoofer(target, host, timing, verbose)"""

class Main(cmd2.Cmd):
    prompt = "test > "
    arguments = []


    #def __init__(self):
        #super.__init__()


    parser = cmd2.Cmd2ArgumentParser()
    parser.add_argument('-c', '--caps', action='store_true', help='all caps when you spell the man name')
    parser.add_argument('string', nargs='+', help='string to echo.')

    @cmd2.with_argparser(parser)
    def do_echo(self, args):
        """Echoes the given string."""
        words = []
        for word in args.string:
            if args.caps:
                word = word.upper()
            
            words.append(word)
        
        print(' '.join(words))
        

if __name__ == "__main__":
    app = Main()
    app.cmdloop()

