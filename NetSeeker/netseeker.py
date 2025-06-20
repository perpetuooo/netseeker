from modules import port_scanner
from modules import network_scanner
from modules import traceroute
from modules import sd_enum
# from modules import arp_spoofer

from resources import NetSeekerArgumentParser


# def app_ping(args):

def app_port_scanner(args):
    port_scanner.portScanner(
        target=args.target,
        ports=args.ports,
        timeout=args.timeout,
        udp=args.udp,
        threads=args.threads,
        bg=args.banner,
        verbose=args.verbose,
    )

def app_network_scanner(args):
    network_scanner.networkScanner(
        target=args.target,
        retries=args.retries,
        timeout=args.timeout,
        threads=args.threads,
        stealth=args.stealth,
        local_tcp_syn=args.local_tcp_syn,
        force_scan=args.force,
        verbose=args.verbose,
    )

def app_traceroute(args):
    traceroute.tracerouteWithMap(
        target=args.target,
        timeout=args.timeout,
        max_hops=args.max_hops,
        gen_map=args.generate_map,
        save_file=args.save_file,
    )

def app_subdomain_enum(args):
    sd_enum.subdomainEnumeration(
        target=args.target,
        wordlist_path=args.wordlist,
        timeout=args.timeout,
        ipv6=args.ipv6,
        mx=args.mx,
        output=args.output,
        http_status=args.http_probe,
        threads=args.threads,
    )

def main():
    parser = NetSeekerArgumentParser(description="NetSeeker", prog="netseeker")
    subparsers = parser.add_subparsers(dest="command")

    # Ping
    # subparsers.add_parser("ping", help="A simple redesign of ICMP ping").set_defaults(func=app_ping)

    # Port Scanner
    pscan = subparsers.add_parser("portscan", help="Scans target for open TCP/UDP ports.")
    pscan.add_argument("target", nargs='?', help="Target IP/domain.", default="127.0.0.1")
    pscan.add_argument("--ports", "-p", help="Ports to scan (e.g., '20', '1-1024', '22,80,443', 'all').", default="1-1024")
    pscan.add_argument("--timeout", "-t", type=int, help="Timeout for waiting a reply (seconds).", default=1)
    pscan.add_argument("--udp", "-sU", action="store_true", help="Enable UDP scan.")
    pscan.add_argument("--banner", "-b", action="store_true", help="Enable banner grabbing.")
    pscan.add_argument("--verbose", "-v", action="store_true", help="Verbose output.")
    pscan.add_argument("--threads", "-T", type=int, help="Max. ammount of threads for the scanner process.", default=80)
    pscan.set_defaults(func=app_port_scanner)

    # Network Scanner
    nscan = subparsers.add_parser("netscan", help="Discover hosts on a network.")
    nscan.add_argument("target", nargs='?', help="Target IP range.", default="Connected Network")
    nscan.add_argument("--retries", "-r", type=int, help="Max. retries per host.", default=0)
    nscan.add_argument("--timeout", "-t", type=int, help="Timeout for waiting a reply (seconds).", default=1)
    nscan.add_argument("--udp", "-sU", action="store_true", help="Enable UDP scan.")
    nscan.add_argument("--tcp-ack", "-sTA", action="store_true", help="Enable TCP ACK scan.")
    nscan.add_argument("--local-tcp-syn", "-sTS", action="store_true", help="Enable TCP SYN scan for local networks.")
    nscan.add_argument("--force", "-f", action="store_true", help="Force all scans even if host was already found.")
    nscan.add_argument("--stealth", "-sS", action="store_true", help="Stealth scan mode.")
    nscan.add_argument("--verbose", "-v", action="store_true", help="Verbose output.")
    nscan.add_argument("--threads", "-T", type=int, help="Max. ammount of threads for the scanner process.", default=80)
    nscan.set_defaults(func=app_network_scanner)

    # Traceroute
    trace = subparsers.add_parser("traceroute", help="Trace the network path to a target.")
    trace.add_argument("target", help="Target IP/domain.")
    trace.add_argument("--timeout", "-t", type=int, help="Timeout per hop (seconds).", default=3)
    trace.add_argument("--max-hops", "-m", type=int, help="Max. number of hops.", default=30)
    trace.add_argument("--generate-map", "-g", action="store_true", help="Generate a interactive map.")
    trace.add_argument("--save-file", "-s", action="store_true", help="Save map to HTML.")
    trace.set_defaults(func=app_traceroute)

    # Subdomain Enumeration
    sdenum = subparsers.add_parser("sdenum", help="Subdomain enumeration with recursive brute force.")
    sdenum.add_argument("target", help="Target domain")
    sdenum.add_argument("--wordlist", "-w", help="Path to a new wordlist file.")
    sdenum.add_argument("--output", "-o", action="store_true", help="Save results in a text file.")
    sdenum.add_argument("--http-probe", "-hp", action="store_true", help="Check subdomains for a HTTP/HTTPS status response.")
    sdenum.add_argument("--ipv6", "-6", action="store_true", help="Scan for IPv6 records (AAAA).")
    sdenum.add_argument("--mx", "-m", action="store_true", help="Scan for mail exchange records (MX).")
    sdenum.add_argument("--timeout", "-t", type=int, help="Timeout for the DNS resolver (seconds).", default=1)
    sdenum.add_argument("--threads", "-T", type=int, help="Max. ammount of threads for the scanner process.", default=80)
    sdenum.set_defaults(func=app_subdomain_enum)


    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()



if __name__ == "__main__":
    main()
