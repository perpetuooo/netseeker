import sys
import time
import socket
from scapy.all import IP, UDP, ICMP, sr1
from alive_progress import alive_bar

from resources import services
from resources import console

"""
TODO:
- Add IPv6 support
- Create a map with the result info
"""

def tracerouteWithMap(target, timeout, max_hops, gen_map):
    target_name = target
    dest_reached = False
    info = services.DevicesInfo()
    results = {}
    
    # Get IP if the target is a domain.
    try:
        if target.endswith(".com"):
            target = socket.gethostbyname(target)
            target_name = f"{target_name} ({target})"

    except socket.gaierror:
        console.print(f"[bold red][!][/bold red] Invalid hostname: {target_name}.")
        sys.exit(1)

    process_time = time.perf_counter()

    with alive_bar(title=f"\033[1;33m[i]\033[0m Tracerouting to {target_name}", bar=None, spinner="classic", monitor=False, elapsed=False, stats=False) as bar:
        # Increase TTL for each hop.
        for ttl in range(1, max_hops + 1):
            if dest_reached:
                break

            hop_info = {
                'ip': None,
                'rtt': [],
                'hostname': None,
            }
            
            # Sends 3 packets per hop (as default in traceroutes).
            for attempt in range(3):
                start_time = time.perf_counter()

                # Create a UDP packet and sending it to the destination address.
                pkt = IP(dst=target, ttl=ttl) / UDP(dport=33434 + ttl)    # Send each packet to a unique port.
                reply = sr1(pkt, timeout=timeout, verbose=False)

                # Calculate RTT.
                rtt = (time.perf_counter() - start_time) * 1000  # Convert to ms.

                if reply:
                    hop_info['ip'] = reply.src  # Router IP.
                    hop_info['rtt'].append(round(rtt, 2))
                    hop_info['hostname'] = info.get_hostname(reply.src) if reply.src is not None else None

                    # Check if the packet reached the destination.
                    if reply.haslayer(ICMP):
                        if reply[ICMP].type == 3 and reply[ICMP].code == 3:   # Destination unreachable (port unreachable).
                            results[ttl] = hop_info
                            dest_reached = True
                
                time.sleep(0.1)
            
            if hop_info['ip'] is not None:
                results[ttl] = hop_info
            else:
                results[ttl] = {"ip": None, "rtt": ['*', '*', '*'], "hostname": "Request timed out"}
        
        bar.title("\033[1;32m[+]\033[0m Traceroute complete!")

    console.print(results)



if __name__ == '__main__':
    pass
    