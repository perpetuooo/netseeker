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
        console.print("ERROR: Invalid hostname.")
        sys.exit(1)

    process_time = time.perf_counter()

    with alive_bar(title=f"Tracerouting to {target_name}", bar=None, spinner="classic", monitor=False, elapsed=False, stats=False) as bar:
        try:
            # Increase TTL for each hop.
            for ttl in range(1, max_hops + 1):
                if dest_reached:
                    return

                hop_info = {
                    'ip': None,
                    'rtt': [],
                    'hostname': None,
                }
                
                # Sends 3 packets per hop (as default in traceroutes).
                for attempt in range(3):
                    start_time = time.perf_counter()

                    # Create a empty UDP packet and sending it to the destination address.
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
                
                results[ttl] = hop_info
            
        finally:
            bar.title("Traceroute complete!")
            console.print(results)



if __name__ == '__main__':
    pass
    