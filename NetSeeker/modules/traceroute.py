import os
import sys
import time
import typer
import socket
import folium
import tempfile
import webbrowser
from scapy.all import IP, UDP, ICMP, sr1
from alive_progress import alive_bar

from resources import services
from resources import console

"""
TODO:
- Add IPv6 support
- Create a map with the result info
"""

def tracerouteWithMap(target, timeout, max_hops, gen_map, save_file):

    def create_map():
        bar.title("\033[1;33m[i]\033[0m Generating map")
        m = folium.Map(world_copy_jump=True)
        locations = []

        # Add your own location first (starting point).
        host = info.get_geolocation()
        if host and host['status'] == 'success':
            locations.append([host['lat'], host['lon']])

            folium.Marker(
                location=[host['lat'], host['lon']],
                tooltip=f"{host['query']} (you)",
                popup=f"{host['city']}, {host['country']}",
                icon=folium.Icon(color='green', icon='info-circle', prefix='fa')
            ).add_to(m)

        # Process each hop in order.
        for ttl in sorted(results.keys()):
            hop = results[ttl]

            if hop['ip'] and not hop['is_private'] and hop['location']['status'] == 'success':
                hop_location = [hop['location']['lat'], hop['location']['lon']]
                locations.append(hop_location)

                console.print(f"hop {ttl}")

                popup_text = f"""
                <b>Hop #</b>: {ttl}<br>
                <b>IP</b>: {hop['ip']}<br>
                <b>Hostname</b>: {hop['hostname']}<br>
                <b>Location</b>: {hop['location']['city']}, {hop['location']['country']}<br>
                <b>RTT</b>: {", ".join(hop['rtt'])}<br>
                <b>ISP</b>: {hop['location']['isp']}<br>
                <b>Organization</b>: {hop['location']['org']}<br>
                """

                # Check if is the target.
                if hop['ip'] == target:
                    folium.Marker(
                        location=hop_location,
                        tooltip=f"Target: {hop['ip']}",
                        popup=folium.Popup(popup_text, max_width=200),
                        icon=folium.Icon(color='red', icon='bullseye', prefix='fa')
                    ).add_to(m)
                    break

                # Regular hop marker.
                folium.Marker(
                    location=hop_location,
                    tooltip=f"Hop {ttl}: {hop['ip']}",
                    popup=folium.Popup(popup_text, max_width=200),
                    icon=folium.Icon(color='blue', icon='server', prefix='fa')
                ).add_to(m)

        # Draw the connecting line.
        if len(locations) > 1:
            folium.PolyLine(
                locations=locations,
                color='purple',
                weight=3,
                opacity=0.7,
                dash_array='5,5'
            ).add_to(m)

        # Adjust map to fit all markers.
        # if locations:
        #     m.fit_bounds([locations[0], locations[-1]])

        console.print(locations)

        if save_file:
            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
            filepath = os.path.join(desktop_path, f"traceroute-{target_name}_{time.strftime("%d-%m-%Y_%H-%M-%S",time.localtime())}.html")

            m.save(filepath)
            webbrowser.open(f"file://{filepath}")
        
        else:
            with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
                m.save(f.name)
                webbrowser.open(f"file://{f.name}")


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
        raise typer.BadParameter(f"[bold red][!][/bold red] Invalid hostname: {target_name}.")

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
                'is_private': None,
                'location': None,
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
                    hop_info['rtt'].append(f"{round(rtt)}ms")

                    # Results depends if there is an IP and if it is public.
                    if reply.src is not None and info.check_ipv4(reply.src) is True:
                        hop_info['hostname'] = info.get_hostname(reply.src)
                        hop_info['is_private'] = False
                        hop_info['location'] = info.get_geolocation(reply.src)
                    
                    else:
                        hop_info['hostname'] = None
                        hop_info['is_private'] = True
                        hop_info['location'] = None

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

        if gen_map:
            create_map()

        bar.title(f"\033[1;32m[+]\033[0m Traceroute complete! Time elapsed: {int(time.perf_counter() - process_time)}s \n")

    console.print(results)



if __name__ == '__main__':
    pass
    