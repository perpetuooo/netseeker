import os
import re
import time
import typer
import socket
import folium
import tempfile
import webbrowser
from threading import Event
from ipaddress import ip_address
from scapy.all import IP, UDP, ICMP, sr1
from rich.progress import Progress, SpinnerColumn, TextColumn, TaskID

from resources import services
from resources import console

"""
TODO:
- Add IPv6 support
"""

def tracerouteWithMap(target, timeout, max_hops, gen_map, save_file):

    def tracert():
        dest_reached = False

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
                    if reply.src is not None and ip_address(reply.src).is_global:
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


    def create_map():
        progress.update(task_id, description="Generating map...")
        m = folium.Map(world_copy_jump=True)
        locations = []

        # Add your own location first (starting point).
        host = info.get_geolocation()
        if host and host['status'] == 'success':
            original_loc = [host['lat'], host['lon']]
            locations.append(original_loc)

            folium.Marker(
                location=original_loc,
                tooltip=folium.Tooltip(f"{host['query']} (you)"),
                popup=folium.Popup(f"{host['city']}, {host['country']}", max_width=250),
                icon=folium.Icon(color='green', icon='info-circle', prefix='fa')
            ).add_to(m)

        # Process each hop in order.
        for ttl in sorted(results.keys()):
            hop = results[ttl]

            if hop['ip'] and not hop['is_private'] and hop['location']['status'] == 'success':
                original_loc = [hop['location']['lat'], hop['location']['lon']]
                locations.append(original_loc)
                
                # Apply tiny offset if this location already exists.
                offset_multiplier = locations.count(original_loc)
                offset = offset_multiplier * 0.0001  # ~11 meters per duplicate.
                marker_loc = [original_loc[0] + offset, original_loc[1] + offset]

                popup_text = f"""
                <b>Hop #{ttl}</b><br>
                <b>IP</b>: {hop['ip']}<br>
                <b>Hostname</b>: {hop['hostname']}<br>
                <b>Location</b>: {hop['location']['city']}, {hop['location']['country']}<br>
                <b>RTT</b>: {", ".join(hop['rtt'])}<br>
                <b>ISP</b>: {hop['location']['isp']}<br>
                <b>Organization</b>: {hop['location']['org']}<br>
                """

                # Target hop marker.
                if hop['ip'] == target:
                    folium.Marker(
                        location=marker_loc,
                        tooltip=folium.Tooltip(f"Target: {hop['ip']}"),
                        popup=folium.Popup(popup_text, max_width=250),
                        icon=folium.Icon(color='red', icon='bullseye', prefix='fa')
                    ).add_to(m)
                    break

                # Regular hop marker.
                folium.Marker(
                    location=marker_loc,
                    tooltip=f"Hop {ttl}: {hop['ip']}",
                    popup=folium.Popup(popup_text, max_width=250),
                    icon=folium.Icon(color='blue', icon='server', prefix='fa')
                ).add_to(m)

        # Draw the connecting line using original coordinates.
        if len(locations) > 1:
            folium.PolyLine(
                locations=locations,
                color='purple',
                weight=3,
                opacity=0.7,
                dash_array='5,5'
            ).add_to(m)

        # Fit bounds to show all markers (using offset positions).
        if locations:
            m.fit_bounds([locations[0], locations[-1]])

        if save_file:
            filepath = os.path.join(info.get_desktop_path(), f"traceroute-{target}_{time.strftime('%d-%m-%Y_%H-%M-%S',time.localtime())}.html")
            m.save(filepath)
            webbrowser.open(f"file://{filepath}")
        else:
            with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
                m.save(f.name)
                webbrowser.open(f"file://{f.name}")


    target_name = target
    info = services.DevicesInfo()
    stop = Event()
    results = {}
    
    # Resolve IP if the target is a domain.
    if info.check_domain(target):
        target_name = f"{target} ({socket.gethostbyname(target)})"

    # If it is an IP, verify if its a valid address.
    elif not info.check_ip(target) and ip_address(target).is_global:
        raise typer.BadParameter(f"[bold red][!][/bold red] Invalid target: {target}") 

    process_time = time.perf_counter()

    with Progress(
        SpinnerColumn(spinner_name="line", style="white"),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task_id:TaskID = progress.add_task(f"Tracerouting to [yellow]{target_name}[yellow]", total=max_hops)

        try:
            tracert()

            if gen_map:
                create_map()
        
        except KeyboardInterrupt:
            stop.set()

    if stop.is_set():
        console.print(f"[bold red][!][/bold red] Traceroute interrupted! Time elapsed: {int(time.perf_counter() - process_time)}s")
    else:
        console.print(f"[bold green][+][/bold green] Scan completed! Time elapsed: {int(time.perf_counter() - process_time)}s")


    if not results:
        console.print("[bold red][!][/bold red] No results found.")
    else: 
        for ttl in sorted(results.keys()):
            hop = results[ttl]

            if hop['ip'] is None:
                console.print(f"[bold yellow]\\[i][/bold yellow] Hop {ttl} - [bold]REQUEST TIMED OUT![/bold]\n")
                continue

            location = hop.get("location") or {}
            location_lines = ""
            
            if location.get("status") == "success":
                location_lines = (
                    f"\t- Location: {location.get("city", "")}, {location.get("regionName", "")}, {location.get("country", "")}\n"
                    f"\t- Coordinates: {location.get("lat", "")}, {location.get("lon", "")}\n"
                    f"\t- ISP: {location.get("isp", "")}"
                )

            # Print hop info
            console.print(f"[bold green][+][/bold green] Hop {ttl}")
            console.print(f"\t- IP: {hop['ip']}")
            console.print(f"\t- RTT: {', '.join(hop['rtt'])}")
            console.print(f"\t- Hostname: {hop['hostname']}")
            console.print(f"\t- Private IP: {'Yes' if hop['is_private'] else 'No'}")

            if location_lines:
                console.print(location_lines)

            console.print()  # Extra newline between hops.



if __name__ == '__main__':
    pass
