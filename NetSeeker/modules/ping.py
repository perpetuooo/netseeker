import os
import sys
import time
import socket
import struct
from rich.progress import Progress, SpinnerColumn, TextColumn, TaskID

from resources import console

def packetInternetGrouper(target, ipv6, timeout, count, ttl):
    # Sets the socket TTL based on the users plataform.
    def set_ttl(sock, ttl):
        success = False

        # Attempt with SOL_IP
        try:
            sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            current_ttl = sock.getsockopt(socket.SOL_IP, socket.IP_TTL)
            if current_ttl == ttl:
                success = True
        except OSError:
            pass

        # Fallback: try with IPPROTO_IP (used on Windows).
        if not success:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                current_ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                if current_ttl == ttl:
                    success = True
            except OSError:
                pass
        
        if not success:
            console.print(f"[bold red][!][/bold red] Failed to set TTL to {ttl}, using default values.")
            ttl = 0     # To stop trying to set a new TTL value every iteration.


    # Perform internet checksum.
    def checksum(data):
        sum = 0
        count = 0
        max_count = (len(data) // 2) * 2

        while count < max_count:
            val = data[count + 1] * 256 + data[count]
            sum = sum + val
            sum = sum & 0xffffffff
            count += 2

        if max_count < len(data):
            sum += data[len(data) - 1]
            sum = sum & 0xffffffff

        sum = (sum >> 16) + (sum & 0xffff)
        sum += (sum >> 16)

        answer = ~sum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        return answer

    
    def ping():
        nonlocal received, miss

        for n in range(count):
            try:
                # Create ICMP raw socket.
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                sock.settimeout(timeout)
                set_ttl(sock, ttl)
                packet_id = os.getpid() & 0xFFFF
                header = struct.pack("bbHHh", 8, 0, 0, packet_id, n)
                data = struct.pack("d", time.time())

                checksum_val = checksum(header + data)
                header = struct.pack("bbHHh", 8, 0, socket.htons(checksum_val), packet_id, n)
                packet = header + data

                sock.sendto(packet, (target, 1))
                start = time.time()
                reply, addr = sock.recvfrom(1024)
                duration = (time.time() - start) * 1000
                responses.append(duration)

                if reply:
                    progress.console.print(f"[bold green][+][/bold green] Response received from {addr[0]} - {duration:.2f}ms")
                    received += 1
            except socket.timeout:
                progress.console.print("[bold yellow][~][/bold yellow] Request timed out.")        
                miss += 1
            finally:
                sock.close()
 

    # Target validation.
    try:
        if target[:1].isdigit():
            socket.gethostbyaddr(target)
        else:
            socket.gethostbyname(target)
    except socket.gaierror:
        console.print(f"[bold red][!][/bold red] Invalid target specified: {target}")
        sys.exit(1)

    received = 0
    miss = 0
    stop = False
    responses = []

    process_time = time.perf_counter()

    with Progress(
        SpinnerColumn(spinner_name="line", style="white"),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console
    ) as progress:
        progress.add_task(f"Performing ping...")

        try:
            ping()
        except KeyboardInterrupt:
            stop = True

    # Longest, shortest and average response time.
    avg = 0; rmin = float("inf"); rmax = float("-inf")
    for x in responses:
        avg += x
        if x < rmin: rmin = x
        if x > rmax: rmax = x
    
    if stop:
        console.print(f"[bold yellow][~][/bold yellow] Ping interrupted! Time elapsed: {(time.perf_counter() - process_time):.2f}s")
    else:
        console.print(f"[bold green][+][/bold green] Ping completed! Time elapsed: {(time.perf_counter() - process_time):.2f}s")

    console.print("\n[bold]--- Ping Statistics ---[/bold]")
    console.print(f"  [bold]└─ Sent:[/] {count}")
    console.print(f"  [bold]└─ Received:[/] {received}")
    console.print(f"  [bold]└─ Missed:[/] {miss}")
    console.print(f"  [bold]└─ Packet Loss:[/] {((miss / count) * 100):.2f}%")

    

    if received:
        avg = avg / received
        console.print("\n[bold]--- Response Statistics (ms) ---[/bold]")
        console.print(f"  [bold]└─ Min:[/] {rmin:.2f}ms")
        console.print(f"  [bold]└─ Max:[/] {rmax:.2f}ms")
        console.print(f"  [bold]└─ Average:[/] {avg:.2f}ms")
    else:
        console.print(f"\n[bold red][!][/bold red] No replies received.")



if __name__ == '__main__':
    pass
