import os
import time
import socket
import struct
import platform

from resources import console

def packetInternetGrouper(target, timeout, count, ttl):
    # Sets the socket TTL based on the users plataform.
    def set_ttl(ttl):
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
            console.print(f"[bold red][!][/bold red] Failed to set TTL to {ttl}.")


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


    received = 0
    miss = 0
    responses = []
    
    # Create ICMP raw socket.
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.settimeout(timeout)
    set_ttl(ttl)

    for n in range(count):
        try:
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
                console.print(f"[bold green][+][/bold green] Ping! - {duration:.2f}ms")
                received += 1
        except socket.timeout:
            console.print("[bold red][+][/bold red] Request timed out.")        
            miss += 1

    sock.close()

    console.print(f"\nReceived: {received}")
    console.print(f"Missed: {miss}")



if __name__ == '__main__':
    pass
