import socket
import struct
import time
import os

from resources import console

def packetInternetGrouper(target, timeout, count, ttl):
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

    #
    def send_packet():
        for n in range(count):
            try:
                # Create ICMP raw socket.
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                sock.settimeout(timeout)
                sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

                packet_id = os.getpid() & 0xFFFF
                header = struct.pack("bbHHh", 8, 0, 0, packet_id, n)
                data = struct.pack("d", time.time())

                checksum_val = checksum(header + data)
                header = struct.pack("bbHHh", 8, 0, socket.htons(checksum_val), packet_id, n)
                packet = header + data

                sock.sendto(packet, (target, 1))
                start = time.time()
                reply, addr = sock.recvfrom(1024)
                duration = time.time() - start

                if reply:
                    console.print(f"[bold green][+][/bold green] Ping! - {duration*1000:.2f}ms")
                    received += 1

            except socket.timeout:
                console.print("[bold red][+][/bold red] Request timed out.")        
                miss += 1
            finally:
                sock.close()


    received = 0
    miss = 0
    send_packet()
    console.print(f"Received: {received}")
    console.print(f"Missed: {miss}")


if __name__ == '__main__':
    pass
