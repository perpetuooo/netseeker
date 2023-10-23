import socket
import threading
from ipaddress import ip_address
from queue import Queue

def pScanner(target, start, end, threads):
    
    queue = Queue()
    open_ports = []
    thread_list = []
    port_list = range(start, end + 1)

    def scanner(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target, port))

            return True
        
        except Exception:
            return False
        
    def start_threads():
        for i in range(threads):
            thread = threading.Thread(target=worker)
            thread_list.append(thread)

        for thread in thread_list:
            thread.start()
        
        for thread in thread_list:
            thread.join()

    def worker():
        while not queue.empty():
            port = queue.get()

            if scanner(port):
                open_ports.append(port)
            
            else:
                pass

    if not ip_address(target):
        print("Invalid IP Address")
        exit(1)

    for port in port_list:
        queue.put(port)

    start_threads()


    if not open_ports:
        print(f"No open ports in {target}.")
    
    else:
        print(f"Open ports in {target}: {open_ports}")



if __name__ == '__main__':
    pass