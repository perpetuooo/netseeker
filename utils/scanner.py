import nmap
import threading
from rich import print
from queue import Queue

def port_scanner(target, start, end, threads):

    queue = Queue()
    thread_list = []
    open_ports = []
    port_range = range(start, end)
    nm = nmap.PortScanner()


    def scanner(port):
        try:
            result = nm.scan(target, str(port))
            port_status = (result['scan'][target]['tcp'][port]['state'])

            if port_status == "open":
                open_ports.append(port)

        except:
            pass


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
            scanner(port)

    print(f"[bold yellow] Scanning {target}...[bold yellow]")

    for port in port_range:
        queue.put(port)

    start_threads()

    if not open_ports:
        print(f"[bold red]No open ports.[/bold red]")

    else:
        print(f"[bold green]{open_ports}[/bold green]")



if __name__ == '__main__':
    pass