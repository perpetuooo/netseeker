import sys
import socket
from nmap import PortScanner
from rich import print
from rich.table import Table
from datetime import datetime

#from services import get_mac

def ScapyNetScanner(target, verb):

    nm = PortScanner()
    target = '192.168.5.132/24'
    host_list = []

    try:
        result = nm.scan(target, arguments='-sn -T4 --max-retries 2', timeout=3000)
        #print(result['scan'])
        #print('\n')

        for hosts in result['scan'].values():
            try:
                #print(hosts)
                host_list.append(hosts)

                ipv4 = (hosts['addresses']['ipv4'])
                print(ipv4)
                
                if len(hosts['addresses']) == 1:
                    pass
                
                else:
                    macs = (hosts['addresses']['mac'])
                    print(macs)

                if len(hosts['vendor']) == 1:
                    hostname = (hosts['vendor'][macs])
                    print(hostname)
                
                else:
                    try:
                        hostname = socket.gethostbyaddr(ipv4)[0]
                        print(hostname)
                    
                    except socket.error:
                        hostname = "host not found"
                        print(hostname)


                print('\n')

            except Exception as e:
                print(f"{str(e)}")

    except Exception as e:
        print(f"{str(e)}")

    print(f"Count: {len(host_list)}")



if __name__ == '__main__':
    pass