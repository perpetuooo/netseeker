import scapy.all as scapy

def ScapyNetScanner(ip):
    result = []

    def scanner(target):
        try:
            arp_request = scapy.ARP(pdst=target)
            #arp_request.show()
            ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            #ether_frame.show()
            request = ether_frame/arp_request
            #request.show()

            response_list = scapy.srp(request, timeout=3, retry=1, verbose=True)[0]

            for sent, received in response_list:
                #print(received.show())
                result.append({'IP': received.psrc, 'MAC': received.hwsrc})

        except Exception as e:
            print(str(e))


    scanner(ip)
    
    for device in result:
        print(device['IP'] + "\t" + device['MAC'])

if __name__ == '__main__':
    pass