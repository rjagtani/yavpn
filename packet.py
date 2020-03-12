from scapy.all import *
import socket 

class PacketManager():
    def __init__(self):
        # get hostname
        self.host = socket.gethostbyname(socket.gethostname())
        pass


    def refactorSourceIP(self, data, src=self.host):
        try:
            pck = IP(data)
        except Exception:
            print("Fail to src of the IP package: ", repr(data))
            return None
        
        pck['IP'].src = src
        dst = pck['IP'].dst
        return raw(pck), dst

    def refactorDestIP(self, data, dst):
        try:
            pck = IP(data)
        except Exception:
            print("Fail to dest of the IP package: ", repr(data))
            return None
        
        pck['IP'].dst = dst
        return raw(pck)

