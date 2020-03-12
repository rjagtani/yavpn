from scapy.all import *
import socket 

class PacketManager():
    def __init__(self):
        # get hostname
        self.host = socket.gethostbyname(socket.gethostname())
        pass


    def refactorSourceIP(self, data, src=self.host):
        pck = IP(data)
        return pck
        pass