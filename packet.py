from scapy.all import *
import socket 

class PacketManager():
    def __init__(self):
        # get hostname
        self.host = socket.gethostbyname(socket.gethostname())
        # TODO which line should be in effect
        self.host = "192.168.1.105"

    def getSrcIPandDstIP(self, data):
        if len(data) == 0:
            return None, None

        try:
            pck = IP(data)
        except Exception:
            return None, None
        
        return pck['IP'].src, pck['IP'].dst

    def refactorSourceIP(self, data, src=None):
        if len(data) == 0:
            return None, None
        try:
            pck = IP(data)
        except Exception:
            print("Fail to src of the IP package: ", repr(data))
            return None
        
        if src is None:
            src = self.host
        pck['IP'].src = src
        dst = pck['IP'].dst

        # recalculate checksum
        del pck['IP'].chksum

        return raw(pck), dst

    def refactorDstIP(self, data, dst):
        if len(data) == 0:
            return None

        try:
            pck = IP(data)
        except Exception:
            print("Fail to dest of the IP package: ", repr(data))
            return None

        pck['IP'].dst = dst
        
        # recalculate checksum
        del pck['IP'].chksum
        
        return raw(pck)

