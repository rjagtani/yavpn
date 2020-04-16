from scapy.all import *
import socket 

class PacketManager():
    def __init__(self):
        pass


    def getSrcIPandDstIP(self, data):
        if len(data) == 0:
            return None, None

        try:
            pck = IP(data)
        except Exception:
            return None, None
        
        return pck['IP'].src, pck['IP'].dst

    def refactorSourceIP(self, data, src):
        if len(data) == 0:
            return None, None, None
        try:
            pck = IP(data)
        except Exception:
            print("Fail to src of the IP package: ", repr(data))
            return None
        
        oldSrc = pck['IP'].src
        oldDst = pck['IP'].dst
        pck['IP'].src = src

        # recalculate checksum
        del pck['IP'].chksum

        return raw(pck), oldSrc, oldDst

    def refactorDstIP(self, data, dst):
        if len(data) == 0:
            return None, None, None

        try:
            pck = IP(data)
        except Exception:
            print("Fail to dest of the IP package: ", repr(data))
            return None

        oldSrc = pck['IP'].src
        oldDst = pck['IP'].dst
        pck['IP'].dst = dst
        
        # recalculate checksum
        del pck['IP'].chksum
        
        return raw(pck), oldSrc, oldDst

