from scapy.all import *
import socket 

class PacketManager():
    ICMP_TYPE = 1
    TCP_TYPE = 2
    UDP_TYPE = 3

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

    def refactorSrcAndDstIP(self, data, src=None, dst=None):
        if len(data) == 0:
            return None, None, None
        try:
            pck = IP(data)
        except Exception:
            print("Fail to src of the IP package: ", repr(data))
            return None, None, None
        
        oldSrc = pck['IP'].src
        oldDst = pck['IP'].dst
        if src is not None: pck['IP'].src = src
        if dst is not None: pck['IP'].dst = dst

        # recalculate checksum
        del pck['IP'].chksum

        return raw(pck), oldSrc, oldDst

    def refactorSportAndDport(self, data, sport=None, dport=None):
        if len(data) == 0:
            return None, None, None
        try:
            pck = IP(data)
        except Exception:
            print("Fail to src of the IP package: ", repr(data))
            return None, None, None
        
        if TCP in pck:
            oldSport = pck['TCP'].sport
            oldDport = pck['TCP'].dport
            if sport is not None: pck['TCP'].sport = sport
            if dport is not None: pck['TCP'].dport = dport

            del pck['TCP'].chksum
            del pck['IP'].chksum
        elif UDP in pck:
            oldSport = pck['UDP'].sport
            oldDport = pck['UDP'].dport
            if sport is not None: pck['UDP'].sport = sport
            if dport is not None: pck['UDP'].dport = dport

            del pck['UDP'].chksum
            del pck['IP'].chksum
        else:
            return None, None, None

        return raw(pck), oldSport, oldDport

    def getType(self, data):
        if len(data) == 0:
            return None
        
        try:
            pck = IP(data)
        except Exception:
            print("Fail to dest of the IP package: ", repr(data))
            return None

        if ICMP in pck:
            return self.ICMP_TYPE
        elif TCP in pck:
            return self.TCP_TYPE
        elif UDP in pck:
            return self.UDP_TYPE

        return None

    def getSourceAndDstPort(self, data):
        if len(data) == 0:
            return None, None

        try:
            pck = IP(data)
        except Exception:
            print("Fail to dest of the IP package: ", repr(data))
            return None, None

        if TCP in pck:
            return pck['TCP'].sport, pck['TCP'].dport 
        elif UDP in pck:
            return pck['UDP'].sport, pck['UDP'].dport

        return None, None
