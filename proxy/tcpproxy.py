from proxy.tlproxy import TransportLayerProxy
from packet import PacketManager

import time
import socket

from scapy.all import *

class TCPProxy(TransportLayerProxy):

    INVALID_SESSION = -1

    def __init__(self, hostIP, packetManager: PacketManager, toAppServer:socket.socket, toClient:socket.socket):
        self.hostIP = hostIP
        self.packetManager = packetManager
        self.toAppServer = toAppServer
        self.toClient = toClient
        self.sessions = []
        self.ports = list(range(1025, 65536))

    def getSessionByAddressInfo(self, src, sport, dst, dport):
        for session in self.sessions:
            if session['src'] == src and \
                session['sport'] == sport and \
                session['dst'] == dst and \
                session['dport'] == dport:
                return session

        return self.INVALID_SESSION

    def getSessionBySSport(self, sSport):
        for session in self.sessions:
            if session['sSport'] == sSport:
                return session

        return self.INVALID_SESSION

    def getNewPortNumber(self):
        return self.ports.pop(0)

    def newSession(self, address, src, sport, dst, dport):
        # add a new session
        new = {
            'clientAddress': address, 
            'src': src,
            'sport': sport,
            'sSport': self.getNewPortNumber(),
            'dst': dst,
            'dport': dport,
            'lastTime': time.time(), 
        }
        self.sessions.append(new)
        return new

    def close(self):
        # clean all sessions
        self.sessions.clear()

    def forwardToAppServer(self, data, clientAddress):
        src, dst = self.packetManager.getSrcIPandDstIP(data)
        sport, dport = self.packetManager.getSourceAndDstPort(data)

        session = self.getSessionByAddressInfo(src, sport, dst, dport)
        if session == self.INVALID_SESSION:
            # create a new session record
            session = self.newSession(clientAddress, src, sport, dst, dport)

        # refactor the source port and source IP
        pck, _, _ = self.packetManager.refactorSrcAndDstIP(data, self.hostIP, None)
        pck, _, _ = self.packetManager.refactorSportAndDport(pck, session['sSport'], None)

        IP(pck).show()

        self.toAppServer.sendto(pck, (dst, dport))

    def fowardToClient(self, data):
        # packet from App server
        src, dst = self.packetManager.getSrcIPandDstIP(data)
        sport, dport = self.packetManager.getSourceAndDstPort(data)

        session = self.getSessionBySSport(dport)
        # check the packet belongs to which exisiting session
        if session == self.INVALID_SESSION:
            return False
        elif session != self.getSessionByAddressInfo(session['src'], session['sport'], session['dst'], session['dport']):
            print("----------- not equal ------------")
            # packet does not belong to the VPN proxy
            return False
        else:
            # refactor packet
            pck, _, _ = self.packetManager.refactorSrcAndDstIP(data, None, session['src'])
            pck, _, _ = self.packetManager.refactorSportAndDport(pck, None, session['sport'])

            # TODO: TO BE DELETED
            print("session src ----- : ", session['src'])
            tmp = IP(pck)
            tmp.show()

            self.toClient.sendto(pck, session['clientAddress'])
        
        return True

