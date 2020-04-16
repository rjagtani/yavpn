#!/usr/bin/env python3

import os
import sys
import time
import struct
import socket
import selectors
from fcntl import ioctl
from threading import Thread

import config
import utils
from route import RouteManager
from packet import PacketManager

DEBUG = config.DEBUG

# Contants
INVALID_ADDRESS = -1
INVALID_TUN = -1
INVALID_SOCKET = -1

class Server:
    def __init__(self):
        self.sessions = []
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(config.BIND_ADDRESS)

        # selector to listen all 'coming in' events
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.udp, selectors.EVENT_READ, data="udp")

        self.packetManager = PacketManager()
        self.routeManager = RouteManager()
        self.hostIP = self.routeManager.gethostIP()
        print('Server listen on %s:%s' % (config.BIND_ADDRESS))

    def getTunfdByAddress(self, address):
        for session in self.sessions:
            if session["address"] == address:
                return session["tunfd"]
        return INVALID_TUN

    def getAddressByTunfd(self, tunfd):
        for session in self.sessions:
            if session["tunfd"] == tunfd:
                return session["address"]
        return INVALID_ADDRESS

    def getSocketByTunfd(self, tunfd):
        for session in self.sessions:
            if session["tunfd"] == tunfd:
                return session["socket"]
        return INVALID_SOCKET

    def getAddressBySocket(self, socket):
        for session in self.sessions:
            if session["socket"] == socket:
                return session["address"]
        return INVALID_ADDRESS
    
    def getTunAddressByAddress(self, address):
        for session in self.sessions:
            if session["address"] == address:
                return session["tunAddress"]
        return INVALID_ADDRESS

    def createSession(self, address):
        try:
            tunfd, tunName = utils.createTunnel()
            tunAddress = config.IPRANGE.pop(0)
            utils.startTunnel(tunName, config.LOCAL_IP, tunAddress)
            rawSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            rawSocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            #rawSocket.setblocking(False)
        except OSError as e:
            print("Error when create new session with address: ", address)
            print("Error message " + str(e))
            return False

        self.sessions.append(
            {
                "tunName": tunName,
                "tunfd": tunfd,
                'address': address,
                'tunAddress': tunAddress,
                'socket': rawSocket, 
                'lastTime': time.time()
            }
        )
        # register tunnel and raw socket
        self.selector.register(tunfd, selectors.EVENT_READ, data=tunName)
        self.selector.register(rawSocket, selectors.EVENT_READ, data="raw")

        reply = "%s;%s" % (tunAddress, config.LOCAL_IP)
        self.udp.sendto(reply.encode(), address)
        return True

    def deleteSessionByTunfd(self, tunfd):
        for session in self.sessions:
            if session['tunfd'] == tunfd:
                del_session = session
        
        try:
            os.close(tunfd)
            del_session['socket'].close()
            
        except OSError:
            return False

        self.sessions.remove(del_session)
        config.IPRANGE.append(del_session['tunAddress'])
        
        try:
            self.selector.unregister(tunfd)
            self.selector.unregister(del_session['socket'])
        except Exception:
            print("Fail to unregister file: ", tunfd, del_session['socket'])
            return False
        
        return True

    def updateLastTime(self, tunfd):
        for session in self.sessions:
            if session["tunfd"] == tunfd:
                session["lastTime"] = time.time()

    def garbageCollector(self):
        while True:
            for session in self.sessions:
                if (time.time() - session["lastTime"]) > config.EXPIRE_TIME:
                    # expire if no response for 1 minute
                    self.deleteSessionByTunfd(session['tunfd'])
                    if DEBUG: print('Session: %s:%s expired!' % session['address'])
            time.sleep(config.COLLECT_CYCLE)

    def authenticate(self, tunfd, data, address):
        if data == b'\x00':
            if tunfd == INVALID_TUN:
                # reconnect
                self.udp.sendto(b'r', address)
            else:
                self.updateLastTime(tunfd)
            return False
        elif data == b'e':
            # close session
            if self.deleteSessionByTunfd(tunfd):
                if DEBUG: print("Client %s:%s disconnect" % address)
            return False
        if data == config.PASSWORD:
            return True

        else:
            if DEBUG:  print("Client %s:%s connection failed!" % address)

    def forwardToAppServer(self, data, tunfd):
        rawSocket = self.getSocketByTunfd(tunfd)
        if rawSocket == INVALID_SOCKET:
            return False

        # refactoring packet
        packet, _, dst = self.packetManager.refactorSourceIP(data, self.hostIP)
        if packet is None:
            return False
        else:
            # send packet through the raw socket
            rawSocket.sendto(packet, (dst, 0))
            return True

    def forwardToClient(self, data, address):
        if address == INVALID_ADDRESS:
            return False

        # refactoring packet
        tunAddress = self.getTunAddressByAddress(address)
        packet, _, _ = self.packetManager.refactorDstIP(data, tunAddress)
        if packet is None:
            return False
        else:
            # send packet through the udp socket
            self.udp.sendto(packet, address)
            return True


    def runService(self):
        # start a thread for garbage collecting
        collectorThread = Thread(target=self.garbageCollector, daemon=True)
        collectorThread.start()

        while True:
            events = self.selector.select(timeout=None)
            for key, mask in events:

                if key.data == "udp":
                    # receive data from udp socket
                    data, address = self.udp.recvfrom(config.BUFFER_SIZE)
                    if DEBUG: print(utils.getCurrentTime() + 'from (%s:%s)' % (address, repr(data)))
                    
                    # resends the packet to App Server or Tunnel
                    srcIP, dstIP = self.packetManager.getSrcIPandDstIP(data) 
                    print("srcIP, dstIP: ", srcIP, dstIP)

                    tunfd = self.getTunfdByAddress(address)
                    if dstIP == config.LOCAL_IP:
                        try:
                            # handle by TUN
                            if DEBUG: print("Write to Tunnel")

                            # add four bytes ethernet frame
                            tdata = config.ETHERNET_FRAME_BYTES + data
                            os.write(tunfd, tdata)
                        except OSError:
                            if DEBUG: print("Error when try to write to tunfd: ", tunfd)
                            continue
                                
                    elif dstIP is None:
                        # control message, handled by the server
                        print("Control Message")
                        if self.authenticate(tunfd, data, address) and tunfd == -1:  
                            # authentication succeeds, create a new session      
                            self.createSession(address)
                            if DEBUG: print('Client %s:%s connect successful' % (address))

                    else:
                        # forward to the App Server
                        print("forward to App Server")
                        if self.forwardToAppServer(data, tunfd):
                            if DEBUG: print(utils.getCurrentTime() + 'forward packet to App Server: %s' % (repr(data)))
                
                elif key.data == "raw":
                    # receive packets from the application server
                    rawSocket = key.fileobj
                    data, address = rawSocket.recvfrom(config.BUFFER_SIZE)

                    # resend data to the client
                    clientAddr = self.getAddressBySocket(rawSocket)
                    if self.forwardToClient(data, clientAddr):
                        if DEBUG: print(utils.getCurrentTime() + 'forward packet to Client: %s' % (repr(data)))
                        pass

                else:
                    try: 
                        tunfd = key.fileobj
                        address = self.getAddressByTunfd(tunfd)
                        data = os.read(tunfd, config.BUFFER_SIZE)
                        # truncate four bytes ethernet frame
                        data = data[4:]

                        self.udp.sendto(data, address)
                        if DEBUG: print(utils.getCurrentTime() + 'to (%s:%s)' % (address, repr(data)))
                    except Exception:
                        continue


if __name__ == '__main__':
    try:
        Server().runService()
    except KeyboardInterrupt:
        print('Closing vpn server ...')
