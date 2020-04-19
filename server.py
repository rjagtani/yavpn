#!/usr/bin/env python3

import os
import sys
import time
import struct
import socket
import selectors
from fcntl import ioctl
from security import SecurityManager, UdpProxy
from threading import Thread

import config
import utils
from route import RouteManager
from packet import PacketManager
from proxy.tcpproxy import TCPProxy


DEBUG = config.DEBUG

# Contants
INVALID_ADDRESS = -1
INVALID_TUN = -1

class Server:
    def __init__(self):
        self.packetManager = PacketManager()
        self.routeManager = RouteManager()
        self.hostIP = self.routeManager.gethostIP()

        self.sessions = []
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(config.BIND_ADDRESS)

        self.tcpRaw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.tcpRaw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.tcpProxy = TCPProxy(self.hostIP, self.packetManager, self.tcpRaw, self.udp)

        self.icmpRaw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.icmpRaw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # encryption
        self.securityManager = SecurityManager(config.FERNET_KEY)
        self.udp_proxy = UdpProxy(self.udp, self.securityManager)

        # selector to listen all 'coming in' events
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.udp, selectors.EVENT_READ, data="udp")
        self.selector.register(self.tcpRaw, selectors.EVENT_READ, data="tcpRaw")
        self.selector.register(self.icmpRaw, selectors.EVENT_READ, data="icmpRaw")

        print('Server listen on %s:%s' % (config.BIND_ADDRESS))

    # def initializeTcp(self):
    #     ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    #     ssl_context.load_cert_chain('yavpn.pem', 'yavpn.key')
    #     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #     sock.bind(config.TCP_BIND_ADDRESS)
    #     sock.listen(2)
    #     secure_sock = ssl_context.wrap_socket(sock, server_side=True)
    #     conn, address = secure_sock.accept()
    #     return conn
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
                'lastTime': time.time()
            }
        )
        # register tunnel and raw socket
        self.selector.register(tunfd, selectors.EVENT_READ, data=tunName)

        reply = "%s;%s" % (tunAddress, config.LOCAL_IP)
        self.udp_proxy.sendto(reply.encode(), address)
        return True

    def deleteSessionByTunfd(self, tunfd):
        for session in self.sessions:
            if session['tunfd'] == tunfd:
                del_session = session
        
        try:
            os.close(tunfd)
        except OSError:
            return False

        self.sessions.remove(del_session)
        config.IPRANGE.append(del_session['tunAddress'])
        
        try:
            self.selector.unregister(tunfd)
        except Exception:
            print("Fail to unregister TUN: ", tunfd)
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
                self.udp_proxy.sendto(b'r', address)
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

    def forwardToAppServer(self, data, address):
        # check packet type and send through socket
        packetType = self.packetManager.getType(data)

        if packetType is None:
            if DEBUG:  print("Fail to forward packet: ", repr(data))

        elif packetType == self.packetManager.ICMP_TYPE:
            # refactoring packet
            pck, _, dst = self.packetManager.refactorSrcAndDstIP(data, self.hostIP, None)
            if pck is None: return False
            self.icmpRaw.sendto(pck, (dst, 0))

        elif packetType == self.packetManager.TCP_TYPE:
            self.tcpProxy.forwardToAppServer(data, address)

        elif packetType == self.packetManager.UDP_TYPE:
            pass

        return True

    def forwardToAllClients(self, data):
        for session in self.sessions:
            tunAddress = session['tunAddress']
            address = session['address']

            # refactoring packet
            pck, _, _ = self.packetManager.refactorSrcAndDstIP(data, None, tunAddress)

            if pck is None:
                return False
            else:
                # send packet through the udp socket
                self.udp_proxy.sendto(pck, address)
                
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
                    data, address = self.udp_proxy.recvfrom(config.BUFFER_SIZE)

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
                        if self.forwardToAppServer(data, address):
                            if DEBUG: print(utils.getCurrentTime() + 'forward packet to App Server: %s' % (repr(data)))
                
                elif key.data == "icmpRaw":
                    # receive packets from the application server
                    socket = key.fileobj
                    data, address = socket.recvfrom(config.BUFFER_SIZE)

                    # resend data to all clients
                    if self.forwardToAllClients(data):
                        if DEBUG: print(utils.getCurrentTime() + 'forward packet to Client: %s' % (repr(data)))

                elif key.data == "tcpRaw":
                    # receive packets from the application server
                    socket = key.fileobj
                    data, address = socket.recvfrom(config.BUFFER_SIZE)

                    # forward data to the client
                    if self.tcpProxy.fowardToClient(data):
                        if DEBUG: print(utils.getCurrentTime() + 'forward packet to Client: %s' % (repr(data)))
                        pass

                else:
                    try: 
                        tunfd = key.fileobj
                        address = self.getAddressByTunfd(tunfd)
                        data = os.read(tunfd, config.BUFFER_SIZE)
                        # truncate four bytes ethernet frame
                        data = data[4:]
                        self.udp_proxy.sendto(data, address)

                        if DEBUG: print(utils.getCurrentTime() + 'to (%s:%s)' % (address, repr(data)))
                    except Exception:
                        continue


if __name__ == '__main__':
    try:
        Server().runService()
    except KeyboardInterrupt:
        print('Closing vpn server ...')
