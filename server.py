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
import packet

DEBUG = config.DEBUG

class Server:
    def __init__(self):
        self.sessions = []
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(config.BIND_ADDRESS)

        # selector to listen all 'coming in' events
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.udp, selectors.EVENT_READ, data="udp")

        self.packetManger = packet.PacketManager()
        print('Server listen on %s:%s' % (config.BIND_ADDRESS))

    def getTunfdByAddress(self, address):
        for session in self.sessions:
            if session["address"] == address:
                return session["tunfd"]
        return -1

    def getAddressByTunfd(self, tunfd):
        for session in self.sessions:
            if session["tunfd"] == tunfd:
                return session["address"]
        return -1

    def getSocketByTunfd(self, tunfd):
        for session in self.sessions:
            if session["tunfd"] == tunfd:
                return session["socket"]
        return -1

    def createSession(self, address):
        try:
            tunfd, tunName = utils.createTunnel()
            tunAddress = config.IPRANGE.pop(0)
            utils.startTunnel(tunName, config.LOCAL_IP, tunAddress)
            rawSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        except OSError:
            print("Error when create new session with address: ", address)
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
                    if DEBUG:
                        print('Session: %s:%s expired!' % session['address'])
            time.sleep(config.COLLECT_CYCLE)

    def authenticate(self, tunfd, data, address):
        if data == b'\x00':
            if tunfd == -1:
                # reconnect
                self.udp.sendto(b'r', address)
            else:
                self.updateLastTime(tunfd)
            return False
        elif data == b'e':
            # close session
            if self.deleteSessionByTunfd(tunfd):
                if DEBUG:
                    print("Client %s:%s disconnect" % address)
            return False
        if data == config.PASSWORD:
            return True

        else:
            if DEBUG:
                print("Client %s:%s connection failed!" % address)

    def sendToAppServer(self, data, tunfd):
        rawSocket = self.getSocketByTunfd(tunfd)
        if rawSocket == -1:
            return False

        # refactoring packet
        packet = self.packetManger.refactorSourceIP(data)
        if packet is None:
            return False
        else:
            # send packet through the raw socket

            return True

    def runService(self):
        # start a thread for garbage collecting
        collectorThread = Thread(target=self.garbageCollector, daemon=True)
        collectorThread.start()

        while True:
            events = self.selector.select(timeout=None)
            for key, mask in events:

                if key.data == "udp":
                    data, address = self.udp.recvfrom(config.BUFFER_SIZE)
                    if DEBUG: 
                        print(utils.getCurrentTime() + 'from (%s:%s)' % (address, repr(data)))
                    
                    try:
                        tunfd = self.getTunfdByAddress(address)
                        try:
                            os.write(tunfd, data)
                        except OSError:
                            # data is not recognized by the tunnel or 
                            # tunnel does not exist
                            if self.authenticate(tunfd, data, address):  
                                # authentication succeeds
                                if tunfd == -1:
                                    # create a new session      
                                    self.createSession(address)
                                    if DEBUG:
                                        print('Client %s:%s connect successful' % (address))

                            else:
                                if data == b'\x00' or data == b'e' or tunfd == -1:
                                    continue
                                # resend to the App Server
                                self.sendToAppServer(data, tunfd)
                                if DEBUG:
                                    print(utils.getCurrentTime() + 'resends packet to App Server: %s' % (repr(data)))

                    except OSError:
                        if DEBUG:
                            print("Error when try to write to tunfd: ", tunfd)
                        continue
                
                elif key.data == "raw":
                    # receive packets from the application server


                    pass

                else:
                    try: 
                        tunfd = key.fileobj
                        address = self.getAddressByTunfd(tunfd)
                        data = os.read(tunfd, config.BUFFER_SIZE)
                        self.udp.sendto(data, address)
                        if DEBUG:
                            print(utils.getCurrentTime() + 'to (%s:%s)' % (address, repr(data)))
                    except Exception:
                        continue


if __name__ == '__main__':
    try:
        Server().runService()
    except KeyboardInterrupt:
        print('Closing vpn server ...')
