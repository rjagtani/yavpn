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

DEBUG = config.DEBUG

class Server:
    def __init__(self):
        super().__init__()
        self.sessions = []
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(config.BIND_ADDRESS)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.udp, selectors.EVENT_READ, data="udp")
        
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

    def createSession(self, address):
        try:
            tunfd, tunName = utils.createTunnel()
            tunAddress = config.IPRANGE.pop(0)
            utils.startTunnel(tunName, config.LOCAL_IP, tunAddress)
        except OSError:
            print("Error when create new session with address: ", address)
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
        self.selector.register(tunfd, selectors.EVENT_READ, data=tunName)
        reply = "%s;%s" % (tunAddress, config.LOCAL_IP)
        self.udp.sendto(reply.encode(), address)
        return True

    def deleteSessionByTunfd(self, tunfd):
        try:
            os.close(tunfd)
        except OSError:
            return False
        
        for session in self.sessions:
            if session['tunfd'] == tunfd:
                self.sessions.remove(session)
                config.IPRANGE.append(session['tunAddress'])
        
        try:
            self.selector.unregister(tunfd)
        except Exception:
            print("Try to unregister not registered tunnel: ", tunfd)
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
                            if not self.authenticate(tunfd, data, address):
                                continue    
                            self.createSession(address)
                            if DEBUG:
                                print('Client %s:%s connect successful' % (address))
                    except OSError:
                        if DEBUG:
                            print("Error when try to write to tunfd: ", tunfd)
                        continue

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
