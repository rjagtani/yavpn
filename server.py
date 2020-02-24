#!/usr/bin/env python3

import os
import sys
# import time
import struct
import socket
import selectors
from fcntl import ioctl
# from threading import Thread

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
        self.selector.register(self.udp, selectors.EVENT_READ | selectors.EVENT_WRITE, data="udp")
        
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
        tunfd, tunName = utils.createTunnel()
        tunAddress = config.IPRANGE.pop(0)
        utils.startTunnel(tunName, config.LOCAL_IP, tunAddress)

        self.sessions.append(
            {
                "tunName": tunName,
                "tunfd": tunfd,
                'address': address,
                'tunAddress': tunAddress
            }
        )
        self.selector.register(tunfd, selectors.EVENT_READ | selectors.EVENT_WRITE, data=tunName)
        reply = "%s;%s" % (tunAddress, config.LOCAL_IP)
        self.udp.sendto(reply.encode(), address)

    def runService(self):
        while True:
            events = self.selector.select(timeout=None)
            for key, mask in events:

                if key.data == "udp":
                    if mask & selectors.EVENT_READ:
                        data, address = self.udp.recvfrom(config.BUFFER_SIZE)
                        if DEBUG: 
                            print(utils.getCurrentTime() + 'from (%s:%s)' % (address, repr(data)))
                        
                        tunfd = self.getTunfdByAddress(address)
                        if tunfd == -1:
                            # create new session
                            try:
                                self.createSession(address)
                                if DEBUG:
                                    print('Client %s:%s connect successful' % (address))
                            except OSError:
                                continue
                        else:
                            try:
                                os.write(tunfd, data)
                            except OSError:
                                continue

                else:
                    if mask & selectors.EVENT_READ:
                        print("INTO SELECTER")
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