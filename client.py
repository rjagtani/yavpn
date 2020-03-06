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

DEBUG = config.DEBUG

class Client():
    def __init__(self, routeManager):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.settimeout(5)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.udp, selectors.EVENT_READ, data="udp")
        self.to = SERVER_ADDRESS
        self.routeManager = routeManager

    def connect(self):
        self.udp.sendto(config.PASSWORD, self.to)
        try:
            #obtain tun IP address
            data, address = self.udp.recvfrom(config.BUFFER_SIZE)
            localIP, peerIP = data.decode().split(';')

            # create and register tunnel
            tunfd, tunName = utils.createTunnel()
            self.selector.register(tunfd, selectors.EVENT_READ, data = tunName)
            print('Local IP: %s, Peer IP: %s' % (localIP, peerIP))
            utils.startTunnel(tunName, localIP, peerIP)

            # modify routing table
            self.routeManager.changeDefaultGW(peerIP, tunName)
            self.routeManager.addHostRoute(self.to[0], dev="enp0s3")

            return tunfd

        except socket.timeout:
            return False

    def keepAlive(self):
        while True:
            time.sleep(config.KEEPALIVE)
            self.udp.sendto(b'\x00', self.to)

    def reconnect(self):
        self.selector.unregister(self.tunfd)
        os.close(self.tunfd)
        print('Reconnecting...')
        self.tunfd = self.connect()
    
    def runService(self):
        print('Start connect to server...')
        self.tunfd = self.connect()
        if not self.tunfd:
            print('Connect failed!')
            sys.exit(0)

        print('Connect to server successful')
        # start keep alive thread
        keepAliveThread = Thread(target=self.keepAlive, daemon=True)
        keepAliveThread.start()
        
        while True:
            try:
                events = self.selector.select(timeout=None)
            except KeyboardInterrupt:
                # close connection
                self.udp.sendto(b'e', self.to)
                raise KeyboardInterrupt

            for key, mask in events:
                if key.data == "udp":
                    data, address = self.udp.recvfrom(config.BUFFER_SIZE)
                    try:
                        os.write(self.tunfd, data)
                        if DEBUG:
                            print(utils.getCurrentTime() + 'from (%s:%s)' % (address, repr(data)))
                    except OSError:
                        if data == b'r':
                            self.reconnect()
                        continue
                
                else: # tunnel events
                    try:
                        data = os.read(self.tunfd, config.BUFFER_SIZE)
                        self.udp.sendto(data, self.to)
                        if DEBUG:
                            print(utils.getCurrentTime() + 'to (%s:%s)' % (self.to, repr(data)))
                    except OSError:
                        continue



if __name__ == '__main__':
    try:
        SERVER_ADDRESS = (sys.argv[1], int(sys.argv[2]))
        RM = RouteManager()
        Client(RM).runService()
    except IndexError:
        print('Usage: %s [remote_ip] [remote_port]' % sys.argv[0])
    except KeyboardInterrupt:
        if DEBUG:
            print('Restoring Default Gateway')
        RM.restoreDefaultGW()
        print('Closing vpn client ...')
