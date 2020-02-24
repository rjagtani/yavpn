import os
import sys
import time
import struct
import socket
import selectors
from fcntl import ioctl
# from threading import Thread

import config
import utils

DEBUG = config.DEBUG

class Client():
    def __init__(self):
        super().__init__()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.settimeout(5)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.udp, selectors.EVENT_READ | selectors.EVENT_WRITE, data="udp")

        self.to = SERVER_ADDRESS

    def connect(self):
        self.udp.sendto(b'e', self.to)
        try:
            data, address = self.udp.recvfrom(config.BUFFER_SIZE)
            localIP, peerIP = data.decode().split(';')
            tunfd, tunName = utils.createTunnel()
            self.selector.register(tunfd, selectors.EVENT_READ | selectors.EVENT_WRITE, data = tunName)
            print('Local IP: %s, Peer IP: %s' % (localIP, peerIP))
            utils.startTunnel(tunName, localIP, peerIP)
            return tunfd

        except socket.timeout:
            return False

    
    def runService(self):
        print('Start connect to server...')
        self.tunfd = self.connect()
        if not self.tunfd:
            print('Connect failed!')
            sys.exit(0)

        print('Connect to server successful')
        
        while True:
            events = self.selector.select(timeout=None)
            for key, mask in events:
                if key.data == "udp":
                    if mask & selectors.EVENT_READ:
                        data, address = self.udp.recvfrom(config.BUFFER_SIZE)
                        try:
                            os.write(self.tunfd, data)
                            if DEBUG:
                                print(utils.getCurrentTime() + 'from (%s:%s)' % (address, repr(data)))
                        except OSError:
                            self.selector.unregister(self.tunfd)
                            os.close(self.tunfd)
                            print('Reconnecting...')
                            self.tunfd = self.connect()

                        continue

                    if mask & selectors.EVENT_WRITE:
                        pass
                
                else:
                    # tunnel events
                    if mask & selectors.EVENT_READ:
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
        Client().runService()
    except IndexError:
        print('Usage: %s [remote_ip] [remote_port]' % sys.argv[0])
    except KeyboardInterrupt:
        print('Closing vpn client ...')