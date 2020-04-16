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
from security import SecurityManager, UdpProxy
DEBUG = config.DEBUG

class Client():
    def __init__(self):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.settimeout(5)
        self.securityManager = SecurityManager(config.FERNET_KEY)
        self.udp_proxy = UdpProxy(self.udp, self.securityManager)
        self.selector = selectors.DefaultSelector()
        # TODO what does data="udp" mean
        self.selector.register(self.udp, selectors.EVENT_READ, data="udp")
        self.to = SERVER_ADDRESS
        self.routeManager = RouteManager()
        self.packetManager = PacketManager()

    def connect(self):
        self.udp_proxy.sendto(config.PASSWORD, self.to)
        try:
            #obtain tun IP address
            data, address = self.udp_proxy.recvfrom(config.BUFFER_SIZE)
            localIP, peerIP = data.decode().split(';')
            self.localIP = localIP
            self.peerIP = peerIP

            # create and register tunnel
            tunfd, tunName = utils.createTunnel()
            self.selector.register(tunfd, selectors.EVENT_READ, data = tunName)
            print('Local IP: %s, Peer IP: %s' % (localIP, peerIP))
            utils.startTunnel(tunName, localIP, peerIP)

            # modify routing table
            # TODO how does peerIP work in this scenario
            self.routeManager.changeDefaultGW(peerIP, tunName)
            self.routeManager.addHostRoute(self.to[0])

            return tunfd

        except socket.timeout:
            return False

    def keepAlive(self):
        while True:
            time.sleep(config.KEEPALIVE)
            self.udp_proxy.sendto(b'\x00', self.to)

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
                self.udp_proxy.sendto(b'e', self.to)
                raise KeyboardInterrupt

            for key, mask in events:
                if key.data == "udp":
                    data, address = self.udp_proxy.recvfrom(config.BUFFER_SIZE)
                    srcIP, dstIP = self.packetManager.getSrcIPandDstIP(data)
                    print("srcIP, dstIP: ", srcIP, dstIP)
                    if dstIP is not None:
                        data = self.packetManager.refactorDstIP(data, self.localIP)
                        data = b"\x00\x00\x00\x00" + data

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

                        self.udp_proxy.sendto(data, self.to)
                        if DEBUG:
                            print(utils.getCurrentTime() + 'to (%s:%s)' % (self.to, repr(data)))
                    except OSError:
                        continue

    def restoreConf(self):
        self.routeManager.restoreDefaultGW()


if __name__ == '__main__':
    try:
        SERVER_ADDRESS = (sys.argv[1], int(sys.argv[2]))
        client = Client()
        client.runService()
    except IndexError:
        print('Usage: %s [remote_ip] [remote_port]' % sys.argv[0])
    except KeyboardInterrupt:
        if DEBUG:
            print('Restoring Default Configuration... ')
        client.restoreConf()
        print('Closing vpn client ...')
