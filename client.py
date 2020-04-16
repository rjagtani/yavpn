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

class Client():
    def __init__(self):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.settimeout(5)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.udp, selectors.EVENT_READ, data="udp")
        self.to = SERVER_ADDRESS
        self.routeManager = RouteManager()
        self.packetManager = PacketManager()

    def connect(self):
        self.udp.sendto(config.PASSWORD, self.to)
        try:
            #obtain tun IP address
            data, address = self.udp.recvfrom(config.BUFFER_SIZE)
            localIP, peerIP = data.decode().split(';')
            self.localIP = localIP
            self.peerIP = peerIP
            print(localIP, peerIP)

            # create and register tunnel
            tunfd, tunName = utils.createTunnel()
            self.selector.register(tunfd, selectors.EVENT_READ, data = tunName)
            print('Local IP: %s, Peer IP: %s' % (localIP, peerIP))
            utils.startTunnel(tunName, localIP, peerIP)

            # modify routing table
            NIC = self.routeManager.getNIC()
            defaultGW = self.routeManager.getDefaultGW()
            self.routeManager.changeDefaultGW(peerIP, tunName)
            self.routeManager.addHostRoute(self.to[0], defaultGW, NIC)

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
                    # truncate f4our dummy bytes
                    # pdata = data[4:]
                    srcIP, dstIP = self.packetManager.getSrcIPandDstIP(data)
                    print("srcIP, dstIP: ", srcIP, dstIP)

                    try:
                        tdata = b"\x00\x00\x08\x00" + data
                        os.write(self.tunfd, tdata)
                        if DEBUG:
                            print(utils.getCurrentTime() + 'from (%s:%s)' % (address, repr(data)))
                    except OSError:
                        if data == b'r':
                            self.reconnect()
                        continue
                
                else: # tunnel events
                    try:
                        data = os.read(self.tunfd, config.BUFFER_SIZE)
                        # truncate four ether frame bytes
                        data = data[4:]
                        
                        self.udp.sendto(data, self.to)
                        if DEBUG:
                            print(utils.getCurrentTime() + 'to (%s:%s)' % (self.to, repr(data)))
                    except OSError:
                        continue

    def restoreConf(self):
        NIC = self.routeManager.getNIC()
        defaultGW = self.routeManager.getDefaultGW()
        self.routeManager.changeDefaultGW(defaultGW, NIC)
        self.routeManager.deleteHostRoute(self.to[0], defaultGW, NIC)


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
