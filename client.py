import os
import sys
import time
import struct
import socket
import selectors
from fcntl import ioctl
from threading import Thread

import bcrypt
import config
import utils
from route import RouteManager
from packet import PacketManager
from security import SecurityManager, UdpProxy

DEBUG = config.DEBUG
VERBOSE = config.VERBOSE

class Client():
    def __init__(self):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.settimeout(5)
        self.securityManager = SecurityManager(config.FERNET_KEY)
        self.udp_proxy = UdpProxy(self.udp, self.securityManager)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.udp, selectors.EVENT_READ, data="udp")
        self.serverAddress = SERVER_ADDRESS
        self.routeManager = RouteManager()
        self.packetManager = PacketManager()

    def connect(self):
        client_password = input("Enter Password:")
        client_password.encode('utf-8')
        hashedPassword = bcrypt.hashpw(client_password, bcrypt.gensalt(10))
        #encrypt client password
        #auth_message = sock.recv(65444)
        #auth_message = auth_message.decode('utf-8')
        self.udp_proxy.sendto(hashedPassword, self.serverAddress)

        try:
            #obtain tun IP address
            data, address = self.udp_proxy.recvfrom(config.BUFFER_SIZE)
            localIP, peerIP = data.decode().split(';')
            self.localTunAddress = localIP
            self.serverTunAddress = peerIP

            # create and register tunnel
            tunfd, tunName = utils.createTunnel()
            self.selector.register(tunfd, selectors.EVENT_READ, data = tunName)
            print('Local IP: %s, Peer IP: %s' % (localIP, peerIP))
            utils.startTunnel(tunName, localIP, peerIP)
            time.sleep(3)

            # modify routing table
            NIC = self.routeManager.getNIC()
            defaultGW = self.routeManager.getDefaultGW()
            self.routeManager.changeDefaultGW(peerIP, tunName)
            self.routeManager.addHostRoute(self.serverAddress[0], defaultGW, NIC)

            return tunfd

        except socket.timeout:
            return False

    def keepAlive(self):
        while True:
            time.sleep(config.KEEPALIVE)
            self.udp_proxy.sendto(b'\x00', self.serverAddress)


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
                self.udp_proxy.sendto(b'e', self.serverAddress)

                raise KeyboardInterrupt

            for key, mask in events:
                if key.data == "udp":
                    data, address = self.udp_proxy.recvfrom(config.BUFFER_SIZE)
                    srcIP, dstIP = self.packetManager.getSrcIPandDstIP(data)
                    if VERBOSE > 0: print("srcIP, dstIP: ", srcIP, dstIP)

                    try:
                        # add four bytes ethernet frame
                        tdata = config.ETHERNET_FRAME_BYTES + data
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
                        # truncate four bytes ethernet frame
                        data = data[4:]
                        
                        self.udp_proxy.sendto(data, self.serverAddress)

                        if DEBUG:
                            print(utils.getCurrentTime() + 'to (%s:%s)' % (self.serverAddress, repr(data)))
                    except OSError:
                        continue

    def restoreConf(self):
        NIC = self.routeManager.getNIC()
        defaultGW = self.routeManager.getDefaultGW()
        self.routeManager.changeDefaultGW(defaultGW, NIC)
        self.routeManager.deleteHostRoute(self.serverAddress[0], defaultGW, NIC)


if __name__ == '__main__':
    try:
        SERVER_ADDRESS = (sys.argv[1], int(sys.argv[2]))
        client = Client()
        client.runService()
    except IndexError:
        print('Usage: %s [VPN_server_ip] [VPN_server_port]' % sys.argv[0])
    except KeyboardInterrupt:
        if DEBUG:
            print('Restoring Default Configuration... ')
        client.restoreConf()
        print('Closing vpn client ...')
    except Exception as e:
        if DEBUG:
            print('Restoring Default Configuration... ')
        client.restoreConf()
        print(e)
        raise e
