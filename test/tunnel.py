import os
import time
import struct
from fcntl import ioctl
from scapy.all import *
import socket
import selectors

import config

def createTunnel(tunName = 'tun%d', tunMode = config.IFF_TUN):
    tunfd = os.open("/dev/net/tun", os.O_RDWR)
    ifn = ioctl(tunfd, config.TUNSETIFF, struct.pack(b'16sH', tunName.encode(), tunMode))
    tunName = ifn[:16].decode().strip("\x00")
    return tunfd, tunName

def startTunnel(tunName, localIP, peerIP):
    os.popen('ifconfig %s %s dstaddr %s mtu %s up' %
                (tunName, localIP, peerIP, config.MTU)).read()


tunfd, tunName = createTunnel()
tunAddress = "10.0.0.2"
local_ip = "10.0.0.1"
startTunnel(tunName, local_ip, tunAddress)

selector = selectors.DefaultSelector()
selector.register(tunfd, selectors.EVENT_READ, data=tunName)

print("start listening...")
while True:
    events = selector.select(timeout=None)
    for key, mask in events:
        if key.data == tunName:
            print("get event")

            data = os.read(key.fileobj, config.BUFFER_SIZE)
            
            packet = IP(data)
            packet['IP'].src = "10.0.0.1"
            packet.show()
            raw = packet["Raw"]

            # print("IP Raw: ",  ICMP(raw))
            
            # print("IP packet: ", packet)
