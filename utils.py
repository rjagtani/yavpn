#!/usr/bin/env python3

import os
import time
import struct
from fcntl import ioctl

import config

# helping functions
def getCurrentTime():
    return time.strftime('[%Y/%m/%d %H:%M:%S]')

def createTunnel(tunName = 'tun%d', tunMode = config.IFF_TUN):
    tunfd = os.open("/dev/net/tun", os.O_RDWR)
    ifn = ioctl(tunfd, config.TUNSETIFF, struct.pack(b'16sH', tunName.encode(), tunMode))
    tunName = ifn[:16].decode().strip("\x00")
    return tunfd, tunName

def startTunnel(tunName, localIP, peerIP):
    print("peer ip %s local ip %s", peerIP, localIP)
    os.popen('ifconfig %s %s dstaddr %s mtu %s up' %
                (tunName, localIP, peerIP, config.MTU)).read()