#!/usr/bin/env python3

import os
import sys
# import time
import struct
import socket
import selectors
from fcntl import ioctl

import config
import utils


def main():
    tunfd1, tunName1 = utils.createTunnel()
    utils.startTunnel(tunName1, "10.0.0.1", "10.0.0.4")
    tunfd, tunName = utils.createTunnel()
    utils.startTunnel(tunName, "10.0.0.4", "10.0.0.5")

    # s_tcp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s_icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s_icmp.bind(("10.0.0.1", 0))
    s_icmp.setblocking(False)

    selector = selectors.DefaultSelector()
    selector.register(s_icmp, selectors.EVENT_READ | selectors.EVENT_WRITE, data="icmp")
    selector.register(tunfd1, selectors.EVENT_READ | selectors.EVENT_WRITE, data=tunName1)
    selector.register(tunfd, selectors.EVENT_READ | selectors.EVENT_WRITE, data=tunName)

    while True:
        events = selector.select(timeout=None)
        for key, mask in events:
            if key.data == "icmp":
                # if mask & selectors.EVENT_READ:
                #     print("get icmp packet")
                #     recv_data = key.fileobj.recvfrom(4096)
                #     print(recv_data)
                pass
            else:
                if mask & selectors.EVENT_READ:
                    print("get tunnel packet")
                    data = os.read(tunfd, 1024)
                    print(data)
                    # os.write(tunfd, data)
                if mask & selectors.EVENT_WRITE:
                    pass
                    

main()




