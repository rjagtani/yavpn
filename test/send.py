import socket
import time
from scapy.all import *
import selectors


DST = "10.0.0.2"
PORT = 37654

sck = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
# sck.bind(("10.0.0.1", PORT))

selector = selectors.DefaultSelector()
selector.register(sck, selectors.EVENT_READ, data="raw")


while True:
    pck = IP(dst=DST) / TCP(sport=16666)
    # send(pck)

    # data = str(pck)[2:-1].encode() 
    data = raw(pck)
    print(data)
    sck.sendto(data, (DST, 0))

    # rev = sck.recvfrom(1024)
    # print("receive: ", rev)


    time.sleep(5)