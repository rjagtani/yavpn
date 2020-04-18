import socket
import time
from scapy.all import *
import selectors


DST = "10.0.0.2"
PORT = 37654

sck = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
sck.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
# sck.bind(("0.0.0.0", PORT))

print("socket port: ", sck.getsockname()[1])

selector = selectors.DefaultSelector()
selector.register(sck, selectors.EVENT_READ, data="raw")


while True:
    events = selector.select(timeout=None)
    for key, mask in events:

        if key.data == "raw":
            sck = key.fileobj
            data, address = sck.recvfrom(1024)
            print("Receive TCP packet: ", repr(data))

            pck = IP(data)
            pck.show()

