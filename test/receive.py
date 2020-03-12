import socket
import time
from scapy.all import *
import selectors


DST = "google.com"
PORT = 37655

sck = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
sck.bind(("142.58.77.253", PORT))
sck.setblocking(False)

selector = selectors.DefaultSelector()
selector.register(sck, selectors.EVENT_READ, data="raw")


while True:
    events = selector.select(timeout=None)
    for key, mask in events:
        if key == "raw":
            data = key.fileobj.recv(1024)
            print("receive data: ", repr(data))