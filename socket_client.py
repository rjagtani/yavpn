#!/usr/bin/env python3

import socket
import time

HOST = '127.0.0.1'
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(b'hello world')
    data = s.recv(1024)
    print('Received', data)


print("client close")

