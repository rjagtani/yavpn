#!/usr/bin/env python3

from ipaddress import ip_network

# Authentication
PASSWORD = b'4fb88ca224e'

# IP Config
BIND_ADDRESS = '0.0.0.0',2003
NETWORK = '10.0.0.0/24'
BUFFER_SIZE = 4096
MTU = 1400

IPRANGE = list(map(str,ip_network(NETWORK)))[1:]
LOCAL_IP = IPRANGE.pop(0)

# Constraints of creating TUN
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002

# Keep Alive
COLLECT_CYCLE = 5
KEEPALIVE = 10
EXPIRE_TIME = 60

# Encryption Config
FERNET_KEY = b'qaOMUbtW4M31PDU8p0LdwTdgE22coHm00RGOFK-FSQs='
# Debug Mode
DEBUG = True