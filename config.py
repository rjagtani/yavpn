#!/usr/bin/env python3

from ipaddress import ip_network

# Authentication
PASSWORD = b'4fb88ca224e'

# IP Config
BIND_ADDRESS = '0.0.0.0',2003
NETWORK = '10.0.0.0/24'
BUFFER_SIZE = 65535
MTU = 1400

IPRANGE = list(map(str,ip_network(NETWORK)))[1:]
LOCAL_IP = IPRANGE.pop(0)

# Constraints of creating TUN
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
ETHERNET_FRAME_BYTES = b"\x00\x00\x08\x00"

# VPN Session Keep Alive
COLLECT_CYCLE = 5
KEEPALIVE = 10
EXPIRE_TIME = 60

# TCP Session Keep Alive
TCP_COLLECT_CYCLE = 60
TCP_EXPIRE_TIME = 300

# Encryption Config
FERNET_KEY = b'qaOMUbtW4M31PDU8p0LdwTdgE22coHm00RGOFK-FSQs='

# Debug Mode
DEBUG = False
VERBOSE = 1