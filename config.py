#!/usr/bin/env python3

from ipaddress import ip_network
from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA
from os import urandom

# Authentication
PASSWORD = {'client1' : b'5L@z\x9e\x03\x1d\xech!\x83\x89\x90\xd29\xaa\x85\xd0_]\x1e\x9a\x17\xc0y\x90\xe2\xf7\xc4\x84\xc6Q\xe9\xab\x02\n\xad\x0f\xeed"\xc7\xfb\\4\xc6&\xc2\x1a\x9b8\xf3\xed\x7f\x1a\x9d\x13\xbb\x93\x0f\xd9\xce\x04\xda'}
#PASSWORD = b'4fb88ca224e'

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
PREFERENCE = 4
FERNET_KEY = b'qaOMUbtW4M31PDU8p0LdwTdgE22coHm00RGOFK-FSQs='
AES_KEY = get_random_bytes(16)
#CHACHA20_KEY = get_random_bytes(32)

RC2_KEY = b'Sixteen byte key'
RC2_IV = get_random_bytes(8)

TDES_KEY = DES3.adjust_key_parity(get_random_bytes(24))
TDES_IV = get_random_bytes(8)

RC4_KEY = b'Very long and confidential key'

CHACHA20_KEY = get_random_bytes(32)
CHACHA_NONCE = get_random_bytes(8)

BLOWFISH_KEY = get_random_bytes(16)
BLOWFISH_IV = urandom(8)


TWOFISH_KEY = b'*secret*'

RSA_KEY = RSA.generate(2048)

# Debug Mode
DEBUG = False
VERBOSE = 1
