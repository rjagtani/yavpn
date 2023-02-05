from cryptography.fernet import Fernet
from Crypto.Cipher import ARC4
from struct import pack
import config

class SecurityManager:
    def __init__(self):
        if (config.PREFERENCE == 1):
            self.encryption_key = config.FERNET_KEY
            self.fernet = Fernet(self.encryption_key)

        elif (config.PREFERENCE == 2):
            self.encryption_key = config.RC4_KEY
            self.rc4 = ARC4.new(self.encryption_key)

    def encrypt_data(self, data):

        if (config.PREFERENCE == 1):
            print('Encrypting using FERNET: ')
            return self.fernet.encrypt(data)

        elif (config.PREFERENCE == 2):
            print('Encrypting using RC4: ')
            return self.rc4.encrypt(data)

    def decrypt_data(self, data):
        if (config.PREFERENCE == 1):
            return self.fernet.decrypt(data)

        elif (config.PREFERENCE == 2):
            return self.rc4.decrypt(data)

class UdpProxy:
    def __init__(self, conn, sm):
        self.conn = conn
        self.sm = sm
    def sendto(self, data, address):
        encrypted_data = self.sm.encrypt_data(data)
        self.conn.sendto(encrypted_data, address)
    def recvfrom(self, buffer_size):
        encrypted_data, address = self.conn.recvfrom(buffer_size)
        data = self.sm.decrypt_data(encrypted_data)
        return data, address
