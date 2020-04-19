from cryptography.fernet import Fernet
import config

class SecurityManager:
    def __init__(self, key):
        self.key = key
        self.fernet = Fernet(self.key)

    def encrypt_data(self, data):
        return self.fernet.encrypt(data)

    def decrypt_data(self, data):
        return self.fernet.decrypt(data)


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
