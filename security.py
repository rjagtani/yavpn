from cryptography.fernet import Fernet
from Crypto.Cipher import ARC2
from Crypto.Cipher import ARC4
from Crypto.Cipher import DES3
from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20
from Crypto.Cipher import Blowfish
import blowfish
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from twofish import Twofish
from struct import pack
from base64 import b64encode
import config


class SecurityManager:
    def __init__(self):
        if (config.PREFERENCE == 1):
            self.encryption_key = config.FERNET_KEY
            self.fernet = Fernet(self.encryption_key)

        elif (config.PREFERENCE == 2):
            self.encryption_key = config.RC2_KEY
            self.rc2enc = ARC2.new(self.encryption_key, ARC2.MODE_CFB, config.RC2_IV)
            self.rc2dec = ARC2.new(self.encryption_key, ARC2.MODE_CFB, config.RC2_IV)

        elif (config.PREFERENCE == 3):  # 3DES Not working
            self.encryption_key = config.TDES_KEY
            self.tdesenc = DES3.new(self.encryption_key, DES3.MODE_CFB, config.TDES_IV)

        elif (config.PREFERENCE == 4):
            self.encryption_key = config.RC4_KEY
            self.rc4 = ARC4.new(self.encryption_key)

        elif (config.PREFERENCE == 5):  # ChaCha20 Not working
            self.encryption_key = config.CHACHA20_KEY
            self.chacha20 = ChaCha20.new(key=self.encryption_key)
            self.nonce = b64encode(self.chacha20.nonce).decode('utf-8')

        elif (config.PREFERENCE == 6):  # Blowfish Not working
            self.encryption_key = config.BLOWFISH_KEY
            self.blowfish = blowfish.Cipher(self.encryption_key)

        elif (config.PREFERENCE == 7):  # RSA not working
            self.RSAPRIV_KEY = config.RSA_KEY.export_key()
            self.RSAPUB_KEY = config.RSA_KEY.public_key().export_key()
            self.rsaenc = PKCS1_OAEP.new(RSA.import_key(self.RSAPUB_KEY))
            self.rsadec = PKCS1_OAEP.new(RSA.import_key(self.RSAPRIV_KEY))

            self.encrypted_symmetric_key = self.rsaenc.encrypt(config.AES_KEY)
            self.symmetric_key = self.rsadec.decrypt(self.encrypted_symmetric_key)



        elif (config.PREFERENCE == 8):
            self.encryption_key = config.TWOFISH_KEY
            self.twofishenc = Twofish(self.encryption_key)
            self.twofishdec = Twofish(self.encryption_key)

        elif (config.PREFERENCE == 9):
            self.encryption_key = config.CHACHA20_KEY
            self.chacha20 = ChaCha20.new(key=self.encryption_key, nonce=config.CHACHA_NONCE)

        elif (config.PREFERENCE == 10):
            self.encryption_key = config.CHACHA20_KEY
            self.chacha20 = ChaCha20.new(key=self.encryption_key, nonce=config.CHACHA_NONCE)

    def encrypt_data(self, data):

        if (config.PREFERENCE == 1):
            print('Encrypting using FERNET: ')
            return self.fernet.encrypt(data)

        elif (config.PREFERENCE == 2):
            print('Encrypting using RC2: ')
            return self.rc2enc.encrypt(data)

        elif (config.PREFERENCE == 3):
            print('Encrypting using Triple DES: ')
            return config.TDES_IV + self.tdesenc.encrypt(data)

        elif (config.PREFERENCE == 4):
            print('Encrypting using RC4: ')
            return self.rc4.encrypt(data)

        elif (config.PREFERENCE == 5):
            print('Encrypting using ChaCha20: ')
            return self.chacha20.encrypt(data)

        elif (config.PREFERENCE == 6):
            print('Encrypting using Blowfish: ')
            return b"".join(self.blowfish.encrypt_ofb(data, config.BLOWFISH_IV))

        elif (config.PREFERENCE == 7):
            print('Encrypting using Hybrid Encryption ( AES + RSA ): ')
            return self.fernet.encrypt(data)

        elif (config.PREFERENCE == 8):
            print('Encrypting using TwoFish: ')
            return self.twofishenc.encrypt(data)

        elif (config.PREFERENCE == 9):
            print('Encrypting using ChaCha20: ')
            return self.chacha20.encrypt(data)

        elif (config.PREFERENCE == 10):
            print('Encrypting using ChaCha20: ')
            return self.chacha20.encrypt(data)

    def decrypt_data(self, data):
        if (config.PREFERENCE == 1):
            return self.fernet.decrypt(data)

        elif (config.PREFERENCE == 2):
            return self.rc2dec.decrypt(data)

        elif (config.PREFERENCE == 3):
            iv = data[:8]
            tdesdec = DES3.new(self.encryption_key, DES3.MODE_CFB, iv)
            return tdesdec.decrypt(data[8:])

        elif (config.PREFERENCE == 4):
            return self.rc4.decrypt(data)

        elif (config.PREFERENCE == 5):
            return self.chacha20.decrypt(data)

        elif (config.PREFERENCE == 6):
            return b"".join(self.blowfish.decrypt_ofb(data, config.BLOWFISH_IV))

        elif (config.PREFERENCE == 7):
            return self.fernet.decrypt(data)


        elif (config.PREFERENCE == 8):
            return self.twofishdec.decrypt(data)

        elif (config.PREFERENCE == 9):
            return self.chacha20.decrypt(data)

        elif (config.PREFERENCE == 10):
            return self.chacha20.decrypt(data)


class UdpProxy:
    def __init__(self, conn, sm):
        self.conn = conn
        self.sm = sm
        self.blowfish = blowfish.Cipher(config.BLOWFISH_KEY)

    def sendto(self, data, address):
        encrypted_data = self.sm.encrypt_data(data)
        self.conn.sendto(encrypted_data, address)

    def recvfrom(self, buffer_size):
        encrypted_data, address = self.conn.recvfrom(buffer_size)
        data = self.sm.decrypt_data(encrypted_data)
        return data, address
