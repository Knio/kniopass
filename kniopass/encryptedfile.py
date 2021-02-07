import os
import logging
import hashlib

import cryptography.hazmat
import cryptography.hazmat.backends
import cryptography.hazmat.primitives.kdf.pbkdf2
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.ciphers
import cryptography.hazmat.primitives.padding

BACKEND = cryptography.hazmat.backends.default_backend()

LOG = logging.getLogger()

class EncryptedFile(object):
    SALT_LENGTH = 32
    DATA_MAGIC_V0 = b'kniopass00000001'
    DATA_MAGIC_V1 = b'blobpass'
    DATA_MAGIC_LEN = len(DATA_MAGIC_V1)
    DATA_VERSION = b'00000001'
    DATA_VERSION_LEN = len(DATA_VERSION)
    ALGORITHMS_V0 = [
        (32, cryptography.hazmat.primitives.ciphers.algorithms.AES),
        (32, cryptography.hazmat.primitives.ciphers.algorithms.Camellia),
        (16, cryptography.hazmat.primitives.ciphers.algorithms.CAST5),
        (16, cryptography.hazmat.primitives.ciphers.algorithms.SEED),
    ]
    ALGORITHMS_V1 = [
        (32, cryptography.hazmat.primitives.ciphers.algorithms.AES),
        (32, cryptography.hazmat.primitives.ciphers.algorithms.Camellia),
        (16, cryptography.hazmat.primitives.ciphers.algorithms.CAST5),
    ]
    KEY_LENGTH_V0 = sum(l for l, a in ALGORITHMS_V0)
    KEY_LENGTH_V1 = sum(l for l, a in ALGORITHMS_V1)
    BLOCK_LENGTH_V1 = sum(a.block_size for l, a in ALGORITHMS_V1) // 8

    def __init__(self, filename, password):
        self.filename = filename
        self.password = password
        self.salt = None
        self.key = None

    def rekey(self):
        self.salt = os.urandom(self.SALT_LENGTH)
        self.key = self.compute_key_v1(self.salt, self.password)

    @classmethod
    def compute_key_v0(cls, salt, password):
        keygen = cryptography.hazmat.primitives.kdf.scrypt.Scrypt(
            backend=BACKEND,
            length=cls.KEY_LENGTH_V0,
            salt=salt,
            n=2<<18, r=8, p=1,
        )
        return keygen.derive(password.encode('utf-8'))

    @classmethod
    def compute_key_v1(cls, salt, password):
        keygen = cryptography.hazmat.primitives.kdf.scrypt.Scrypt(
            backend=BACKEND,
            length=cls.KEY_LENGTH_V1,
            salt=salt,
            n=2<<18, r=8, p=1,
        )
        return keygen.derive(password.encode('utf-8'))

    @classmethod
    def decrypt_data_v0(cls, key, data):
        key_offset = sum(i[0] for i in cls.ALGORITHMS_V0)
        nonce = data[:cls.KEY_LENGTH_V0]
        data = data[cls.KEY_LENGTH_V0:]
        for key_size, alg in reversed(cls.ALGORITHMS_V0):
            key_offset -= key_size
            k = key[key_offset : key_offset + key_size]
            a = alg(k)
            n = nonce[key_offset : key_offset + a.block_size // 8]
            p = cryptography.hazmat.primitives.padding.PKCS7(a.block_size).unpadder()
            cipher = cryptography.hazmat.primitives.ciphers.Cipher(
                a,
                cryptography.hazmat.primitives.ciphers.modes.CBC(n),
                backend=BACKEND
            )
            decryptor = cipher.decryptor()
            data = decryptor.update(data) + decryptor.finalize()
            data = p.update(data) + p.finalize()

        if not data[0:16] == cls.DATA_MAGIC_V0:
            raise Exception('Wrong password or invalid kniopass file')
        data = data[16:]

        return data

    @classmethod
    def decrypt_data_v1(cls, key, data):
        usedLen = cls.DATA_MAGIC_LEN+cls.DATA_VERSION_LEN+cls.SALT_LENGTH
        sha = hashlib.sha512()
        sha.update(data[:usedLen+cls.BLOCK_LENGTH_V1])
        data = data[usedLen:]
        nonce = data[:cls.BLOCK_LENGTH_V1]
        data = data[cls.BLOCK_LENGTH_V1:]

        key_offset = cls.KEY_LENGTH_V1
        block_offset = cls.BLOCK_LENGTH_V1
        for key_size, alg in reversed(cls.ALGORITHMS_V1):
            key_offset -= key_size
            k = key[key_offset : key_offset + key_size]
            a = alg(k)
            block_offset -= a.block_size // 8
            n = nonce[block_offset : block_offset + a.block_size // 8]
            p = cryptography.hazmat.primitives.padding.PKCS7(a.block_size).unpadder()
            cipher = cryptography.hazmat.primitives.ciphers.Cipher(
                a,
                cryptography.hazmat.primitives.ciphers.modes.CBC(n),
                backend=BACKEND
            )
            decryptor = cipher.decryptor()
            data = decryptor.update(data) + decryptor.finalize()
            data = p.update(data) + p.finalize()

        oldHash = data[:sha.digest_size]
        data = data[sha.digest_size:]
        sha.update(data)
        if oldHash != sha.digest():
            raise Exception('Wrong password or invalid kniopass file')

        return data

    @classmethod
    def encrypt_payload(cls, key, salt, data):
        nonce = os.urandom(cls.BLOCK_LENGTH_V1)
        payload = cls.DATA_MAGIC_V1 + cls.DATA_VERSION + salt + nonce
        sha = hashlib.sha512()
        sha.update(payload)
        sha.update(data)
        data = sha.digest() + data

        key_offset = 0
        block_offset = 0
        for key_size, alg in cls.ALGORITHMS_V1:
            k = key[key_offset : key_offset + key_size]
            a = alg(k)
            n = nonce[block_offset : block_offset + a.block_size // 8]
            key_offset += key_size
            block_offset += a.block_size // 8
            p = cryptography.hazmat.primitives.padding.PKCS7(a.block_size).padder()
            data = p.update(data) + p.finalize()
            cipher = cryptography.hazmat.primitives.ciphers.Cipher(
                a,
                cryptography.hazmat.primitives.ciphers.modes.CBC(n),
                backend=BACKEND
            )
            encryptor = cipher.encryptor()
            data = encryptor.update(data) + encryptor.finalize()
        return payload + data

    @classmethod
    def decrypt_payload(cls, passphrase, data):
        offset = 0
        version = None
        if data[:len(cls.DATA_MAGIC_V0)] == cls.DATA_MAGIC_V0:
            version = 0
            offset += len(cls.DATA_MAGIC_V0)
        elif data[:cls.DATA_MAGIC_LEN] == cls.DATA_MAGIC_V1:
            offset += cls.DATA_MAGIC_LEN
            version = int(data[offset:offset+cls.DATA_VERSION_LEN])
            offset += cls.DATA_VERSION_LEN
        else:
            raise Exception('Not a kniopass file. (magic = {!r}'.format(data[0:16]))

        salt = data[offset:offset+cls.SALT_LENGTH]
        offset += cls.SALT_LENGTH
        key = None
        if version == 0:
            data = data[offset:]
            key = cls.compute_key_v0(salt, passphrase)
            data = cls.decrypt_data_v0(key, data)
        elif version == 1:
            key = cls.compute_key_v1(salt, passphrase)
            data = cls.decrypt_data_v1(key, data)
        else:
            raise Exception('Unknown version')
        return {'key': key, 'salt': salt, 'version': version, 'pt': data}

    def load_file(self):
        LOG.info('Loading %s', self.filename)
        data = open(self.filename, 'rb').read()
        ret = self.decrypt_payload(self.password, data)
        self.key = ret['key']
        self.salt = ret['salt']
        return ret['pt']

    def save_file(self, data):
        LOG.info('Saving to %s', self.filename)
        data = self.encrypt_payload(self.key, self.salt, data)
        open(self.filename, 'wb').write(data)
